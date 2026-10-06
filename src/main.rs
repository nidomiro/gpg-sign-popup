use std::env;
use std::ffi::CString;
use std::fs::{create_dir_all, File, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DIRECTION_TO_CARD: &str = ">>";
const DIRECTION_FROM_CARD: &str = "<<";
const DIRECTION_META: &str = "##";

// ---------------------------------------------------------------- timestamps

/// Applies the process environment's locale so strftime("%c") renders in the
/// user's own date format. Must run once before the first timestamp.
fn activate_environment_locale() {
    let environment_default = CString::new("").expect("static string is valid");
    unsafe {
        libc::setlocale(libc::LC_TIME, environment_default.as_ptr());
    }
}

fn local_timestamp() -> String {
    unsafe {
        let mut wall_clock: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut wall_clock);

        let mut broken_down_time: libc::tm = std::mem::zeroed();
        libc::localtime_r(&wall_clock.tv_sec, &mut broken_down_time);

        let mut rendered = [0 as libc::c_char; 160];
        let locale_format = CString::new("%c %Z").expect("static string is valid");
        let written_bytes = libc::strftime(
            rendered.as_mut_ptr(),
            rendered.len(),
            locale_format.as_ptr(),
            &broken_down_time,
        );

        let formatted_time = if written_bytes == 0 {
            String::from("<strftime overflow>")
        } else {
            let bytes: Vec<u8> = rendered[..written_bytes]
                .iter()
                .map(|&character| character as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };

        // %c has no sub-second resolution, but the touch stall is a timing
        // question, so milliseconds get appended explicitly.
        format!("{} .{:03}", formatted_time, wall_clock.tv_nsec / 1_000_000)
    }
}

// -------------------------------------------------------------------- logging

struct ProxyLogger {
    log_file: Option<Mutex<File>>,
    started_at: Instant,
    process_id: u32,
}

impl ProxyLogger {
    fn new(log_path: Option<&Path>) -> std::io::Result<Self> {
        let log_file = match log_path {
            Some(log_path) => Some(Mutex::new(Self::open_log_file(log_path)?)),
            None => None,
        };

        Ok(Self {
            log_file,
            started_at: Instant::now(),
            process_id: std::process::id(),
        })
    }

    fn open_log_file(log_path: &Path) -> std::io::Result<File> {
        if let Some(parent_directory) = log_path.parent() {
            create_dir_all(parent_directory)?;
        }

        // The log contains card serials, key grips and the digests being
        // signed — keep it owner-only.
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(log_path)?;

        // .mode() only applies on creation; narrow a pre-existing file too.
        log_file.set_permissions(Permissions::from_mode(0o600))?;
        Ok(log_file)
    }

    fn log(&self, direction: &str, message: &str) {
        let Some(log_file) = &self.log_file else {
            return;
        };

        let elapsed_milliseconds = self.started_at.elapsed().as_millis();
        let log_line = format!(
            "{} [{}] +{:>8}ms {} {}\n",
            local_timestamp(),
            self.process_id,
            elapsed_milliseconds,
            direction,
            message
        );

        if let Ok(mut log_file) = log_file.lock() {
            let _ = log_file.write_all(log_line.as_bytes());
            let _ = log_file.flush();
        }
    }

    /// Reports an unrecoverable error (log, and stderr so gpg-agent's own log
    /// shows it even when file logging is off) and exits.
    fn fatal(&self, message: &str) -> ! {
        self.log(DIRECTION_META, message);
        eprintln!("scdaemon-touch-proxy: {}", message);
        std::process::exit(2);
    }
}

/// Logging is off unless `SCDAEMON_TOUCH_PROXY_LOG` is set: `1` selects the
/// default location, any other value (except empty/`0`) is used as the path.
fn configured_log_path() -> Option<PathBuf> {
    let configured = env::var("SCDAEMON_TOUCH_PROXY_LOG").ok()?;
    match configured.as_str() {
        "" | "0" => return None,
        "1" => {}
        path => return Some(PathBuf::from(path)),
    }

    let home_directory = PathBuf::from(env::var("HOME").unwrap_or_else(|_| String::from("/tmp")));

    Some(if cfg!(target_os = "macos") {
        home_directory.join("Library/Logs/scdaemon-touch-proxy.log")
    } else {
        let state_directory = env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_directory.join(".local/state"));
        state_directory.join("scdaemon-touch-proxy/session.log")
    })
}

// ------------------------------------------------------------ target discovery

fn resolve_real_scdaemon(logger: &ProxyLogger) -> PathBuf {
    if let Ok(configured_path) = env::var("SCDAEMON_TOUCH_PROXY_TARGET") {
        return PathBuf::from(configured_path);
    }

    // NOTE: `gpgconf --list-components` would report *this* proxy once
    // scdaemon-program is set. libexecdir is a plain directory and stays
    // unaffected, so it is the safe query.
    let libexec_output = match Command::new("gpgconf")
        .args(["--list-dirs", "libexecdir"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => logger.fatal(&format!("gpgconf failed: {}", output.status)),
        Err(error) => logger.fatal(&format!("gpgconf not runnable: {}", error)),
    };

    let libexec_directory = String::from_utf8_lossy(&libexec_output.stdout)
        .trim()
        .to_string();

    PathBuf::from(libexec_directory).join("scdaemon")
}

fn guard_against_self_exec(target_path: &Path, logger: &ProxyLogger) {
    let own_path = match env::current_exe().and_then(|path| path.canonicalize()) {
        Ok(path) => path,
        Err(error) => logger.fatal(&format!("cannot determine own executable path: {}", error)),
    };
    let canonical_target = match target_path.canonicalize() {
        Ok(path) => path,
        Err(error) => logger.fatal(&format!(
            "target {} unusable: {}",
            target_path.display(),
            error
        )),
    };

    if own_path == canonical_target {
        logger.fatal(&format!("refusing to exec itself: {}", own_path.display()));
    }
}

// ------------------------------------------------------------------ touch watch

/// Assuan commands that make the card demand a touch (depending on the key's
/// touch policy) once the PIN is satisfied.
const TOUCH_COMMANDS: [&str; 3] = ["PKSIGN", "PKAUTH", "PKDECRYPT"];
const DEFAULT_POPUP_DELAY_MS: u64 = 500;
const POPUP_MESSAGE: &str = "Touch your YubiKey to confirm";

#[derive(Default)]
struct WatchState {
    /// Bumped on every arm/disarm; a pending timer fires only if unchanged.
    generation: u64,
    /// A touch-capable command is in flight and has not got its final status.
    operation_active: bool,
    /// The card has an open INQUIRE; the agent's D lines are secrets (PIN).
    inquiry_open: bool,
    popup: Option<Child>,
}

/// scdaemon never announces "waiting for touch": the card simply stays silent.
/// So the proxy infers it: after the command (and after any PIN inquiry has
/// been answered) a response that takes longer than `delay` means touch wait.
struct TouchWatch {
    state: Mutex<WatchState>,
    delay: Duration,
    popup_commands: Vec<Vec<String>>,
    logger: Arc<ProxyLogger>,
}

impl TouchWatch {
    fn from_environment(logger: Arc<ProxyLogger>) -> Arc<Self> {
        let delay_milliseconds = env::var("SCDAEMON_TOUCH_PROXY_POPUP_DELAY_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_POPUP_DELAY_MS);

        let popup_commands = match env::var("SCDAEMON_TOUCH_PROXY_POPUP") {
            // `exec` so that killing the child really kills the dialog.
            Ok(command) if !command.trim().is_empty() => vec![vec![
                String::from("sh"),
                String::from("-c"),
                format!("exec {}", command),
            ]],
            _ => default_popup_commands(),
        };

        Arc::new(Self {
            state: Mutex::new(WatchState::default()),
            delay: Duration::from_millis(delay_milliseconds),
            popup_commands,
            logger,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WatchState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Inspects one protocol line, updates the touch state machine and returns
    /// the text that is safe to write to the log (secrets redacted).
    fn observe(self: &Arc<Self>, direction: &str, line: &str) -> String {
        let command = line.split(' ').next().unwrap_or("");

        if direction == DIRECTION_TO_CARD {
            match command {
                _ if TOUCH_COMMANDS.contains(&command) => {
                    self.lock().operation_active = true;
                    self.arm();
                }
                "END" => {
                    let operation_active = {
                        let mut state = self.lock();
                        state.inquiry_open = false;
                        state.operation_active
                    };
                    if operation_active {
                        self.arm();
                    }
                }
                "D" if self.lock().inquiry_open => return String::from("D <redacted>"),
                "CAN" | "RESTART" | "RESET" | "BYE" => self.reset(),
                _ => {}
            }
        } else if direction == DIRECTION_FROM_CARD {
            match command {
                "INQUIRE" => {
                    let operation_active = {
                        let mut state = self.lock();
                        state.inquiry_open = true;
                        state.operation_active
                    };
                    if operation_active {
                        // The user is typing the PIN, not touching.
                        self.disarm();
                    }
                }
                "D" | "OK" | "ERR" => {
                    let operation_active = self.lock().operation_active;
                    if operation_active {
                        self.disarm();
                        if command != "D" {
                            self.lock().operation_active = false;
                        }
                    }
                }
                "S" if line.starts_with("S PINCACHE_PUT") => {
                    return String::from("S PINCACHE_PUT <redacted>");
                }
                _ => {}
            }
        }

        line.to_string()
    }

    fn reset(&self) {
        {
            let mut state = self.lock();
            state.operation_active = false;
            state.inquiry_open = false;
        }
        self.disarm();
    }

    /// Cancels any pending timer and closes a visible popup.
    fn disarm(&self) {
        let popup = {
            let mut state = self.lock();
            state.generation += 1;
            state.popup.take()
        };
        if let Some(mut popup) = popup {
            let _ = popup.kill();
            let _ = popup.wait();
            self.logger.log(DIRECTION_META, "touch popup closed");
        }
    }

    /// Starts the countdown; if nothing answers within `delay`, show the popup.
    fn arm(self: &Arc<Self>) {
        self.disarm();
        let expected_generation = self.lock().generation;
        let watch = Arc::clone(self);
        thread::spawn(move || {
            thread::sleep(watch.delay);
            let mut state = watch.lock();
            if state.generation != expected_generation || state.popup.is_some() {
                return;
            }
            state.popup = watch.spawn_popup();
        });
    }

    fn spawn_popup(&self) -> Option<Child> {
        for command in &self.popup_commands {
            let spawned = Command::new(&command[0])
                .args(&command[1..])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            match spawned {
                Ok(child) => {
                    self.logger.log(
                        DIRECTION_META,
                        &format!("touch popup shown via {}", command[0]),
                    );
                    return Some(child);
                }
                Err(error) => self.logger.log(
                    DIRECTION_META,
                    &format!("popup command {} failed: {}", command[0], error),
                ),
            }
        }
        None
    }
}

fn default_popup_commands() -> Vec<Vec<String>> {
    let command = |parts: &[&str]| -> Vec<String> { parts.iter().map(|part| part.to_string()).collect() };

    if cfg!(target_os = "macos") {
        vec![command(&[
            "osascript",
            "-e",
            &format!(
                "display dialog \"{}\" with title \"GPG signature\" buttons {{\"Dismiss\"}} default button 1 giving up after 120",
                POPUP_MESSAGE
            ),
        ])]
    } else {
        vec![
            command(&["kdialog", "--title", "GPG signature", "--msgbox", POPUP_MESSAGE]),
            command(&[
                "zenity",
                "--info",
                "--title=GPG signature",
                &format!("--text={}", POPUP_MESSAGE),
                "--timeout=120",
            ]),
            command(&["notify-send", "-u", "critical", "GPG signature", POPUP_MESSAGE]),
        ]
    }
}

// ------------------------------------------------------------------- forwarding

/// Copies bytes through immediately and only then reassembles them into lines
/// for the log. Forwarding must never wait for a complete line — scdaemon and
/// gpg-agent would deadlock on a half-written response.
fn forward_and_log(
    mut source: impl Read,
    mut sink: impl Write,
    direction: &'static str,
    logger: Arc<ProxyLogger>,
    watch: Arc<TouchWatch>,
) {
    let mut read_buffer = [0u8; 4096];
    let mut pending_line: Vec<u8> = Vec::new();

    loop {
        let byte_count = match source.read(&mut read_buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                logger.log(
                    DIRECTION_META,
                    &format!("{} read error: {}", direction, error),
                );
                break;
            }
        };

        let chunk = &read_buffer[..byte_count];
        if let Err(error) = sink.write_all(chunk).and_then(|_| sink.flush()) {
            logger.log(
                DIRECTION_META,
                &format!("{} write error: {}", direction, error),
            );
            break;
        }

        for &byte in chunk {
            if byte == b'\n' {
                let line = String::from_utf8_lossy(&pending_line);
                let logged_line = watch.observe(direction, &line);
                logger.log(direction, &logged_line);
                pending_line.clear();
            } else {
                pending_line.push(byte);
            }
        }
    }

    if !pending_line.is_empty() {
        logger.log(
            direction,
            &format!("<unterminated> {}", String::from_utf8_lossy(&pending_line)),
        );
    }
    logger.log(DIRECTION_META, &format!("{} channel closed", direction));
}

// ------------------------------------------------------------------------ main

fn main() {
    activate_environment_locale();

    let scdaemon_arguments: Vec<String> = env::args().skip(1).collect();
    let log_path = configured_log_path();
    let logger = match ProxyLogger::new(log_path.as_deref()) {
        Ok(logger) => Arc::new(logger),
        Err(error) => {
            eprintln!(
                "scdaemon-touch-proxy: cannot open log {:?}: {}",
                log_path, error
            );
            std::process::exit(2);
        }
    };

    logger.log(DIRECTION_META, "---- proxy start ----");
    logger.log(DIRECTION_META, &format!("argv: {:?}", scdaemon_arguments));
    logger.log(
        DIRECTION_META,
        &format!("parent pid: {}", unsafe { libc::getppid() }),
    );
    for variable_name in ["LANG", "LC_ALL", "LC_TIME", "TZ", "GNUPGHOME"] {
        logger.log(
            DIRECTION_META,
            &format!("env {}={:?}", variable_name, env::var(variable_name).ok()),
        );
    }

    let target_path = resolve_real_scdaemon(&logger);
    guard_against_self_exec(&target_path, &logger);
    logger.log(
        DIRECTION_META,
        &format!("target: {}", target_path.display()),
    );

    let mut scdaemon_process = match Command::new(&target_path)
        .args(&scdaemon_arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(process) => process,
        Err(error) => logger.fatal(&format!("failed to spawn scdaemon: {}", error)),
    };

    let scdaemon_stdin = scdaemon_process.stdin.take().expect("piped stdin missing");
    let scdaemon_stdout = scdaemon_process
        .stdout
        .take()
        .expect("piped stdout missing");

    let touch_watch = TouchWatch::from_environment(Arc::clone(&logger));

    let agent_to_card_logger = Arc::clone(&logger);
    let agent_to_card_watch = Arc::clone(&touch_watch);
    thread::spawn(move || {
        forward_and_log(
            std::io::stdin(),
            scdaemon_stdin,
            DIRECTION_TO_CARD,
            agent_to_card_logger,
            agent_to_card_watch,
        )
    });

    let card_to_agent_logger = Arc::clone(&logger);
    let card_to_agent_watch = Arc::clone(&touch_watch);
    let card_to_agent_thread = thread::spawn(move || {
        forward_and_log(
            scdaemon_stdout,
            std::io::stdout(),
            DIRECTION_FROM_CARD,
            card_to_agent_logger,
            card_to_agent_watch,
        )
    });

    let exit_status = scdaemon_process
        .wait()
        .expect("failed to wait for scdaemon");
    let _ = card_to_agent_thread.join();
    touch_watch.reset();

    logger.log(
        DIRECTION_META,
        &format!("scdaemon exited with {:?}", exit_status.code()),
    );
    std::process::exit(exit_status.code().unwrap_or(1));
}
