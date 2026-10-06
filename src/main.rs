use std::env;
use std::ffi::CString;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

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
    log_file: Mutex<File>,
    started_at: Instant,
    process_id: u32,
}

impl ProxyLogger {
    fn new(log_path: &Path) -> std::io::Result<Self> {
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

        Ok(Self {
            log_file: Mutex::new(log_file),
            started_at: Instant::now(),
            process_id: std::process::id(),
        })
    }

    fn log(&self, direction: &str, message: &str) {
        let elapsed_milliseconds = self.started_at.elapsed().as_millis();
        let log_line = format!(
            "{} [{}] +{:>8}ms {} {}\n",
            local_timestamp(),
            self.process_id,
            elapsed_milliseconds,
            direction,
            message
        );

        if let Ok(mut log_file) = self.log_file.lock() {
            let _ = log_file.write_all(log_line.as_bytes());
            let _ = log_file.flush();
        }
    }
}

fn default_log_path() -> PathBuf {
    if let Ok(configured_path) = env::var("SCDAEMON_TOUCH_PROXY_LOG") {
        return PathBuf::from(configured_path);
    }

    let home_directory = PathBuf::from(env::var("HOME").unwrap_or_else(|_| String::from("/tmp")));

    if cfg!(target_os = "macos") {
        home_directory.join("Library/Logs/scdaemon-touch-proxy.log")
    } else {
        let state_directory = env::var("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_directory.join(".local/state"));
        state_directory.join("scdaemon-touch-proxy/session.log")
    }
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
        Ok(output) => {
            logger.log(
                DIRECTION_META,
                &format!("gpgconf failed: {}", output.status),
            );
            std::process::exit(2);
        }
        Err(error) => {
            logger.log(DIRECTION_META, &format!("gpgconf not runnable: {}", error));
            std::process::exit(2);
        }
    };

    let libexec_directory = String::from_utf8_lossy(&libexec_output.stdout)
        .trim()
        .to_string();

    PathBuf::from(libexec_directory).join("scdaemon")
}

fn guard_against_self_exec(target_path: &Path, logger: &ProxyLogger) {
    let own_path = match env::current_exe().and_then(|path| path.canonicalize()) {
        Ok(path) => path,
        Err(error) => {
            logger.log(
                DIRECTION_META,
                &format!("cannot determine own executable path: {}", error),
            );
            std::process::exit(2);
        }
    };
    let canonical_target = match target_path.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            logger.log(
                DIRECTION_META,
                &format!("target {} unusable: {}", target_path.display(), error),
            );
            std::process::exit(2);
        }
    };

    if own_path == canonical_target {
        logger.log(
            DIRECTION_META,
            &format!("refusing to exec itself: {}", own_path.display()),
        );
        std::process::exit(2);
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
                logger.log(direction, &String::from_utf8_lossy(&pending_line));
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
    let log_path = default_log_path();
    let logger = match ProxyLogger::new(&log_path) {
        Ok(logger) => Arc::new(logger),
        Err(error) => {
            eprintln!(
                "scdaemon-touch-proxy: cannot open log {}: {}",
                log_path.display(),
                error
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
        Err(error) => {
            logger.log(
                DIRECTION_META,
                &format!("failed to spawn scdaemon: {}", error),
            );
            std::process::exit(2);
        }
    };

    let scdaemon_stdin = scdaemon_process.stdin.take().expect("piped stdin missing");
    let scdaemon_stdout = scdaemon_process
        .stdout
        .take()
        .expect("piped stdout missing");

    let agent_to_card_logger = Arc::clone(&logger);
    thread::spawn(move || {
        forward_and_log(
            std::io::stdin(),
            scdaemon_stdin,
            DIRECTION_TO_CARD,
            agent_to_card_logger,
        )
    });

    let card_to_agent_logger = Arc::clone(&logger);
    let card_to_agent_thread = thread::spawn(move || {
        forward_and_log(
            scdaemon_stdout,
            std::io::stdout(),
            DIRECTION_FROM_CARD,
            card_to_agent_logger,
        )
    });

    let exit_status = scdaemon_process
        .wait()
        .expect("failed to wait for scdaemon");
    let _ = card_to_agent_thread.join();

    logger.log(
        DIRECTION_META,
        &format!("scdaemon exited with {:?}", exit_status.code()),
    );
    std::process::exit(exit_status.code().unwrap_or(1));
}
