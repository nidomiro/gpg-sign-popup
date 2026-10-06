# scdaemon-touch-proxy

Diagnostic Assuan proxy between gpg-agent and the real scdaemon. Forwards bytes
unchanged and logs every line with local-format timestamp, pid and ms since start.

## Install
    mise run install      # builds release, copies to ~/.local/bin, restarts gpg-agent

Configure gpg-agent once (the task never touches this file):

    echo "scdaemon-program $HOME/.local/bin/scdaemon-touch-proxy" >> ~/.gnupg/gpg-agent.conf
    gpg --card-status

gpg-agent keeps running the old proxy until restarted; `mise run install` does that
via `gpgconf --kill gpg-agent`. Manual equivalent: `cargo build --release`,
`install -m 755 target/release/scdaemon-touch-proxy ~/.local/bin/`, `gpgconf --kill gpg-agent`.

macOS: `xattr -d com.apple.quarantine` on a copied prebuilt binary.

## Env

- `SCDAEMON_TOUCH_PROXY_TARGET` real scdaemon path (default: `$(gpgconf --list-dirs libexecdir)/scdaemon`)
- `SCDAEMON_TOUCH_PROXY_LOG` log path (macOS `~/Library/Logs/scdaemon-touch-proxy.log`, else `$XDG_STATE_HOME/scdaemon-touch-proxy/session.log`)

## Reading the log

- `>> PKSIGN` → gap → `<< OK`/`ERR` = touch wait.
- `>> GETINFO socket_name` then no PKSIGN via proxy = agent bypasses the pipe.
- `env LANG=None` = C-locale timestamps; set LANG for gpg-agent.

## Touch popup

scdaemon never announces a touch wait; the proxy infers it. After a
`PKSIGN`/`PKAUTH`/`PKDECRYPT` (and after the PIN inquiry is answered with `END`),
no `D`/`OK`/`ERR` within the delay ⇒ popup. It closes on the response.

- `SCDAEMON_TOUCH_PROXY_POPUP_DELAY_MS` (default 500)
- `SCDAEMON_TOUCH_PROXY_POPUP` shell command to run as the popup (killed to dismiss).
  Defaults: macOS `osascript` dialog; Linux `kdialog`, `zenity`, `notify-send` (first that starts).

Env vars must be visible to gpg-agent (`gpgconf --kill gpg-agent` after changing them).

## Log redaction

Agent `D` lines after a card `INQUIRE` (the PIN) and `S PINCACHE_PUT` values are
logged as `<redacted>`. Logs written by versions before this contain the PIN in clear.
