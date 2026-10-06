# scdaemon-touch-proxy

Diagnostic Assuan proxy between gpg-agent and the real scdaemon. Forwards bytes
unchanged and logs every line with local-format timestamp, pid and ms since start.

## Install
    cargo build --release
    install -m 755 target/release/scdaemon-touch-proxy ~/.local/bin/
    echo "scdaemon-program $HOME/.local/bin/scdaemon-touch-proxy" >> ~/.gnupg/gpg-agent.conf
    gpgconf --kill gpg-agent
    gpg --card-status

macOS: `xattr -d com.apple.quarantine` on a copied prebuilt binary.

## Env
- `SCDAEMON_TOUCH_PROXY_TARGET` real scdaemon path (default: `$(gpgconf --list-dirs libexecdir)/scdaemon`)
- `SCDAEMON_TOUCH_PROXY_LOG` log path (macOS `~/Library/Logs/scdaemon-touch-proxy.log`, else `$XDG_STATE_HOME/scdaemon-touch-proxy/session.log`)

## Reading the log
- `>> PKSIGN` → gap → `<< OK`/`ERR` = touch wait.
- `>> GETINFO socket_name` then no PKSIGN via proxy = agent bypasses the pipe.
- `env LANG=None` = C-locale timestamps; set LANG for gpg-agent.
