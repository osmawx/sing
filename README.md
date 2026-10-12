# blanc

Run a single app or command through BlancVPN (or your own proxy) on macOS, without routing the whole system.

`blanc` starts a local [sing-box](https://sing-box.sagernet.org) instance with a mixed HTTP + SOCKS5 inbound on `127.0.0.1:1080`, then launches the target through it:

- CLI commands go through `proxychains4` plus `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` env vars (static Go/Bun/Node binaries ignore proxychains, so they use the env vars).
- GUI Electron/Chromium apps are started with `--proxy-server`, because Chromium ignores proxy env vars and breaks under proxychains.

## Requirements

- macOS
- `sing-box`, `proxychains4`: `brew install sing-box proxychains-ng`
- `python3` (stdlib only)

## Install

```bash
./install.sh
```

The script symlinks the repo files into place:

| Repo file | Installed path |
|---|---|
| `bin/blanc` | `~/.local/bin/blanc` |
| `share/select.py` | `~/.local/share/blanc/select.py` |
| `proxychains/blanc.conf` | `~/.proxychains/blanc.conf` |

Existing regular files are kept as `*.bak`. Make sure `~/.local/bin` is on `PATH`.

Then put the subscription URL into `~/.config/sing-box/blanc.sub` (see `config/blanc.sub.example`), `chmod 600` it, and pick a server:

```bash
blanc select
blanc select Amsterdam
```

## Usage

```
blanc <command> [args]          run a command through Blanc
blanc app <Name.app>            run a GUI/Electron app (Claude, Slack, Chrome…)
blanc stop                      stop sing-box
blanc status                    route to server, SOCKS state, external IP
blanc select                    list servers (subscription + custom), * = current
blanc select <name>             switch server (sing-box restarts if running)
blanc select add <link> [name]  add a custom proxy (vless/vmess/trojan/ss/hy2/socks5/http)
blanc select add socks5 1.2.3.4:1080 login password [name]
blanc select add socks5://1.2.3.4:1080:login:password [name]
blanc select rm <name>          remove a custom proxy
```

For `blanc app`, quit the running instance first, otherwise macOS hands the launch to it without the proxy flag.

## Files (not in the repo)

All live in `~/.config/sing-box/` and contain secrets. They are ignored by `.gitignore`:

- `blanc.sub`: subscription URL
- `custom.txt`: custom proxy links, one per line (see `config/custom.txt.example`)
- `blanc.json`: generated sing-box config
- `blanc.current`, `blanc.pid`: runtime state

Logs go to `~/Library/Logs/blanc-sing-box.log`.

## Running alongside another VPN

If another VPN is active, blocks traffic outside its tunnel and removes foreign routes, the connection to the Blanc server goes through that VPN. The payload stays encrypted end to end.
