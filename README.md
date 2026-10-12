# sing

Run a single app or command through a proxy or VPN key (BlancVPN subscription, VLESS, WireGuard and more) on macOS, without routing the whole system.

`sing` starts a local [sing-box](https://sing-box.sagernet.org) instance with a mixed HTTP + SOCKS5 inbound on `127.0.0.1:1080`, then launches the target through it:

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
| `bin/sing` | `~/.local/bin/sing` |
| `share/select.py` | `~/.local/share/sing/select.py` |
| `proxychains/sing.conf` | `~/.proxychains/sing.conf` |

Existing regular files are kept as `*.bak`. Files from the old `blanc` version (`blanc.sub`, `blanc.json`, `blanc.current`) are renamed to `sing.*`. Make sure `~/.local/bin` is on `PATH`.

Then put the subscription URL into `~/.config/sing-box/sing.sub` (see `config/sing.sub.example`), `chmod 600` it, and pick a server:

```bash
sing select
sing select Amsterdam
```

## Usage

```
sing <command> [args]          run a command through the proxy
sing app <Name.app>            run a GUI/Electron app (Claude, Slack, Chrome…)
sing stop                      stop sing-box
sing status                    route to server, SOCKS state, external IP
sing select                    list servers (subscription + custom), * = current
sing select <name>             switch server (sing-box restarts if running)
sing select add <link> [name]  add a custom proxy (vless/vmess/trojan/ss/hy2/wg/socks5/http)
sing select add <file.conf> [name]  import a WireGuard config
sing select add socks5 1.2.3.4:1080 login password [name]
sing select add socks5://1.2.3.4:1080:login:password [name]
sing select rm <name>          remove a custom proxy
```

For `sing app`, quit the running instance first, otherwise macOS hands the launch to it without the proxy flag.

## Supported protocols

| Protocol | Link schemes | Notes |
|---|---|---|
| VLESS | `vless://` | TLS, Reality, ws, grpc, http, httpupgrade |
| VMess | `vmess://` | v2rayN base64 JSON |
| Trojan | `trojan://` | |
| Shadowsocks | `ss://` | SIP002 and legacy base64, Outline keys |
| Hysteria2 | `hysteria2://`, `hy2://` | obfs supported |
| WireGuard | `wireguard://`, `wg://`, `.conf` file | v2rayN and Hiddify link formats |
| SOCKS5 / HTTP(S) | `socks5://`, `socks://`, `http://`, `https://` | optional login/password |

Not supported: AmneziaWG (rejected with an error), OpenVPN, IKEv2/IPsec, L2TP, and the `xhttp` transport (sing-box does not implement it).

Subscriptions can be base64 or plain text, one link per line. Lines with unsupported schemes are skipped. Clash YAML and sing-box JSON subscriptions are not supported.

WireGuard runs over UDP. If another VPN drops UDP to the WireGuard server, use a TCP-based protocol instead.

## Files (not in the repo)

All live in `~/.config/sing-box/` and contain secrets. They are ignored by `.gitignore`:

- `sing.sub`: subscription URL
- `custom.txt`: custom proxy links, one per line (see `config/custom.txt.example`)
- `sing.json`: generated sing-box config
- `sing.current`, `sing.pid`: runtime state

Logs go to `~/Library/Logs/sing.log`.

## Running alongside another VPN

If another VPN is active, blocks traffic outside its tunnel and removes foreign routes, the connection to the proxy server goes through that VPN. The payload stays encrypted end to end.
