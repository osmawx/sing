# Security policy

## Supported versions

Only the latest commit on `main` is supported. There are no release branches.

## Reporting a vulnerability

Do not open a public issue for security problems.

Report privately through GitHub: **Security → Report a vulnerability** on this repository
([direct link](https://github.com/osmawx/sing/security/advisories/new)).

Include:

- what is affected (`bin/sing`, `share/select.py`, `install.sh`, generated `sing.json`);
- steps to reproduce, with **fake** links and keys only;
- the impact you expect (traffic leak outside the proxy, secret exposure, code execution, and so on).

You will get a reply within 7 days. Fixes land on `main`, and the advisory is published after the fix.

## Never paste real secrets

Subscription URLs, proxy links, WireGuard private keys and `sing.json` contain credentials.
Redact them in issues, pull requests, logs and reports. If you leaked one, rotate it with your provider:
removing it from GitHub does not make it safe again.

## Scope

In scope:

- traffic of a command started with `sing` leaving outside the local sing-box proxy;
- secrets written with permissions wider than `0600`, or printed to the log or terminal;
- command injection through server names, links, subscription content or `.conf` files;
- `install.sh` overwriting or deleting user files.

Out of scope:

- vulnerabilities in sing-box, proxychains-ng or the proxy protocols themselves (report them upstream);
- apps that ignore both proxychains and proxy settings;
- a malicious subscription provider: you already trust it with your traffic.
