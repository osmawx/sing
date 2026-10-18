# Contributing

Bug reports, fixes and new protocol support are welcome. By taking part you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md). Report security problems privately, see [SECURITY.md](SECURITY.md).

## Setup

```bash
brew install sing-box proxychains-ng shellcheck
git clone https://github.com/osmawx/sing.git
cd sing
./install.sh
```

`install.sh` symlinks the repo files, so edits apply at once.

## Checks

Run before you open a pull request. CI runs the same checks:

```bash
shellcheck bin/sing install.sh
uvx ruff check .
python3 -m unittest discover -s tests
```

`share/select.py` uses the Python standard library only. Keep it that way: users run it with the system `python3`.

New link formats and transports need tests in `tests/test_select.py`, with fake hosts and keys only.

## Style

- Bash: `set -euo pipefail`, quote every expansion, one comment above each function.
- Python: PEP 8, descriptive names, a docstring on every function.
- If you add or remove lines in the `bin/sing` header, update the `sed -n 'START,ENDp'` range that prints the help.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`.
- Imperative subject, 50 characters or fewer. The body explains why.
- One change per pull request. Never commit `sing.sub`, `custom.txt`, `sing.json` or real links.
