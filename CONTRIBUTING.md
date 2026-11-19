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

For changes to GitHub Actions, run `pipx run zizmor --persona=regular .github/workflows`.
CI also scans commits for secrets with Gitleaks. Do not paste real credentials into test output or pull request descriptions.

## Style

- Bash: `set -euo pipefail`, quote every expansion, one comment above each function.
- Python: PEP 8, descriptive names, a docstring on every function.
- If you add or remove lines in the `bin/sing` header, update the `sed -n 'START,ENDp'` range that prints the help.

Keep changes focused. Add tests for failure paths and behavior that protects proxy routing or credentials.

## Branches

- Start each change from current `main` in a separate branch: `git fetch --prune` then `git switch -c fix/short-name origin/main`.
- Name branches `<type>/<kebab-case>`. Use `feat`, `fix`, `refactor`, `docs`, `test`, `ci`, or `chore` as the type.
- Keep one task per branch. If a change depends on an unmerged branch, base the new branch on it and merge in order.
- Do not push directly to `main`, rewrite another contributor's branch, or create merge commits in a pull request branch.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`. Add a scope when it helps, for example `fix(select): reject empty links`.
- Write an English imperative subject without a trailing period. Keep it at 50 characters or fewer; use the body to explain non-obvious reasons.
- Do not replace Git author or committer identity. Credit AI-assisted commits with a `Co-Authored-By` trailer when applicable.
- Keep one change per pull request. Never commit `sing.sub`, `custom.txt`, `sing.json`, real links, or keys.
- Explain why the change is needed in the pull request description. List key changes and any checks you could not run.
- Wait for CI checks and address review comments before merging. The maintainer decides when to merge.

## Automatic releases

Successful CI on `main` publishes a standalone runtime archive and its checksum. CI stamps `1.0.<CI run number>` into the packaged `VERSION` without changing source files. `scripts/package_release.py` packages only explicit runtime files. Publish the initial CLI release before merging the extension's release installer.
