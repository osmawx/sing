# Instructions for AI agents

- Follow [CONTRIBUTING.md](CONTRIBUTING.md) for branches, commits, pull requests, checks, and code style.
- Read [README.md](README.md) for supported protocols and installation behavior before changing user-facing behavior.
- Read [SECURITY.md](SECURITY.md) before changing proxy routing, credentials, configuration files, or installation.
- Never put real subscription URLs, proxy links, private keys, or generated `sing.json` in code, tests, logs, issues, or pull requests.

## Work on a task

1. Inspect the relevant code and tests. Reuse existing parsers and helpers where possible.
2. For a complex change, write a short plan before editing.
3. Add a failing test for a bug or new protocol behavior. Implement the smallest fix, then refactor.
4. Review the diff for traffic leaks, secret exposure, command injection, and accidental changes to user files.
5. Run the checks in [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a pull request.

## Project constraints

- `share/select.py` must keep working with the system `python3` and the standard library only.
- Use fake hosts, links, and keys in tests. Add protocol and transport cases to `tests/test_select.py`.
- Keep `install.sh` safe for existing user files. Verify migration and backup behavior when changing them.
- If the `bin/sing` help header changes length, update the `sed -n 'START,ENDp'` range that prints it.
- Do not bypass checks or commit with `--no-verify`.

## Git

- Check the current branch and worktree before editing. Keep unrelated changes intact.
- Use one task per branch, based on current `main`. Name branches `<type>/<kebab-case>`; use a type from [CONTRIBUTING.md](CONTRIBUTING.md#branches).
- Do not push, open a pull request, merge, delete a remote branch, or change repository settings without the owner's explicit instruction.
