# Contributing

Thanks for helping improve this project!

## Reporting Issues

Open a GitHub issue and include:
- what you expected vs. what happened,
- steps to reproduce (command and output),
- your Python version and OS.

Link to the relevant lines of code where possible (click the line number → "Reference in new issue").
Security issues: follow [SECURITY.md](SECURITY.md) instead.

## Development Setup

```bash
poetry install
pre-commit install
```

## Pull Request Process

1. Branch from an up-to-date `main` (`fix/<issue>-short-name`, `feat/<name>`, `docs/<name>`).
2. Keep each PR focused on one change; reference the issue with `Closes #<n>`.
3. Before opening a PR, all of these must pass:
   - `poetry run ruff format --check .`
   - `poetry run ruff check .` (0 errors)
   - `poetry run mypy` (0 errors, strict mode)
   - `poetry run bandit -c pyproject.toml -r .`
   - `poetry run pytest` (all tests pass, coverage ≥ 75%)
4. PRs are merged with squash/rebase only (linear history) after review by a code owner.
5. Direct pushes to `main` are blocked.

## Coding Style

- PEP 8, enforced by **ruff** (line length 88).
- Type hints on all functions (checked by **mypy --strict**).
- Docstrings on all public functions.
- No secrets in code. The trufflehog pre-commit hook will block them.

## Testing

- Put tests in `tests/`, named `test_*.py`.
- Mock network calls to Rekor (`unittest.mock.patch`) so tests are fast and deterministic.
- New features and bug fixes must include tests.