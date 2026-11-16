# Python Rekor Monitor Template

Template code for NYU CS-GY 9223 Software Supply Chain Security.

A command-line tool that verifies entries in the [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) transparency log. It can:

- fetch the latest signed checkpoint from the public Rekor instance,
- verify an artifact's signature and its **inclusion proof** in the log,
- verify **consistency** between an older checkpoint and the latest one.

## Installation

Requirements: Python 3.10+, [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/zyanTheKid/NYU-SSCS.git
cd NYU-SSCS
pipx install poetry
poetry install
```

## Usage

```bash
# Print the latest checkpoint
poetry run python main.py -c

# Verify an artifact's signature and inclusion in the log
poetry run python main.py --inclusion <log_index> --artifact artifact.md

# Verify consistency of an older checkpoint with the latest
poetry run python main.py --consistency --tree-id <id> --tree-size <size> --root-hash <hash>

# Add -d to any command for debug output
```

## Development

```bash
poetry install                      # installs dev tools too
pre-commit install                  # enables the trufflehog secret scan on commit

poetry run ruff format .            # format
poetry run ruff check .             # lint
poetry run mypy                     # type check
poetry run bandit -c pyproject.toml -r .   # security scan
poetry run pytest                   # tests + coverage report
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT. See [LICENSE](LICENSE).