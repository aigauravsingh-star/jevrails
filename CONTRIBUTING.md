# Contributing

Thanks for helping make JevRails useful.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
```

## Design Principles

- Keep exact security checks local.
- Treat model decisions as probabilistic signals, not a complete security boundary.
- Add new semantic checks through the question catalog and policy config.
- Keep integrations thin and testable.

## Pull Requests

- Include tests for behavior changes.
- Document new public APIs in `README.md`.
- Avoid adding required runtime dependencies unless the core library truly needs them.
