# Release Checklist

## 1. Verify

```bash
python -m pip install -e ".[dev,openai,fastapi]"
python -m ruff check .
python -m pytest
python -m build
```

## 2. Publish Source

```bash
git init
git add .
git commit -m "Initial Apache-2.0 release"
git branch -M main
git remote add origin https://github.com/<owner>/jevrails.git
git push -u origin main
git tag v0.1.0
git push origin v0.1.0
```

## 3. Publish Package

```bash
python -m twine upload dist/*
```

## 4. Announce

Use the LinkedIn draft in the project notes and include:

- Apache-2.0 license.
- Alpha status.
- Hybrid security model.
- Request for benchmark feedback.
