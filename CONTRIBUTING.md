
---

### 📄 `CONTRIBUTING.md`

```markdown
# Contributing Guidelines

We love contributions! Here's how you can help:

---

## 🚀 Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/pe-security-analyzer.git
   cd pe-security-analyzer
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 💡 Submitting a Pull Request

1. Create a new branch:
   ```bash
   git checkout -b fix/your-feature-name
   ```

2. Make your changes and commit with a clear message:
   ```bash
   git commit -m "feat: short description of feature"
   ```

3. Push and open a pull request to the `main` branch.

---

## ✅ Requirements

- Follow [PEP8](https://pep8.org) style guide.
- All code should be lint-free (`flake8`) and preferably type-safe (`mypy`).
- Ensure your code runs on Python 3.6+.

---

## 📋 Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `chore:` Routine maintenance
- `test:` Adding or updating tests

---

## 🙌 Thank You!

Thanks for helping improve this project! 💙
```

---

### ⚙️ `.github/workflows/lint.yml` (CI for linting)

```yaml
name: Python Lint

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install flake8

      - name: Run flake8 linter
        run: |
          flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
          flake8 . --count --exit-zero --max-complexity=10 --max-line-length=120 --statistics
```

---
