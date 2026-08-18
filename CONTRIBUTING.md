# 🦑 Contributing to SquidMan

Thank you for your interest in contributing to **SquidMan**! We welcome bug reports, feature requests, documentation improvements, and pull requests.

---

## 📋 Table of Contents

- [Getting Started](#-getting-started)
- [Local Development Setup](#-local-development-setup)
- [Testing & Verification](#-testing--verification)
- [Submitting Pull Requests](#-submitting-pull-requests)
- [Need Help?](#-need-help)

---

## 🚀 Getting Started

1. **Fork the Repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/magicrana/squidman.git
   cd squidman
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   # or for fixes:
   # git checkout -b fix/issue-description
   ```

---

## 🛠️ Local Development Setup

### 1. Create and Activate a Virtual Environment

```bash
# Create environment
python -m venv venv

# Activate (macOS / Linux):
source venv/bin/activate

# Activate (Windows):
venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install httpx
```

---

## 🧪 Testing & Verification

Ensure your environment is running smoothly and all automated checks pass before submitting code:

```bash
# 1. Run the automated test suite
python test_suite.py

# 2. Verify code syntax and compilation
python -m py_compile server.py
```

> [!TIP]
> Ensure all unit tests pass cleanly without unhandled exceptions before opening your pull request.

---

## 📬 Submitting Pull Requests

- **Keep it focused:** Limit each pull request to a single feature or bug fix.
- **Commit clearly:** Use concise, descriptive commit messages (e.g., `feat: implement retry handler`, `fix: address connection timeout`).
- **Explain your changes:** Include a concise summary of changes, references to any relevant issues (e.g., `Fixes #12`), and your verification steps.
- **All tests green:** Verify that `python test_suite.py` and `py_compile` pass without errors.

---

## 💬 Need Help?

If you run into issues or have questions about contributing, feel free to open an issue or start a discussion on GitHub.
