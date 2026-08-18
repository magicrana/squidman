# Contributing to SquidMan

Thank you for your interest in contributing to **SquidMan**! We welcome bug reports, feature requests, documentation improvements, and pull requests.

---

## Getting Started

1. **Fork the Repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/magicrana/squidman.git
   cd squidman
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

---

## Local Development & Testing

1. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install httpx
   ```
3. Run the automated test suite:
   ```bash
   python test_suite.py
   ```
4. Verify code compilation:
   ```bash
   python -m py_compile server.py
   ```

---

## Submitting Pull Requests

- Keep pull requests focused on a single concern or feature.
- Ensure all tests pass before opening a PR.
- Write clear, descriptive commit messages.
- Provide a summary of changes and validation steps in your PR description.
