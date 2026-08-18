# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.0   | :white_check_mark: |

---

## Security Features & Design

SquidMan is engineered with high-anonymity commercial proxy standards:
- **Zero-Leakage Header Filtering**: Removes `Via`, `X-Forwarded-For`, `From`, `Referer`, `Server`, and proxy client IP tags.
- **Bcrypt Hash Protection**: Passwords stored in `/etc/squid/users.pwd` are salted with standard `$2b$` bcrypt hashes.
- **Strict User IP Pool Enforcement**: Restricted users are strictly bound to their authorized outgoing pools; any unauthorized port or IP access attempt is dropped.
- **API Key Authentication**: Management endpoints are protected with constant-time comparison API keys (`X-API-Key`).

---

## Reporting a Vulnerability

If you discover a security vulnerability within this project:
1. Please **do not** report security vulnerabilities via public GitHub issues.
2. Submit a report privately by creating a [GitHub Security Advisory](https://github.com/magicrana/squidman/security) or contacting the maintainer.
3. Include a description of the vulnerability, reproduction steps, and potential impact.
