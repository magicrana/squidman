# 🛡️ Security Policy

We take the security of **SquidMan** seriously. This document outlines the supported versions, our core security posture, and the process for responsibly disclosing vulnerabilities.

---

## 📦 Supported Versions

Only the latest active major/minor releases receive active security patches and vulnerability triage:

| Version | Status | Supported |
| :--- | :--- | :---: |
| **`1.0.0`** | Current Active Release | ✅ Yes |

---

## 🔒 Security Architecture & Posture

SquidMan is engineered to satisfy strict high-anonymity commercial proxy standards:

| Layer / Mechanism | Implementation Details |
| :--- | :--- |
| **Zero-Leakage Filtering** | Strips sensitive tracking headers including `Via`, `X-Forwarded-For`, `From`, `Referer`, `Server`, and proxy client IP signatures. |
| **Credential Hardening** | Salting and hashing credentials in `/etc/squid/users.pwd` using standard `$2b$`-cost **bcrypt**. |
| **Strict Pool Isolation** | Rigidly confines restricted users to designated egress IP pools; unauthorized cross-port or egress route attempts are immediately dropped. |
| **API Key Authentication** | Management and control API endpoints require high-entropy keys validated via constant-time string comparison (`X-API-Key`) to prevent timing attacks. |

---

## 🚨 Reporting a Vulnerability

> [!CAUTION]
> **Do not disclose security vulnerabilities through public GitHub issues, discussions, or pull requests.**

If you discover a potential vulnerability or security flaw:

1. **Submit a Private Advisory**: Open a confidential advisory report via [GitHub Security Advisories](https://github.com/magicrana/squidman/security/advisories/new).
2. **Provide Reproducible Context**:
   - Detailed description of the flaw and affected endpoints/components.
   - Minimal reproduction steps, payload samples, or proof-of-concept (PoC) scripts.
   - Assessment of potential impact (e.g., identity leak, privilege escalation, unauthenticated access).
3. **Coordinated Disclosure**:
   - We aim to acknowledge reports within **48 hours**.
   - A timeline for remediation and public disclosure will be coordinated privately before any patch or advisory goes public.
