<div align="center">

# 🦑 SquidMan &bull; High-Anonymity Proxy Server & Panel

**Turn-key, multi-IP commercial forward proxy solution with an embedded FastAPI management dashboard.**

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Squid](https://img.shields.io/badge/Squid-5+-0078D7.svg)](http://www.squid-cache.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](test_suite.py)
[![Security: High Anonymity](https://img.shields.io/badge/anonymity-elite%20%2F%20zero--leakage-purple.svg)](SECURITY.md)

</div>

---

## 🌟 Highlights

- 🛡️ **Elite Zero-Leakage Anonymity**: All client headers (`Via`, `X-Forwarded-For`, `From`, `Referer`, `Server`) are automatically stripped. Caching is disabled (`cache deny all`) for maximum raw streaming bandwidth and minimal latency.
- ⚡ **1-Click Batch IP Pool Expansion**: Expand `/29`, `/30`, `/28` CIDR subnet blocks or custom IP ranges with sequential or shared inbound port mappings in a single click.
- 🔄 **Self-Outgoing Inbound Matching (`myip -> tcp_outgoing_address`)**: Inbound traffic arriving at any server IP automatically exits through that exact same IP address.
- 🔒 **User IP Pool Access Control**: Restrict users to specific IP pools (All IPs, Custom Selected List, Subnet/CIDR Range, or Fixed Single IP) with real-time modal pool inspectors and strict Squid ACL enforcement.
- 🔑 **Credential & Password Management**: Bcrypt salted hashes (`$2b$`) directly compatible with Apache `basic_ncsa_auth`, with in-dashboard password resets and strong password generators.
- 🌐 **Dynamic Secondary IP Binding**: Dynamically add and remove secondary IPv4 addresses using `NetworkManager` (`nmcli`) or `iproute2` (`ip addr`).
- 🚪 **Dedicated Inbound Port Routing**: Assign dedicated listening ports directly to specific outgoing IPs.
- ⚙️ **On-the-Fly Primary Port Changes**: Reconfigure primary proxy listening port (e.g. `3128`, `8080`, `1080`, `8888`) directly from the GUI with automated Squid reload.
- 📋 **Ready-to-Use Code Generator**: Instant connection snippets for cURL, Python (`requests`, `httpx`), Node.js (`axios`), Go, and CLI environment variables.
- 📊 **Modern Dark-Mode Dashboard**: Sleek single-page application embedded directly into the server with real-time CPU, RAM, uptime, and Squid service metrics.

---

## 📐 Architecture & Routing Flow

```
                      ┌──────────────────────────────────────────────┐
                      │                 Client                       │
                      │  (cURL, Python, Scrapers, Browsers, etc.)    │
                      └──────────────────────┬───────────────────────┘
                                             │ HTTP Proxy Request
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │              SquidMan Server                 │
                      │                                              │
                      │  1. Inbound Port (:3128 / :3129 / :3130)     │
                      │  2. Dual-Layer ACL Check:                    │
                      │     ├─ IP Whitelist (allowed_ips.txt)        │
                      │     └─ User Auth (users.pwd / bcrypt)        │
                      │  3. IP Pool & Routing Enforcement:           │
                      │     └─ User Authorized for this IP / Port?   │
                      │  4. Zero-Leakage Header Sanitization         │
                      │     (Strip Via, X-Forwarded-For, etc.)       │
                      └──────────────────────┬───────────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
                       ▼ Exit via IP #1                            ▼ Exit via IP #2
               (198.51.100.10)                             (198.51.100.11)
                       │                                           │
                       └─────────────────────┬─────────────────────┘
                                             │ Clean High-Anonymity Request
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │             Target Destination               │
                      │  (Target sees ONLY the chosen public IP)     │
                      └──────────────────────────────────────────────┘
```

---

## 🚀 Quick Start & Installation

###  Remote One-Liner (curl)

```bash
curl -sSL https://raw.githubusercontent.com/magicrana/squidman/main/setup.sh | sudo bash
```

---

## 📁 Repository Structure

```text
squidman/
├── server.py                # FastAPI REST API backend + Embedded SPA Dashboard
├── setup.sh                 # Multi-distro Linux installer & systemd configurator
├── uninstall.sh             # Interactive & automated uninstaller script
├── squid.conf.template      # Production zero-leakage Squid configuration
├── squid-panel.service      # Systemd service unit definition
├── requirements.txt         # Python dependencies (FastAPI, Uvicorn, Passlib, Bcrypt)
├── test_suite.py            # Automated integration & regression test suite
├── LICENSE                  # MIT License
├── CONTRIBUTING.md          # Guidelines for contributing
└── SECURITY.md              # Security policies and high-anonymity guarantee
```

---

## 🔑 REST API Reference

All REST endpoints require administrative authentication via the `X-API-Key: <YOUR_API_KEY>` HTTP header or `?api_key=<YOUR_API_KEY>` URL query parameter.

### 1. User & Credential Management

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/users` | List all proxy users with assigned IP pools |
| `POST` | `/api/v1/users` | Create or update a proxy user |
| `POST` | `/api/v1/users/{username}/password` | Reset password for a proxy user |
| `DELETE` | `/api/v1/users/{username}` | Permanently delete a proxy user |

#### Example: Create User with Dedicated Subnet Pool
```bash
curl -X POST http://127.0.0.1:8000/api/v1/users \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "crawler_bot_01",
    "password": "SecurePassword123!",
    "ip_access_mode": "range",
    "ip_range_or_cidr": "192.168.1.0/29",
    "notes": "Scraper Pool Alpha"
  }'
```

---

### 2. Multi-IP & Subnet Pool Expansion

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/network/ips/preview` | Preview usable host IPs from CIDR or Range |
| `POST` | `/api/v1/network/ips/batch` | Batch bind IP block to interface with sequential/shared ports |
| `POST` | `/api/v1/network/ips` | Bind a single secondary IPv4 address |
| `DELETE` | `/api/v1/network/ips` | Unbind a secondary IPv4 address |
| `GET` | `/api/v1/network/interfaces` | List network interfaces and all bound IPv4 addresses |

---

### 3. Port Routing & Squid Configuration

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/network/ports` | List dedicated port-to-IP mappings |
| `POST` | `/api/v1/network/ports` | Map dedicated inbound port to outgoing IP |
| `POST` | `/api/v1/config/port` | Change primary proxy listening port (e.g. :3128) |
| `GET` | `/api/v1/status` | Live system metrics (CPU, RAM, Squid status, uptime) |
| `POST` | `/api/v1/proxy/restart` | Issue safe service restart |

---

### 4. Client IP Whitelist

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/ips` | List all whitelisted client IPs / CIDRs |
| `POST` | `/api/v1/ips` | Add new IP / CIDR to whitelist |
| `DELETE` | `/api/v1/ips/{ip}` | Remove IP from whitelist |

---

## 🧪 Testing

Run the automated test suite locally:

```bash
# Install dependencies
pip install -r requirements.txt httpx

# Execute test suite
python test_suite.py
```

---

## 🗑️ Uninstallation

To cleanly remove SquidMan, stop background daemons, and remove configuration files:

```bash
sudo ./uninstall.sh
```

Or run automated non-interactive purge:

```bash
sudo ./uninstall.sh -y --purge
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <b>SquidMan</b> &bull; Crafted with ❤️ by <a href="https://github.com/magicrana">MagicRana</a>
</div>
