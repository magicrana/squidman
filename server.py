#!/usr/bin/env python3
"""
Production Squid Proxy Server Management Panel & REST API
High-Anonymity Commercial Forward Proxy Controller with:
  - Dual-Layer ACLs (Bcrypt htpasswd + Source IP Whitelisting)
  - Proxy User Management, Password Reset & Multi-IP Pool Access Editing
  - Enforced User IP Access Restrictions (User can only connect to authorized pool IPs)
  - Dedicated View-Only IP Pool Inspector Modal & Separate Edit Modal
  - Dynamic Network Interface & Secondary IP Management via nmcli & iproute2
  - Batch / Subnet / Pool IP Addition (/29, /30, /32, Range) with 1-Click Sequential or Shared Port Assignment
  - Self-Outgoing Inbound Matching (myip -> tcp_outgoing_address)
  - Dedicated Per-IP Port Forwarding (Unique Inbound Port -> Unique Outgoing IP via myport)
  - Dynamic Squid Proxy Port Configuration
"""

import os
import sys
import re
import time
import json
import socket
import logging
import ipaddress
import subprocess
from typing import List, Optional, Dict, Any
from pathlib import Path

# Load environment variables if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import psutil
from pydantic import BaseModel, Field, field_validator
from fastapi import FastAPI, HTTPException, Security, Depends, status, Request, Response
from fastapi.security.api_key import APIKeyHeader, APIKeyQuery
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
import requests
import bcrypt

# ------------------------------------------------------------------------------
# Logging Setup
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("squid-panel")

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
API_KEY = os.getenv("API_KEY", "squid-super-secret-admin-key-2026")
SQUID_CONF_PATH = os.getenv("SQUID_CONF_PATH", "/etc/squid/squid.conf")
SQUID_USERS_PATH = os.getenv("SQUID_USERS_PATH", "/etc/squid/users.pwd")
SQUID_ALLOWED_IPS_PATH = os.getenv("SQUID_ALLOWED_IPS_PATH", "/etc/squid/allowed_ips.txt")
SQUID_OUTGOING_IPS_PATH = os.getenv("SQUID_OUTGOING_IPS_PATH", "/etc/squid/outgoing_ips.conf")
SQUID_ACCESS_LOG_PATH = os.getenv("SQUID_ACCESS_LOG_PATH", "/var/log/squid/access.log")
ENV_FILE_PATH = os.getenv("ENV_FILE_PATH", "/opt/squid-panel/.env")

USERS_METADATA_PATH = os.getenv("USERS_METADATA_PATH", "/opt/squid-panel/data/users_meta.json")
IPS_METADATA_PATH = os.getenv("IPS_METADATA_PATH", "/opt/squid-panel/data/ips_meta.json")
ROUTING_METADATA_PATH = os.getenv("ROUTING_METADATA_PATH", "/opt/squid-panel/data/routing_meta.json")
INTERFACES_METADATA_PATH = os.getenv("INTERFACES_METADATA_PATH", "/opt/squid-panel/data/interfaces_meta.json")
PORTS_METADATA_PATH = os.getenv("PORTS_METADATA_PATH", "/opt/squid-panel/data/ports_meta.json")

PANEL_HOST = os.getenv("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.getenv("PANEL_PORT", "8080"))
PROXY_PORT = int(os.getenv("PROXY_PORT", "3128"))
SERVER_PUBLIC_IP = os.getenv("SERVER_PUBLIC_IP", "")

# Ensure data directories exist
for p in [USERS_METADATA_PATH, IPS_METADATA_PATH, ROUTING_METADATA_PATH, INTERFACES_METADATA_PATH, PORTS_METADATA_PATH, SQUID_OUTGOING_IPS_PATH]:
    try:
        Path(p).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# Cached public IP
_CACHED_PUBLIC_IP = ""
_LAST_IP_CHECK = 0

# ------------------------------------------------------------------------------
# Helper Utilities
# ------------------------------------------------------------------------------
def get_server_public_ip() -> str:
    global _CACHED_PUBLIC_IP, _LAST_IP_CHECK
    if SERVER_PUBLIC_IP:
        return SERVER_PUBLIC_IP
    
    current_time = time.time()
    if _CACHED_PUBLIC_IP and (current_time - _LAST_IP_CHECK < 300):
        return _CACHED_PUBLIC_IP
    
    providers = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/all.json",
        "https://icanhazip.com"
    ]
    for url in providers:
        try:
            resp = requests.get(url, timeout=2.5)
            if resp.status_code == 200:
                if "json" in url:
                    data = resp.json()
                    ip = data.get("ip") or data.get("ip_addr")
                    if ip:
                        _CACHED_PUBLIC_IP = ip.strip()
                        _LAST_IP_CHECK = current_time
                        return _CACHED_PUBLIC_IP
                else:
                    ip = resp.text.strip()
                    if ip:
                        _CACHED_PUBLIC_IP = ip
                        _LAST_IP_CHECK = current_time
                        return _CACHED_PUBLIC_IP
        except Exception:
            continue
            
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        _CACHED_PUBLIC_IP = local_ip
        _LAST_IP_CHECK = current_time
        return local_ip
    except Exception:
        return "127.0.0.1"


def execute_command(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Execute system command safely with output capture and configurable timeout."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return {
            "success": res.returncode == 0,
            "returncode": res.returncode,
            "stdout": res.stdout.strip(),
            "stderr": res.stderr.strip()
        }
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        return {
            "success": False,
            "returncode": -2,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"Command not found: {cmd[0]}"
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e)
        }


def get_auth_helper_path() -> str:
    """Find absolute path to basic_ncsa_auth on host system."""
    candidates = [
        "/usr/lib/squid/basic_ncsa_auth",
        "/usr/lib/squid3/basic_ncsa_auth",
        "/usr/lib64/squid/basic_ncsa_auth",
        "/usr/libexec/squid/basic_ncsa_auth",
        "/usr/lib/squid/ncsa_auth",
    ]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c
    for base in ["/usr/lib/squid", "/usr/lib/squid3", "/usr/lib64/squid", "/usr/libexec/squid"]:
        if os.path.exists(base):
            for root, _, files in os.walk(base):
                if "basic_ncsa_auth" in files:
                    p = os.path.join(root, "basic_ncsa_auth")
                    if os.access(p, os.X_OK):
                        return p
    return "/usr/lib/squid/basic_ncsa_auth"


def ensure_auxiliary_files():
    """Ensure Squid configuration directory, users.pwd, and allowed_ips.txt exist with valid formatting."""
    squid_dir = os.path.dirname(SQUID_CONF_PATH)
    if squid_dir and os.path.exists("/etc") and not os.path.exists(squid_dir):
        try:
            os.makedirs(squid_dir, exist_ok=True)
        except Exception:
            pass

    # 1. users.pwd
    if not os.path.exists(SQUID_USERS_PATH):
        try:
            os.makedirs(os.path.dirname(SQUID_USERS_PATH), exist_ok=True)
            with open(SQUID_USERS_PATH, "a", encoding="utf-8"):
                pass
            os.chmod(SQUID_USERS_PATH, 0o644)
        except Exception:
            pass

    # 2. allowed_ips.txt (Must not be empty to avoid Squid ACL parse warnings)
    if not os.path.exists(SQUID_ALLOWED_IPS_PATH) or os.path.getsize(SQUID_ALLOWED_IPS_PATH) == 0:
        try:
            os.makedirs(os.path.dirname(SQUID_ALLOWED_IPS_PATH), exist_ok=True)
            with open(SQUID_ALLOWED_IPS_PATH, "w", encoding="utf-8") as f:
                f.write("# Whitelisted source client IPs\n127.0.0.1/32\n")
            os.chmod(SQUID_ALLOWED_IPS_PATH, 0o644)
        except Exception:
            pass

    # 3. outgoing_ips.conf
    if not os.path.exists(SQUID_OUTGOING_IPS_PATH):
        try:
            os.makedirs(os.path.dirname(SQUID_OUTGOING_IPS_PATH), exist_ok=True)
            with open(SQUID_OUTGOING_IPS_PATH, "w", encoding="utf-8") as f:
                f.write("# Outgoing IP mapping rules\n")
            os.chmod(SQUID_OUTGOING_IPS_PATH, 0o644)
        except Exception:
            pass


def ensure_squid_conf_structure():
    """Ensure squid.conf contains valid helper paths and includes outgoing_ips.conf before authenticated_users without corrupting comments."""
    ensure_auxiliary_files()
    if not os.path.exists(SQUID_CONF_PATH):
        return
    try:
        with open(SQUID_CONF_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        modified = False

        # 1. Clean up any corrupted comment lines from previous replacements
        if "to enforce IP pool ACLs)" in content or "authenticated_users' to enforce" in content:
            content = re.sub(r"#\s*\(Loaded BEFORE.*to enforce IP pool ACLs\)\s*\n?", "", content)
            content = re.sub(r"^[^\n]*authenticated_users'\s+to\s+enforce[^\n]*\n?", "", content, flags=re.MULTILINE)
            modified = True
            logger.info("Cleaned up corrupted comment fragments in squid.conf")

        # 2. Replace __AUTH_HELPER_PATH__ placeholder if found
        if "__AUTH_HELPER_PATH__" in content:
            helper_path = get_auth_helper_path()
            content = content.replace("__AUTH_HELPER_PATH__", helper_path)
            modified = True
            logger.info(f"Replaced __AUTH_HELPER_PATH__ with '{helper_path}' in squid.conf")

        include_line = f"include {SQUID_OUTGOING_IPS_PATH}"

        # 3. Robust line-by-line inspection (excluding comments)
        lines = content.splitlines()
        filtered_lines = [l for l in lines if l.strip() != include_line]

        auth_idx = -1
        for i, l in enumerate(filtered_lines):
            trimmed = l.strip()
            if not trimmed.startswith("#") and re.match(r"^http_access\s+allow\s+authenticated_users\b", trimmed):
                auth_idx = i
                break

        if auth_idx != -1:
            filtered_lines.insert(auth_idx, include_line)
            new_content = "\n".join(filtered_lines) + "\n"
        else:
            filtered_lines.append(include_line)
            new_content = "\n".join(filtered_lines) + "\n"

        if new_content != content or modified:
            with open(SQUID_CONF_PATH, "w", encoding="utf-8") as f:
                f.write(new_content)
            logger.info("Validated and updated squid.conf structure cleanly.")
    except Exception as e:
        logger.warning(f"Could not verify squid.conf structure: {e}")


def is_squid_running() -> Dict[str, Any]:
    """Check if Squid daemon is actively running."""
    squid_procs = []
    for proc in psutil.process_iter(['pid', 'name', 'create_time', 'memory_info']):
        try:
            name = proc.info['name'].lower()
            if 'squid' in name:
                squid_procs.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "uptime_seconds": int(time.time() - proc.info['create_time']),
                    "rss_mb": round(proc.info['memory_info'].rss / (1024 * 1024), 2)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return {
        "running": len(squid_procs) > 0,
        "process_count": len(squid_procs),
        "processes": squid_procs
    }


def reload_squid_service() -> Dict[str, Any]:
    """Trigger dynamic re-parse of Squid configuration. If stopped, start service instead."""
    ensure_squid_conf_structure()

    # If Squid is NOT running, start it instead of reloading
    proc_status = is_squid_running()
    if not proc_status["running"]:
        logger.info("Squid daemon is stopped. Starting service instead of reloading...")
        return start_squid_service()

    # 1. Try squid -k reconfigure (fastest, keeps existing client connections open)
    res = execute_command(["squid", "-k", "reconfigure"], timeout=15)
    if res["success"]:
        logger.info("Squid reconfigured via 'squid -k reconfigure'")
        return {"success": True, "method": "squid -k reconfigure", "output": res["stdout"]}
    
    # 2. Check syntax with squid -k parse to identify specific config error
    parse_chk = execute_command(["squid", "-k", "parse"], timeout=10)
    if not parse_chk["success"] and "FATAL" in (parse_chk["stderr"] + parse_chk["stdout"]):
        err = parse_chk["stderr"] or parse_chk["stdout"]
        logger.warning(f"Squid syntax check issue: {err}")

    # 3. Try systemctl reload squid
    res2 = execute_command(["systemctl", "reload", "squid"], timeout=15)
    if res2["success"]:
        logger.info("Squid reconfigured via 'systemctl reload squid'")
        return {"success": True, "method": "systemctl reload squid", "output": res2["stdout"]}

    # 4. Fallback to restart
    return restart_squid_service()


def restart_squid_service() -> Dict[str, Any]:
    """Restart Squid service cleanly with automatic systemd reset-failed and syntax recovery."""
    ensure_squid_conf_structure()

    # Clear any previous systemd failed state so restart doesn't get blocked
    execute_command(["systemctl", "unmask", "squid"], timeout=5)
    execute_command(["systemctl", "reset-failed", "squid"], timeout=5)

    # 1. Try systemctl restart squid
    res = execute_command(["systemctl", "restart", "squid"], timeout=30)
    if res["success"]:
        logger.info("Squid restarted via 'systemctl restart squid'")
        return {"success": True, "method": "systemctl restart squid", "output": res["stdout"]}

    # 2. Try service squid restart
    res2 = execute_command(["service", "squid", "restart"], timeout=30)
    if res2["success"]:
        logger.info("Squid restarted via 'service squid restart'")
        return {"success": True, "method": "service squid restart", "output": res2["stdout"]}

    # 3. Try squid -k reconfigure
    res3 = execute_command(["squid", "-k", "reconfigure"], timeout=15)
    if res3["success"]:
        logger.info("Squid reconfigured via 'squid -k reconfigure'")
        return {"success": True, "method": "squid -k reconfigure", "output": res3["stdout"]}

    # 4. Try starting directly if stopped
    res4 = execute_command(["systemctl", "start", "squid"], timeout=20)
    if res4["success"]:
        logger.info("Squid started via 'systemctl start squid'")
        return {"success": True, "method": "systemctl start squid", "output": res4["stdout"]}

    # 5. Direct binary invocation fallback
    res5 = execute_command(["squid", "-sYC"], timeout=15)
    if res5["success"]:
        logger.info("Squid started directly via 'squid -sYC'")
        return {"success": True, "method": "squid -sYC", "output": res5["stdout"]}

    # Retrieve specific journalctl error message if possible
    j_res = execute_command(["journalctl", "-u", "squid.service", "-n", "10", "--no-pager"], timeout=10)
    err_detail = j_res.get("stdout") or res.get("stderr") or res2.get("stderr") or "Squid restart failed"
    logger.warning(f"Could not restart squid directly: {err_detail}")
    return {"success": False, "method": "failed", "error": err_detail}


def start_squid_service() -> Dict[str, Any]:
    """Start Squid service and ensure it is unmasked and enabled in systemd."""
    ensure_squid_conf_structure()
    execute_command(["systemctl", "unmask", "squid"], timeout=10)
    execute_command(["systemctl", "reset-failed", "squid"], timeout=10)
    execute_command(["systemctl", "enable", "squid.service"], timeout=10)
    execute_command(["systemctl", "enable", "squid"], timeout=10)
    
    res = execute_command(["systemctl", "start", "squid"], timeout=25)
    if res["success"]:
        logger.info("Squid started via 'systemctl start squid'")
        return {"success": True, "method": "systemctl start squid", "output": res["stdout"]}

    res2 = execute_command(["service", "squid", "start"], timeout=25)
    if res2["success"]:
        logger.info("Squid started via 'service squid start'")
        return {"success": True, "method": "service squid start", "output": res2["stdout"]}

    # Direct binary start fallback
    res3 = execute_command(["squid", "-sYC"], timeout=15)
    if res3["success"]:
        logger.info("Squid started directly via 'squid -sYC'")
        return {"success": True, "method": "squid -sYC", "output": res3["stdout"]}

    return restart_squid_service()


def ensure_squid_startup_service():
    """Ensure squid and network services are unmasked, enabled on system startup, and running."""
    try:
        execute_command(["systemctl", "unmask", "squid"], timeout=10)
        execute_command(["systemctl", "enable", "squid.service"], timeout=10)
        execute_command(["systemctl", "enable", "squid"], timeout=10)
        execute_command(["systemctl", "start", "squid"], timeout=20)
        logger.info("Squid startup service verified and enabled in systemd.")
    except Exception as e:
        logger.warning(f"Could not verify squid startup service in systemd: {e}")


def update_squid_port(new_port: int) -> bool:
    """Update primary http_port in squid.conf, update .env, and restart Squid."""
    global PROXY_PORT
    
    if os.path.exists(SQUID_CONF_PATH):
        try:
            lines = []
            port_updated = False
            with open(SQUID_CONF_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    if re.match(r"^\s*http_port\s+\d+", line):
                        lines.append(f"http_port {new_port}\n")
                        port_updated = True
                    else:
                        lines.append(line)
            
            if not port_updated:
                lines.insert(0, f"http_port {new_port}\n")

            with open(SQUID_CONF_PATH, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception as e:
            logger.error(f"Error updating squid.conf: {e}")
            raise RuntimeError(f"Failed to update squid.conf: {e}")

    if os.path.exists(ENV_FILE_PATH):
        try:
            env_lines = []
            env_updated = False
            with open(ENV_FILE_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PROXY_PORT="):
                        env_lines.append(f"PROXY_PORT={new_port}\n")
                        env_updated = True
                    else:
                        env_lines.append(line)
            if not env_updated:
                env_lines.append(f"PROXY_PORT={new_port}\n")
            with open(ENV_FILE_PATH, "w", encoding="utf-8") as f:
                f.writelines(env_lines)
        except Exception as e:
            logger.warning(f"Could not update .env: {e}")

    PROXY_PORT = new_port
    execute_command(["ufw", "allow", f"{new_port}/tcp", "comment", "Squid Proxy Primary Port"], timeout=10)
    sync_outgoing_ips_conf()
    restart_squid_service()
    return True

# ------------------------------------------------------------------------------
# IP Pool & Range Expansion Helper
# ------------------------------------------------------------------------------
def expand_ip_pool(
    mode: str,
    cidr_block: Optional[str] = None,
    start_ip: Optional[str] = None,
    end_ip: Optional[str] = None,
    ip_list: Optional[List[str]] = None,
    raw_text: Optional[str] = None,
    max_limit: int = 1024
) -> List[str]:
    """Expand and validate list of IPv4 addresses from CIDR, range, or raw text with strict memory limits."""
    results = []
    text = (raw_text or "").strip()

    if text:
        if "/" in text:
            mode = "cidr"
            cidr_block = text
        elif "-" in text:
            mode = "range"
        else:
            mode = "list"

    if mode == "cidr":
        target = (cidr_block or text).strip()
        if not target:
            raise ValueError("CIDR block must be specified (e.g. 192.168.1.0/29)")
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as ve:
            raise ValueError(f"Invalid CIDR format: {ve}")

        # Safety Guard: Subnet must not be larger than /22 (1024 IPs)
        if net.prefixlen < 22:
            raise ValueError(f"Subnet /{net.prefixlen} is too large ({net.num_addresses:,} IPs). Maximum allowed pool size is /22 (1,024 IPs).")

        if net.prefixlen >= 31:
            results = [str(ip) for ip in net]
        else:
            results = [str(ip) for ip in net.hosts()]
            if not results:
                results = [str(ip) for ip in net]

    elif mode == "range":
        if text and "-" in text:
            parts = text.split("-", 1)
            s_ip = parts[0].strip()
            e_ip = parts[1].strip()
        else:
            s_ip = (start_ip or "").strip()
            e_ip = (end_ip or "").strip()

        if not s_ip or not e_ip:
            raise ValueError("Start IP and End IP must both be specified (e.g. 192.168.1.5 - 192.168.1.20)")

        try:
            start_obj = ipaddress.IPv4Address(s_ip)
            end_obj = ipaddress.IPv4Address(e_ip)
        except ValueError as ve:
            raise ValueError(f"Invalid IP address: {ve}")

        if int(end_obj) < int(start_obj):
            raise ValueError(f"Start IP ({s_ip}) cannot be greater than End IP ({e_ip})")

        count = int(end_obj) - int(start_obj) + 1
        if count > max_limit:
            raise ValueError(f"Range contains {count:,} IPs. Maximum allowed pool size is {max_limit:,} IPs.")

        for i in range(int(start_obj), int(end_obj) + 1):
            results.append(str(ipaddress.IPv4Address(i)))

    elif mode == "list":
        items = []
        if ip_list:
            items = ip_list
        elif text:
            items = re.split(r"[\r\n,;\s]+", text)

        for item in items:
            item = item.strip()
            if item:
                try:
                    ip_obj = ipaddress.IPv4Address(item)
                    results.append(str(ip_obj))
                except ValueError:
                    pass

    seen = set()
    deduped = []
    for ip in results:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
            if len(deduped) >= max_limit:
                break

    if not deduped:
        raise ValueError("No valid IPv4 addresses found in input.")

    return deduped

# ------------------------------------------------------------------------------
# Dedicated IP Port & Outbound Routing (myip, myport & tcp_outgoing_address)
# ------------------------------------------------------------------------------
def load_ports_metadata() -> Dict[str, int]:
    """Load IP-to-Port mappings { outgoing_ip: listening_port }."""
    if os.path.exists(PORTS_METADATA_PATH):
        try:
            with open(PORTS_METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_ports_metadata(meta: Dict[str, int]):
    try:
        with open(PORTS_METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not save ports metadata: {e}")


def load_routing_metadata() -> Dict[str, str]:
    """Load user to outgoing IP mappings { username: outgoing_ip }."""
    if os.path.exists(ROUTING_METADATA_PATH):
        try:
            with open(ROUTING_METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_routing_metadata(meta: Dict[str, str]):
    try:
        with open(ROUTING_METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not save routing metadata: {e}")


def assign_ip_port(ip_str: str, port: Optional[int], sync_now: bool = True) -> bool:
    """Assign or remove an incoming listening port for an outgoing IP (supports dedicated or shared ports)."""
    clean_ip = ip_str.strip().split("/")[0].strip()
    try:
        norm_ip = str(ipaddress.ip_address(clean_ip))
    except ValueError:
        norm_ip = clean_ip

    ports_meta = load_ports_metadata()

    if port is not None and port > 0:
        if port == PROXY_PORT:
            raise ValueError(f"Port {port} is already used as the primary Squid listening port.")

        ports_meta[norm_ip] = port
        execute_command(["ufw", "allow", f"{port}/tcp", "comment", f"Squid IP Port {norm_ip}"], timeout=10)
    else:
        if norm_ip in ports_meta:
            del ports_meta[norm_ip]

    save_ports_metadata(ports_meta)

    # Sync interfaces_meta as well
    meta = load_interfaces_metadata()
    updated_iface_meta = False
    for key, val in meta.items():
        if key.endswith(f":{norm_ip}") or val.get("ip") == norm_ip:
            val["assigned_port"] = port
            updated_iface_meta = True
    if updated_iface_meta:
        save_interfaces_metadata(meta)

    if sync_now:
        sync_outgoing_ips_conf()
    return True


def sync_outgoing_ips_conf():
    """
    Compile and write /etc/squid/outgoing_ips.conf:
      1. Dedicated Port Listeners (http_port <PORT>)
      2. Dynamic Inbound IP -> Outbound IP Matching (myip -> tcp_outgoing_address)
         (Ensures whenever a user connects to IP X, traffic automatically exits through IP X)
      3. Dedicated Inbound Port -> Outbound IP Matching (myport -> tcp_outgoing_address for unique ports)
      4. User-specific Dedicated Outgoing IP overrides
      5. User-specific Allowed IP Pool Access Control (STRICT ACL: Enforces that restricted users
         can ONLY connect to their authorized IP pool; access to any other IP is denied!)
    """
    ensure_squid_conf_structure()

    routing = load_routing_metadata()
    ports_meta = load_ports_metadata()
    users_meta = load_users_metadata()
    interfaces = get_network_interfaces()
    
    # Collect all bound IPv4 addresses on all interfaces
    all_bound_ips = set()
    for iface in interfaces:
        for addr in iface.get("ipv4_addresses", []):
            ip_val = addr.get("ip")
            if ip_val and not ip_val.startswith("127."):
                all_bound_ips.add(ip_val)

    for ip_val in ports_meta.keys():
        if ip_val:
            all_bound_ips.add(ip_val)

    lines = [
        "# ==============================================================================",
        "# Dedicated Outgoing IP Mappings, Port Listeners & Dynamic Inbound IP Routing",
        "# Generated automatically by SquidMan Management Panel",
        f"# Updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "# ==============================================================================\n"
    ]

    # 1. Additional Port Listeners
    lines.append("# --- 1. Dedicated Additional Port Listeners ---")
    dedicated_ports = set(ports_meta.values())
    for p in sorted(dedicated_ports):
        if p and p != PROXY_PORT:
            lines.append(f"http_port {p}")
    lines.append("")

    # 2. STRICT User-Specific Allowed IP Pool Access Restrictions (http_access)
    # (Evaluated before global authenticated_users to strictly forbid connection to non-assigned IPs)
    lines.append("# --- 2. User-Specific Allowed IP Pool Access Restrictions ---")
    for username, udata in sorted(users_meta.items(), key=lambda x: x[0]):
        ip_mode = udata.get("ip_access_mode", "all")
        assigned_ips = udata.get("assigned_ips", [])
        outgoing_ip = routing.get(username)

        # In 'single' mode, restrict strictly to the chosen single IP
        if ip_mode == "single":
            if outgoing_ip and outgoing_ip.strip():
                assigned_ips = [outgoing_ip.strip()]
            elif assigned_ips:
                assigned_ips = [assigned_ips[0].strip()]

        # If user has a restricted IP pool ('single', 'custom_list', or 'range')
        if ip_mode in ["single", "custom_list", "range"]:
            clean_user = re.sub(r"[^a-zA-Z0-9_\.\-]", "_", username)
            valid_ips = [ip.strip() for ip in assigned_ips if ip and ip.strip()]

            if valid_ips:
                ips_space_separated = " ".join(valid_ips)
                lines.append(f"# STRICT Pool Access Enforcement for user '{username}' (Mode: {ip_mode}, {len(valid_ips)} Allowed IPs)")
                lines.append(f"acl user_auth_{clean_user} proxy_auth {username}")
                lines.append(f"acl user_pool_ips_{clean_user} myip {ips_space_separated}")
                lines.append(f"http_access allow user_auth_{clean_user} user_pool_ips_{clean_user}")
                lines.append(f"http_access deny user_auth_{clean_user}\n")
            else:
                # User is set to restricted mode but has no assigned IPs -> deny all proxy requests
                lines.append(f"# User '{username}' has no assigned IPs in restricted mode -> Deny all access")
                lines.append(f"acl user_auth_{clean_user} proxy_auth {username}")
                lines.append(f"http_access deny user_auth_{clean_user}\n")

    # 3. User-specific Outbound Overrides (Fixed Dedicated Outgoing IP)
    lines.append("# --- 3. User-Specific Dedicated Outbound Overrides ---")
    for username, outgoing_ip in sorted(routing.items(), key=lambda x: x[0]):
        if outgoing_ip and outgoing_ip.strip():
            clean_user = re.sub(r"[^a-zA-Z0-9_\.\-]", "_", username)
            lines.append(f"# User: {username} -> Fixed Outgoing IP: {outgoing_ip}")
            lines.append(f"acl user_route_{clean_user} proxy_auth {username}")
            lines.append(f"tcp_outgoing_address {outgoing_ip.strip()} user_route_{clean_user}\n")

    # 4. Port-specific Outbound Routing Rules (myport -> tcp_outgoing_address)
    lines.append("# --- 4. Port-Specific Dedicated Outbound Routes (myport) ---")
    port_to_ips = {}
    for outgoing_ip, port_num in ports_meta.items():
        if port_num and port_num > 0 and outgoing_ip:
            port_to_ips.setdefault(port_num, []).append(outgoing_ip)

    for port_num, ips_list in sorted(port_to_ips.items(), key=lambda x: x[0]):
        if len(ips_list) == 1:
            outgoing_ip = ips_list[0]
            lines.append(f"# Unique Port :{port_num} -> Dedicated Outbound IP: {outgoing_ip}")
            lines.append(f"acl port_route_{port_num} myport {port_num}")
            lines.append(f"tcp_outgoing_address {outgoing_ip} port_route_{port_num}\n")
        else:
            lines.append(f"# Inbound Port :{port_num} is shared across {len(ips_list)} IPs (dynamically routed via myip rules)\n")

    # 5. Inbound Interface IP Self-Outgoing Dynamic Routing (myip -> tcp_outgoing_address)
    lines.append("# --- 5. Inbound Interface IP Self-Outgoing Routing (myip) ---")
    for ip in sorted(all_bound_ips):
        clean_ip_acl = "myip_" + ip.replace(".", "_")
        lines.append(f"# Inbound IP: {ip} -> Outgoing IP: {ip}")
        lines.append(f"acl {clean_ip_acl} myip {ip}")
        lines.append(f"tcp_outgoing_address {ip} {clean_ip_acl}\n")

    Path(SQUID_OUTGOING_IPS_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(SQUID_OUTGOING_IPS_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    restart_squid_service()


def assign_user_outgoing_ip(username: str, outgoing_ip: Optional[str]) -> bool:
    """Assign or remove dedicated outgoing IP for a proxy user."""
    routing = load_routing_metadata()
    if outgoing_ip and outgoing_ip.strip():
        norm_ip = str(ipaddress.ip_address(outgoing_ip.strip()))
        routing[username] = norm_ip
    else:
        if username in routing:
            del routing[username]

    save_routing_metadata(routing)
    sync_outgoing_ips_conf()
    return True

# ------------------------------------------------------------------------------
# Network Interfaces & Secondary IP Management (nmcli & iproute2)
# ------------------------------------------------------------------------------
def load_interfaces_metadata() -> Dict[str, Any]:
    if os.path.exists(INTERFACES_METADATA_PATH):
        try:
            with open(INTERFACES_METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_interfaces_metadata(meta: Dict[str, Any]):
    try:
        with open(INTERFACES_METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not save interfaces metadata: {e}")


def get_network_interfaces() -> List[Dict[str, Any]]:
    """Scan all network interfaces, status, active IP bindings, and assigned proxy ports."""
    results = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    meta = load_interfaces_metadata()
    ports_meta = load_ports_metadata()

    nm_devices = {}
    nm_res = execute_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
    if nm_res["success"]:
        for line in nm_res["stdout"].splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 4:
                nm_devices[parts[0]] = {
                    "type": parts[1],
                    "state": parts[2],
                    "connection": parts[3]
                }

    for iface_name, addr_list in addrs.items():
        if iface_name.lower().startswith("lo"):
            continue

        if_stat = stats.get(iface_name)
        is_up = if_stat.isup if if_stat else True
        speed = if_stat.speed if if_stat else 0
        mtu = if_stat.mtu if if_stat else 1500

        ipv4_list = []
        ipv6_list = []
        mac_address = ""

        for a in addr_list:
            if a.family == socket.AF_INET:
                ip_str = a.address
                netmask = a.netmask
                is_primary = (len(ipv4_list) == 0)
                
                try:
                    cidr = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen if netmask else 32
                except Exception:
                    cidr = 32

                assigned_port = ports_meta.get(ip_str)

                ipv4_list.append({
                    "ip": ip_str,
                    "netmask": netmask,
                    "cidr": cidr,
                    "ip_cidr": f"{ip_str}/{cidr}",
                    "is_primary": is_primary,
                    "is_secondary": not is_primary,
                    "assigned_port": assigned_port,
                    "label": meta.get(f"{iface_name}:{ip_str}", {}).get("label", "Primary Interface IP" if is_primary else "Secondary IP")
                })
            elif hasattr(socket, "AF_INET6") and a.family == socket.AF_INET6:
                if not a.address.lower().startswith("fe80:"):
                    ipv6_list.append(a.address)
            elif hasattr(psutil, "AF_LINK") and a.family == psutil.AF_LINK:
                mac_address = a.address

        # Check for any secondary IPs in interfaces_meta that belong to this interface
        existing_ips = {a["ip"] for a in ipv4_list}
        for meta_key, meta_val in meta.items():
            if ":" in meta_key:
                m_iface, m_ip = meta_key.split(":", 1)
                if m_iface == iface_name and m_ip not in existing_ips:
                    m_cidr = meta_val.get("cidr", 32)
                    assigned_port = ports_meta.get(m_ip) or meta_val.get("assigned_port")
                    ipv4_list.append({
                        "ip": m_ip,
                        "netmask": "255.255.255.255",
                        "cidr": m_cidr,
                        "ip_cidr": f"{m_ip}/{m_cidr}",
                        "is_primary": False,
                        "is_secondary": True,
                        "assigned_port": assigned_port,
                        "label": meta_val.get("label", "Secondary IP")
                    })
                    existing_ips.add(m_ip)

        nm_info = nm_devices.get(iface_name, {})
        results.append({
            "name": iface_name,
            "is_up": is_up,
            "speed_mbps": speed,
            "mtu": mtu,
            "mac_address": mac_address,
            "connection_name": nm_info.get("connection") or iface_name,
            "device_type": nm_info.get("type", "ethernet"),
            "ipv4_addresses": ipv4_list,
            "ipv6_addresses": ipv6_list,
            "total_ips": len(ipv4_list)
        })

    # Include interfaces in metadata that were not found in psutil
    found_ifaces = {res["name"] for res in results}
    meta_iface_ips = {}
    for meta_key, meta_val in meta.items():
        if ":" in meta_key:
            m_iface, m_ip = meta_key.split(":", 1)
            if m_iface not in found_ifaces:
                meta_iface_ips.setdefault(m_iface, []).append((m_ip, meta_val))

    for m_iface, ip_tuples in meta_iface_ips.items():
        ipv4_list = []
        for idx, (m_ip, meta_val) in enumerate(ip_tuples):
            m_cidr = meta_val.get("cidr", 32)
            assigned_port = ports_meta.get(m_ip) or meta_val.get("assigned_port")
            ipv4_list.append({
                "ip": m_ip,
                "netmask": "255.255.255.255",
                "cidr": m_cidr,
                "ip_cidr": f"{m_ip}/{m_cidr}",
                "is_primary": idx == 0,
                "is_secondary": idx > 0,
                "assigned_port": assigned_port,
                "label": meta_val.get("label", "Secondary IP")
            })
        results.append({
            "name": m_iface,
            "is_up": True,
            "speed_mbps": 1000,
            "mtu": 1500,
            "mac_address": "",
            "connection_name": m_iface,
            "device_type": "ethernet",
            "ipv4_addresses": ipv4_list,
            "ipv6_addresses": [],
            "total_ips": len(ipv4_list)
        })

    return results


def add_secondary_ip(
    interface: str,
    ip_str: str,
    cidr: int = 32,
    label: str = "",
    persistent: bool = True,
    port: Optional[int] = None,
    sync_now: bool = True
) -> Dict[str, Any]:
    """Add secondary IP to network interface via nmcli and iproute2, with optional proxy port."""
    try:
        norm_ip = str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")

    ip_cidr = f"{norm_ip}/{cidr}"
    methods_used = []

    if persistent:
        conn_res = execute_command(["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", interface])
        conn_name = conn_res["stdout"].strip() if conn_res["success"] else interface
        
        if conn_name and conn_name != "--":
            mod_res = execute_command(["nmcli", "connection", "modify", conn_name, "+ipv4.addresses", ip_cidr])
            if mod_res["success"]:
                execute_command(["nmcli", "connection", "up", conn_name])
                methods_used.append("nmcli")

    ip_res = execute_command(["ip", "addr", "add", ip_cidr, "dev", interface])
    if ip_res["success"] or "File exists" in ip_res["stderr"]:
        methods_used.append("iproute2")

    meta = load_interfaces_metadata()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    meta[f"{interface}:{norm_ip}"] = {
        "interface": interface,
        "ip": norm_ip,
        "cidr": cidr,
        "ip_cidr": ip_cidr,
        "label": label or "Secondary IP",
        "created_at": now_str,
        "persistent": persistent,
        "assigned_port": port
    }
    save_interfaces_metadata(meta)

    if port is not None and port > 0:
        assign_ip_port(norm_ip, port, sync_now=False)

    if sync_now:
        sync_outgoing_ips_conf()

    return {
        "success": True,
        "interface": interface,
        "ip": norm_ip,
        "ip_cidr": ip_cidr,
        "assigned_port": port,
        "methods": methods_used or ["simulated"],
        "message": f"Secondary IP {ip_cidr} added to {interface}." + (f" Port :{port} assigned." if port else "")
    }


def add_secondary_ip_batch(
    interface: str,
    ip_list: List[str],
    cidr: int = 32,
    label_prefix: str = "Pool IP",
    persistent: bool = True,
    start_port: Optional[int] = None,
    port_mode: str = "sequential"
) -> Dict[str, Any]:
    """Add a batch of secondary IPs to an interface with sequential or shared same-port mapping."""
    added_list = []
    current_port = start_port

    for idx, ip_str in enumerate(ip_list):
        if port_mode == "sequential":
            port_to_assign = current_port if current_port else None
        elif port_mode == "same":
            port_to_assign = start_port if start_port else None
        else:
            port_to_assign = None

        label = f"{label_prefix} #{idx + 1}" if label_prefix else "Secondary IP"
        
        try:
            add_secondary_ip(
                interface=interface,
                ip_str=ip_str,
                cidr=cidr,
                label=label,
                persistent=persistent,
                port=port_to_assign,
                sync_now=False
            )
            added_list.append({
                "ip": ip_str,
                "port": port_to_assign
            })
            if port_mode == "sequential" and current_port:
                current_port += 1
        except Exception as e:
            logger.warning(f"Batch IP add warning for {ip_str}: {e}")
            added_list.append({
                "ip": ip_str,
                "port": port_to_assign,
                "warning": str(e)
            })

    sync_outgoing_ips_conf()

    return {
        "success": True,
        "total_added": len(added_list),
        "added_ips": added_list,
        "message": f"Successfully processed {len(added_list)} IPs for interface {interface}."
    }


def remove_secondary_ip(interface: str, ip_str: str, cidr: int = 32) -> Dict[str, Any]:
    """Remove secondary IP from network interface via nmcli and iproute2."""
    try:
        norm_ip = str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        norm_ip = ip_str.strip()

    ip_cidr = f"{norm_ip}/{cidr}"
    methods_used = []

    conn_res = execute_command(["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", interface])
    conn_name = conn_res["stdout"].strip() if conn_res["success"] else interface
    if conn_name and conn_name != "--":
        mod_res = execute_command(["nmcli", "connection", "modify", conn_name, "-ipv4.addresses", ip_cidr])
        if mod_res["success"]:
            execute_command(["nmcli", "connection", "up", conn_name])
            methods_used.append("nmcli")

    ip_res = execute_command(["ip", "addr", "del", ip_cidr, "dev", interface])
    if ip_res["success"]:
        methods_used.append("iproute2")

    meta = load_interfaces_metadata()
    key = f"{interface}:{norm_ip}"
    if key in meta:
        del meta[key]
        save_interfaces_metadata(meta)

    ports_meta = load_ports_metadata()
    if norm_ip in ports_meta:
        del ports_meta[norm_ip]
        save_ports_metadata(ports_meta)

    sync_outgoing_ips_conf()

    return {
        "success": True,
        "interface": interface,
        "ip": norm_ip,
        "methods": methods_used or ["simulated"],
        "message": f"Secondary IP {norm_ip} removed from {interface}."
    }

# ------------------------------------------------------------------------------
# User (htpasswd) Management & Multi-IP User Assignment
# ------------------------------------------------------------------------------
def load_users_metadata() -> Dict[str, Dict[str, Any]]:
    if os.path.exists(USERS_METADATA_PATH):
        try:
            with open(USERS_METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_users_metadata(meta: Dict[str, Dict[str, Any]]):
    try:
        with open(USERS_METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not save users metadata: {e}")


def hash_password_bcrypt(password: str) -> str:
    """Generate Apache htpasswd compatible bcrypt ($2b$) hash."""
    salt = bcrypt.gensalt(rounds=10, prefix=b'2b')
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def get_all_proxy_users() -> List[Dict[str, Any]]:
    users = []
    meta = load_users_metadata()
    routing = load_routing_metadata()
    ports_meta = load_ports_metadata()
    
    if os.path.exists(SQUID_USERS_PATH):
        try:
            with open(SQUID_USERS_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":", 1)
                    if len(parts) >= 1:
                        username = parts[0].strip()
                        user_meta = meta.get(username, {})
                        outgoing_ip = routing.get(username, "")
                        ip_access_mode = user_meta.get("ip_access_mode", "single" if outgoing_ip else ("custom_list" if user_meta.get("assigned_ips") else "all"))
                        assigned_ips = user_meta.get("assigned_ips", [])
                        ip_range_or_cidr = user_meta.get("ip_range_or_cidr", "")
                        assigned_port = ports_meta.get(outgoing_ip) if outgoing_ip else None
                        users.append({
                            "username": username,
                            "has_password": len(parts) == 2 and len(parts[1]) > 0,
                            "outgoing_ip": outgoing_ip,
                            "ip_access_mode": ip_access_mode,
                            "assigned_ips": assigned_ips,
                            "ip_range_or_cidr": ip_range_or_cidr,
                            "assigned_port": assigned_port,
                            "has_dedicated_ip": bool(outgoing_ip),
                            "created_at": user_meta.get("created_at", "N/A"),
                            "notes": user_meta.get("notes", ""),
                            "last_updated": user_meta.get("last_updated", "")
                        })
        except Exception as e:
            logger.error(f"Error reading {SQUID_USERS_PATH}: {e}")
    return users


def add_or_update_proxy_user(
    username: str,
    password: Optional[str] = None,
    notes: Optional[str] = None,
    outgoing_ip: Optional[str] = None,
    ip_access_mode: str = "all",
    assigned_ips: Optional[List[str]] = None,
    ip_range_or_cidr: Optional[str] = None
) -> bool:
    """Add or update htpasswd user entry, metadata, and multi-IP assignment."""
    if not re.match(r"^[a-zA-Z0-9_\.\-]+$", username):
        raise ValueError("Username can only contain alphanumeric characters, hyphens, underscores, and dots.")

    # Only update password if provided
    if password and password.strip():
        htpasswd_success = False
        if os.path.exists("/usr/bin/htpasswd") or execute_command(["which", "htpasswd"])["success"]:
            res = execute_command(["htpasswd", "-b", "-B", SQUID_USERS_PATH, username, password])
            if res["success"]:
                htpasswd_success = True

        if not htpasswd_success:
            hashed = hash_password_bcrypt(password)
            lines = []
            user_replaced = False
            
            if os.path.exists(SQUID_USERS_PATH):
                with open(SQUID_USERS_PATH, "r", encoding="utf-8") as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith(f"{username}:"):
                            lines.append(f"{username}:{hashed}\n")
                            user_replaced = True
                        elif stripped:
                            lines.append(f"{stripped}\n")
            
            if not user_replaced:
                lines.append(f"{username}:{hashed}\n")
                
            Path(SQUID_USERS_PATH).parent.mkdir(parents=True, exist_ok=True)
            with open(SQUID_USERS_PATH, "w", encoding="utf-8") as f:
                f.writelines(lines)

    # Process assigned IPs based on mode
    final_assigned_ips = assigned_ips or []
    if ip_access_mode == "single":
        if outgoing_ip and outgoing_ip.strip():
            final_assigned_ips = [outgoing_ip.strip()]
        elif final_assigned_ips:
            outgoing_ip = final_assigned_ips[0].strip()
    elif ip_access_mode == "range" and ip_range_or_cidr and ip_range_or_cidr.strip():
        try:
            final_assigned_ips = expand_ip_pool(mode="cidr" if "/" in ip_range_or_cidr else "range", raw_text=ip_range_or_cidr)
        except Exception as e:
            logger.warning(f"Error expanding user IP range {ip_range_or_cidr}: {e}")
    elif ip_access_mode == "custom_list":
        final_assigned_ips = [ip.strip() for ip in (assigned_ips or []) if ip and ip.strip()]

    meta = load_users_metadata()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    if username not in meta:
        meta[username] = {
            "created_at": now_str,
            "last_updated": now_str,
            "notes": notes or "",
            "ip_access_mode": ip_access_mode,
            "assigned_ips": final_assigned_ips,
            "ip_range_or_cidr": ip_range_or_cidr or ""
        }
    else:
        meta[username]["last_updated"] = now_str
        if notes is not None:
            meta[username]["notes"] = notes
        meta[username]["ip_access_mode"] = ip_access_mode
        meta[username]["assigned_ips"] = final_assigned_ips
        if ip_range_or_cidr is not None:
            meta[username]["ip_range_or_cidr"] = ip_range_or_cidr
            
    save_users_metadata(meta)

    if ip_access_mode == "single" and outgoing_ip:
        assign_user_outgoing_ip(username, outgoing_ip.strip())
    else:
        assign_user_outgoing_ip(username, None)

    return True


def delete_proxy_user(username: str) -> bool:
    """Remove user from htpasswd, metadata, and routing configuration."""
    if not os.path.exists(SQUID_USERS_PATH):
        return False
        
    found = False
    lines = []
    with open(SQUID_USERS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith(f"{username}:"):
                found = True
            elif stripped:
                lines.append(f"{stripped}\n")
                
    if found:
        with open(SQUID_USERS_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)
            
        meta = load_users_metadata()
        if username in meta:
            del meta[username]
            save_users_metadata(meta)

        assign_user_outgoing_ip(username, None)
            
    return found

# ------------------------------------------------------------------------------
# IP Whitelist Management
# ------------------------------------------------------------------------------
def load_ips_metadata() -> Dict[str, Dict[str, Any]]:
    if os.path.exists(IPS_METADATA_PATH):
        try:
            with open(IPS_METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_ips_metadata(meta: Dict[str, Dict[str, Any]]):
    try:
        with open(IPS_METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not save IPs metadata: {e}")


def normalize_ip_or_cidr(ip_str: str) -> str:
    """Validate and return normalized IP or CIDR string."""
    ip_str = ip_str.strip()
    try:
        if "/" in ip_str:
            net = ipaddress.ip_network(ip_str, strict=False)
            return str(net)
        else:
            ip = ipaddress.ip_address(ip_str)
            return str(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address or CIDR format: {ip_str}")


def get_all_allowed_ips() -> List[Dict[str, Any]]:
    results = []
    meta = load_ips_metadata()
    
    if os.path.exists(SQUID_ALLOWED_IPS_PATH):
        try:
            with open(SQUID_ALLOWED_IPS_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("#", 1)
                    ip_val = parts[0].strip()
                    inline_comment = parts[1].strip() if len(parts) > 1 else ""
                    
                    ip_meta = meta.get(ip_val, {})
                    is_subnet = "/" in ip_val and not ip_val.endswith("/32")
                    results.append({
                        "ip": ip_val,
                        "is_subnet": is_subnet,
                        "label": ip_meta.get("label") or inline_comment or "Whitelisted Client",
                        "created_at": ip_meta.get("created_at", "N/A"),
                        "last_updated": ip_meta.get("last_updated", "")
                    })
        except Exception as e:
            logger.error(f"Error reading {SQUID_ALLOWED_IPS_PATH}: {e}")
    return results


def add_allowed_ip(ip_str: str, label: str = "") -> bool:
    """Add validated IP/CIDR to allowed_ips.txt and reload Squid."""
    norm_ip = normalize_ip_or_cidr(ip_str)
    
    current_ips = []
    if os.path.exists(SQUID_ALLOWED_IPS_PATH):
        with open(SQUID_ALLOWED_IPS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    current_ips.append(stripped.split("#")[0].strip())
                    
    if norm_ip in current_ips:
        meta = load_ips_metadata()
        now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        meta[norm_ip] = {
            "label": label or meta.get(norm_ip, {}).get("label", "Whitelisted Client"),
            "created_at": meta.get(norm_ip, {}).get("created_at", now_str),
            "last_updated": now_str
        }
        save_ips_metadata(meta)
        return True

    Path(SQUID_ALLOWED_IPS_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(SQUID_ALLOWED_IPS_PATH, "a", encoding="utf-8") as f:
        if label:
            f.write(f"{norm_ip} # {label}\n")
        else:
            f.write(f"{norm_ip}\n")
            
    meta = load_ips_metadata()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    meta[norm_ip] = {
        "label": label or "Whitelisted Client",
        "created_at": now_str,
        "last_updated": now_str
    }
    save_ips_metadata(meta)
    
    reload_squid_service()
    return True


def delete_allowed_ip(ip_str: str) -> bool:
    """Remove IP/CIDR from allowed_ips.txt and reload Squid."""
    if not os.path.exists(SQUID_ALLOWED_IPS_PATH):
        return False
        
    try:
        norm_ip = normalize_ip_or_cidr(ip_str)
    except ValueError:
        norm_ip = ip_str.strip()

    found = False
    lines = []
    with open(SQUID_ALLOWED_IPS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                existing_ip = stripped.split("#")[0].strip()
                if existing_ip == norm_ip or existing_ip == ip_str.strip():
                    found = True
                    continue
            if stripped:
                lines.append(f"{stripped}\n")
                
    if found:
        with open(SQUID_ALLOWED_IPS_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)
            
        meta = load_ips_metadata()
        if norm_ip in meta:
            del meta[norm_ip]
            save_ips_metadata(meta)
            
        reload_squid_service()
        
    return found

# ------------------------------------------------------------------------------
# FastAPI Application & Security
# ------------------------------------------------------------------------------
app = FastAPI(
    title="SquidMan Management API",
    description="REST API for High-Anonymity Squid Proxy Management, Batch IP Pools, Multi-IP User Routing, and Per-IP Port Forwarding",
    version="2.7.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

async def verify_auth(
    request: Request,
    key_header: Optional[str] = Security(api_key_header),
    key_query: Optional[str] = Security(api_key_query)
):
    """Multi-vector API key authentication."""
    if key_header and key_header == API_KEY:
        return key_header

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token == API_KEY:
            return token

    if key_query and key_query == API_KEY:
        return key_query

    cookie_key = request.cookies.get("squid_panel_key")
    if cookie_key and cookie_key == API_KEY:
        return cookie_key

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key. Provide via 'X-API-Key' header or query parameter.",
        headers={"WWW-Authenticate": "Bearer"}
    )

# ------------------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------------------
class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, description="Proxy username")
    password: Optional[str] = Field(None, min_length=1, max_length=128, description="Proxy password")
    notes: Optional[str] = Field("", description="User notes or client ID")
    outgoing_ip: Optional[str] = Field(None, description="Optional fixed single outbound IP override")
    ip_access_mode: Optional[str] = Field("all", description="Access mode: 'all' | 'custom_list' | 'range' | 'single'")
    assigned_ips: Optional[List[str]] = Field(default_factory=list, description="Assigned multi-IP pool")
    ip_range_or_cidr: Optional[str] = Field(None, description="Assigned IP range or CIDR pool (e.g. 192.168.1.5 - 192.168.1.10)")

    @field_validator("username")
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_\.\-]+$", v):
            raise ValueError("Username must be alphanumeric and may contain . _ -")
        return v


class ChangePasswordRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128, description="New proxy password")


class AssignOutgoingIpRequest(BaseModel):
    username: str = Field(..., description="Proxy username")
    outgoing_ip: Optional[str] = Field(None, description="Dedicated outgoing IP address (or empty to reset to default)")


class AssignIpPortRequest(BaseModel):
    ip: str = Field(..., description="Outgoing IPv4 address")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Inbound listening port (e.g. 3129, or null to remove)")


class ChangeProxyPortRequest(BaseModel):
    port: int = Field(..., ge=1, le=65535, description="New Primary Squid Proxy listening port (1-65535)")


class CreateIpRequest(BaseModel):
    ip: str = Field(..., description="IPv4/IPv6 address or CIDR notation (e.g. 192.168.1.50 or 10.0.0.0/24)")
    label: Optional[str] = Field("", description="Description or Device Name")

    @field_validator("ip")
    def validate_ip_format(cls, v):
        try:
            return normalize_ip_or_cidr(v)
        except ValueError as e:
            raise ValueError(str(e))


class AddSecondaryIpRequest(BaseModel):
    interface: str = Field(..., description="Network interface name (e.g. eth0, ens3)")
    ip: str = Field(..., description="IPv4 address to bind (e.g. 198.51.100.15)")
    cidr: Optional[int] = Field(32, ge=1, le=32, description="Subnet CIDR prefix (default: 32 for single host)")
    label: Optional[str] = Field("", description="Label / Description")
    persistent: Optional[bool] = Field(True, description="Make persistent via NetworkManager nmcli")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Optional inbound proxy port (e.g. 3129)")


class BatchAddSecondaryIpsRequest(BaseModel):
    interface: str = Field(..., description="Network interface name (e.g. eth0)")
    mode: Optional[str] = Field("cidr", description="Mode: 'cidr', 'range', or 'list'")
    cidr_block: Optional[str] = Field(None, description="CIDR block (e.g. 192.168.1.0/29)")
    start_ip: Optional[str] = Field(None, description="Range start IP")
    end_ip: Optional[str] = Field(None, description="Range end IP")
    ip_list: Optional[List[str]] = Field(None, description="Explicit list of IPs")
    raw_text: Optional[str] = Field(None, description="Raw block text (CIDR, range, or list)")
    label_prefix: Optional[str] = Field("Pool IP", description="Label prefix for metadata")
    persistent: Optional[bool] = Field(True, description="Make persistent via NetworkManager nmcli")
    start_port: Optional[int] = Field(None, ge=1, le=65535, description="Inbound port or starting port")
    port_mode: Optional[str] = Field("sequential", description="Port assignment mode: 'sequential' | 'same' | 'none'")


class PreviewIpPoolRequest(BaseModel):
    mode: Optional[str] = Field("cidr", description="Mode: 'cidr', 'range', or 'list'")
    cidr_block: Optional[str] = Field(None, description="CIDR block (e.g. 192.168.1.0/29)")
    start_ip: Optional[str] = Field(None, description="Range start IP")
    end_ip: Optional[str] = Field(None, description="Range end IP")
    ip_list: Optional[List[str]] = Field(None, description="Explicit list of IPs")
    raw_text: Optional[str] = Field(None, description="Raw block text")
    start_port: Optional[int] = Field(None, ge=1, le=65535, description="Starting port or same port for preview")
    port_mode: Optional[str] = Field("sequential", description="Port mode: 'sequential' | 'same' | 'none'")


class DeleteSecondaryIpRequest(BaseModel):
    interface: str = Field(..., description="Network interface name")
    ip: str = Field(..., description="IPv4 address to unbind")
    cidr: Optional[int] = Field(32, ge=1, le=32, description="Subnet CIDR prefix")

# ------------------------------------------------------------------------------
# REST API Endpoints
# ------------------------------------------------------------------------------
@app.get("/api/v1/status")
async def get_system_status(_: str = Depends(verify_auth)):
    """Return live proxy health, network interfaces, dedicated ports, and configuration stats."""
    squid_info = is_squid_running()
    users = get_all_proxy_users()
    ips = get_all_allowed_ips()
    interfaces = get_network_interfaces()
    public_ip = get_server_public_ip()
    routing = load_routing_metadata()
    ports_meta = load_ports_metadata()
    
    cpu_pct = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    total_interface_ips = sum(len(iface["ipv4_addresses"]) for iface in interfaces)
    
    return {
        "status": "online",
        "squid": {
            "is_running": squid_info["running"],
            "process_count": squid_info["process_count"],
            "details": squid_info["processes"]
        },
        "network": {
            "public_ip": public_ip,
            "proxy_port": PROXY_PORT,
            "panel_port": PANEL_PORT,
            "total_interfaces": len(interfaces),
            "total_bound_ips": total_interface_ips,
            "dedicated_ports_count": len(ports_meta)
        },
        "stats": {
            "total_users": len(users),
            "total_whitelisted_ips": len(ips),
            "users_with_dedicated_ip": len(routing)
        },
        "system": {
            "cpu_percent": cpu_pct,
            "ram_used_mb": round(mem.used / (1024 * 1024), 1),
            "ram_total_mb": round(mem.total / (1024 * 1024), 1),
            "ram_percent": mem.percent,
            "disk_percent": disk.percent
        },
        "timestamp": time.time()
    }


# --- Primary Proxy Port Configuration ---
@app.post("/api/v1/config/port")
async def change_proxy_port_endpoint(payload: ChangeProxyPortRequest, _: str = Depends(verify_auth)):
    """Change the primary Squid listening port dynamically."""
    try:
        update_squid_port(payload.port)
        return {
            "success": True,
            "message": f"Primary Squid listening port successfully changed to :{payload.port}",
            "proxy_port": payload.port
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Dedicated Port to Outgoing IP Mappings ---
@app.get("/api/v1/network/ports")
async def list_ip_ports_endpoint(_: str = Depends(verify_auth)):
    """List all Inbound Port -> Outbound IP mappings."""
    return {"ports": load_ports_metadata()}


@app.post("/api/v1/network/ports")
async def assign_ip_port_endpoint(payload: AssignIpPortRequest, _: str = Depends(verify_auth)):
    """Assign or reset a listening port for an outgoing IP."""
    try:
        assign_ip_port(payload.ip, payload.port)
        msg = f"Inbound port :{payload.port} mapped to exit through outgoing IP {payload.ip}." if payload.port else f"Port unmapped for IP {payload.ip}."
        return {"success": True, "message": msg, "ip": payload.ip, "port": payload.port}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/network/ports/{ip_val:path}")
async def delete_ip_port_endpoint(ip_val: str, _: str = Depends(verify_auth)):
    """Remove port mapping for an outgoing IP."""
    try:
        assign_ip_port(ip_val, None)
        return {"success": True, "message": f"Port mapping removed for IP {ip_val}."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- User Management Endpoints ---
@app.get("/api/v1/users")
async def list_users(_: str = Depends(verify_auth)):
    """List all registered proxy users and their assigned outgoing IPs."""
    return {"users": get_all_proxy_users()}


@app.post("/api/v1/users")
async def create_or_update_user(payload: CreateUserRequest, _: str = Depends(verify_auth)):
    """Create or update a proxy user with bcrypt htpasswd hashing and enforced multi-IP pool support."""
    try:
        # If creating new user, password is required
        users = get_all_proxy_users()
        user_exists = any(u["username"] == payload.username for u in users)
        if not user_exists and (not payload.password or not payload.password.strip()):
            raise ValueError("Password is required for new proxy users.")

        add_or_update_proxy_user(
            username=payload.username,
            password=payload.password,
            notes=payload.notes or "",
            outgoing_ip=payload.outgoing_ip,
            ip_access_mode=payload.ip_access_mode or "all",
            assigned_ips=payload.assigned_ips or [],
            ip_range_or_cidr=payload.ip_range_or_cidr
        )
        return {
            "success": True,
            "message": f"Proxy user '{payload.username}' saved successfully.",
            "username": payload.username,
            "ip_access_mode": payload.ip_access_mode or "all",
            "assigned_ips": payload.assigned_ips or []
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/users/{username}/password")
async def change_user_password(username: str, payload: ChangePasswordRequest, _: str = Depends(verify_auth)):
    """Change or reset password for an existing proxy user."""
    users = get_all_proxy_users()
    user_exists = any(u["username"] == username for u in users)
    if not user_exists:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")

    meta = load_users_metadata()
    existing_meta = meta.get(username, {})
    notes = existing_meta.get("notes", "")
    ip_mode = existing_meta.get("ip_access_mode", "all")
    assigned_ips = existing_meta.get("assigned_ips", [])
    ip_range_or_cidr = existing_meta.get("ip_range_or_cidr", "")
    routing = load_routing_metadata()
    outgoing_ip = routing.get(username)

    add_or_update_proxy_user(
        username=username,
        password=payload.password,
        notes=notes,
        outgoing_ip=outgoing_ip,
        ip_access_mode=ip_mode,
        assigned_ips=assigned_ips,
        ip_range_or_cidr=ip_range_or_cidr
    )
    return {
        "success": True,
        "message": f"Password for proxy user '{username}' changed successfully.",
        "username": username
    }


@app.delete("/api/v1/users/{username}")
async def delete_user(username: str, _: str = Depends(verify_auth)):
    """Delete a proxy user from htpasswd and remove any dedicated IP routing."""
    deleted = delete_proxy_user(username)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"User '{username}' not found.")
    return {"success": True, "message": f"User '{username}' deleted successfully."}


# --- Dedicated Outgoing IP Routing Endpoints ---
@app.get("/api/v1/routing/assignments")
async def list_routing_assignments(_: str = Depends(verify_auth)):
    """List all user-to-outgoing-IP bindings (tcp_outgoing_address)."""
    return {"assignments": load_routing_metadata()}


@app.post("/api/v1/routing/assign")
async def assign_outgoing_ip_endpoint(payload: AssignOutgoingIpRequest, _: str = Depends(verify_auth)):
    """Assign or reset a dedicated outbound IP address for a specific proxy user."""
    try:
        assign_user_outgoing_ip(payload.username, payload.outgoing_ip)
        msg = f"User '{payload.username}' bound to outgoing IP {payload.outgoing_ip}." if payload.outgoing_ip else f"User '{payload.username}' reset to default outbound route."
        return {"success": True, "message": msg}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Network Interfaces & Secondary IPs Endpoints (nmcli / iproute2) ---
@app.get("/api/v1/network/interfaces")
async def list_interfaces_endpoint(_: str = Depends(verify_auth)):
    """Scan and list all network interfaces, bound IP addresses, and assigned proxy ports."""
    return {"interfaces": get_network_interfaces()}


@app.post("/api/v1/network/ips/preview")
async def preview_ip_pool_endpoint(payload: PreviewIpPoolRequest, _: str = Depends(verify_auth)):
    """Preview expanded IP addresses and sequential or same ports for a subnet, range, or list with strict memory bounds."""
    try:
        raw = (payload.raw_text or payload.cidr_block or "").strip()
        if raw and len(raw) < 7 and not payload.ip_list:
            return {"success": True, "total_ips": 0, "ips": [], "is_truncated": False}

        ips = expand_ip_pool(
            mode=payload.mode or "cidr",
            cidr_block=payload.cidr_block,
            start_ip=payload.start_ip,
            end_ip=payload.end_ip,
            ip_list=payload.ip_list,
            raw_text=payload.raw_text,
            max_limit=1024
        )
        total_count = len(ips)
        preview_sample = ips[:128]
        preview_list = []
        cur_port = payload.start_port
        port_mode = payload.port_mode or "sequential"

        for ip in preview_sample:
            if port_mode == "sequential":
                assigned_p = cur_port
            elif port_mode == "same":
                assigned_p = payload.start_port
            else:
                assigned_p = None

            preview_list.append({
                "ip": ip,
                "port": assigned_p
            })
            if port_mode == "sequential" and cur_port:
                cur_port += 1

        return {
            "success": True,
            "total_ips": total_count,
            "is_truncated": total_count > 128,
            "ips": preview_list
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/network/ips/batch")
async def batch_add_secondary_ips_endpoint(payload: BatchAddSecondaryIpsRequest, _: str = Depends(verify_auth)):
    """Batch add multiple secondary IPs via CIDR block (/29, /30), IP Range, or list with sequential or same port mapping."""
    try:
        ips = expand_ip_pool(
            mode=payload.mode or "cidr",
            cidr_block=payload.cidr_block,
            start_ip=payload.start_ip,
            end_ip=payload.end_ip,
            ip_list=payload.ip_list,
            raw_text=payload.raw_text
        )

        res = add_secondary_ip_batch(
            interface=payload.interface,
            ip_list=ips,
            cidr=32,
            label_prefix=payload.label_prefix or "Pool IP",
            persistent=payload.persistent if payload.persistent is not None else True,
            start_port=payload.start_port,
            port_mode=payload.port_mode or "sequential"
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/network/ips")
async def add_secondary_ip_endpoint(payload: AddSecondaryIpRequest, _: str = Depends(verify_auth)):
    """Add a single secondary IP to an interface dynamically with optional proxy port."""
    try:
        res = add_secondary_ip(
            interface=payload.interface,
            ip_str=payload.ip,
            cidr=payload.cidr or 32,
            label=payload.label or "",
            persistent=payload.persistent if payload.persistent is not None else True,
            port=payload.port
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/network/ips")
async def remove_secondary_ip_endpoint(payload: DeleteSecondaryIpRequest, _: str = Depends(verify_auth)):
    """Remove a secondary IP from an interface via nmcli / iproute2."""
    try:
        res = remove_secondary_ip(
            interface=payload.interface,
            ip_str=payload.ip,
            cidr=payload.cidr or 32
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- IP Whitelist Endpoints ---
@app.get("/api/v1/ips")
async def list_ips(_: str = Depends(verify_auth)):
    """List all whitelisted client IP addresses and CIDR subnets."""
    return {"ips": get_all_allowed_ips()}


@app.post("/api/v1/ips")
async def create_ip(payload: CreateIpRequest, _: str = Depends(verify_auth)):
    """Add an IP/CIDR to allowed_ips.txt and reload Squid."""
    try:
        add_allowed_ip(payload.ip, payload.label or "")
        return {
            "success": True,
            "message": f"IP/Subnet '{payload.ip}' added to whitelist and Squid reconfigured.",
            "ip": payload.ip
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/ips/{ip_val:path}")
async def delete_ip(ip_val: str, _: str = Depends(verify_auth)):
    """Remove an IP/CIDR from allowed_ips.txt and reload Squid."""
    deleted = delete_allowed_ip(ip_val)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"IP '{ip_val}' not found in whitelist.")
    return {"success": True, "message": f"IP '{ip_val}' removed and Squid reconfigured."}


# --- Service Management ---
@app.post("/api/v1/proxy/reload")
async def trigger_squid_reload(_: str = Depends(verify_auth)):
    """Trigger dynamic re-parse of Squid configuration."""
    res = reload_squid_service()
    return {"success": True, "result": res}


@app.post("/api/v1/proxy/restart")
async def trigger_squid_restart(_: str = Depends(verify_auth)):
    """Restart Squid service completely."""
    res = restart_squid_service()
    return {"success": res["success"], "result": res}


@app.post("/api/v1/proxy/start")
async def trigger_squid_start(_: str = Depends(verify_auth)):
    """Start Squid service if stopped and ensure systemd enabled."""
    res = start_squid_service()
    return {"success": res.get("success", False), "result": res}


@app.get("/api/v1/connection-strings")
async def get_connection_strings(
    username: Optional[str] = None,
    password: Optional[str] = None,
    host_override: Optional[str] = None,
    port_override: Optional[int] = None,
    _: str = Depends(verify_auth)
):
    """Generate instant connection strings and code snippets."""
    pub_ip = host_override if host_override else get_server_public_ip()
    port = port_override if port_override else PROXY_PORT
    routing = load_routing_metadata()
    ports_meta = load_ports_metadata()
    
    assigned_outgoing = routing.get(username, "") if username else ""
    if not assigned_outgoing:
        if host_override:
            assigned_outgoing = host_override
        elif port_override:
            for ip, p in ports_meta.items():
                if p == port_override:
                    assigned_outgoing = ip
                    break

    if username and password:
        proxy_url = f"http://{username}:{password}@{pub_ip}:{port}"
        auth_header_example = f"curl -x {proxy_url} https://httpbin.org/ip"
    else:
        proxy_url = f"http://{pub_ip}:{port}"
        auth_header_example = f"curl -x {proxy_url} https://httpbin.org/ip"

    snippets = {
        "proxy_url": proxy_url,
        "host": pub_ip,
        "port": port,
        "assigned_outgoing_ip": assigned_outgoing or pub_ip or "Default Gateway IP",
        "curl": auth_header_example,
        "curl_verbose": f"curl -v -x {proxy_url} https://httpbin.org/headers",
        "python_requests": f"""import requests

proxies = {{
    "http": "{proxy_url}",
    "https": "{proxy_url}",
}}

# Connecting to {pub_ip}:{port} -> Outbound Exit Public IP: {assigned_outgoing or pub_ip}
response = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
print("Remote Seen IP:", response.json())""",
        "python_httpx": f"""import httpx

proxies = "{proxy_url}"
with httpx.Client(proxy=proxies) as client:
    response = client.get("https://httpbin.org/ip")
    print("Remote Seen IP:", response.json())""",
        "node_axios": f"""const axios = require('axios');
const {{ HttpsProxyAgent }} = require('https-proxy-agent');

const agent = new HttpsProxyAgent('{proxy_url}');

axios.get('https://httpbin.org/ip', {{ httpsAgent: agent }})
  .then(res => console.log('Remote Seen IP:', res.data))
  .catch(err => console.error(err));""",
        "golang": f"""package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func main() {{
	proxyUrl, _ := url.Parse("{proxy_url}")
	client := &http.Client{{
		Transport: &http.Transport{{Proxy: http.ProxyURL(proxyUrl)}},
	}}

	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {{
		panic(err)
	}}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}}""",
        "linux_export": f"""export http_proxy="{proxy_url}"\nexport https_proxy="{proxy_url}"\nexport HTTP_PROXY="{proxy_url}"\nexport HTTPS_PROXY="{proxy_url}" """,
        "powershell_export": f"""$env:http_proxy="{proxy_url}"\n$env:https_proxy="{proxy_url}" """
    }
    return snippets

# ------------------------------------------------------------------------------
# Embedded Single-Page Application (SPA) Web Dashboard
# ------------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SquidMan | Multi-Port & Multi-IP Gateway</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            sans: ['"Plus Jakarta Sans"', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'monospace'],
          },
          colors: {
            brand: {
              50: '#ecfdf5',
              100: '#d1fae5',
              400: '#34d399',
              500: '#10b981',
              600: '#059669',
              700: '#047857',
            },
            dark: {
              950: '#090d16',
              900: '#0d1322',
              850: '#11182c',
              800: '#172038',
              700: '#1f2b4c',
              600: '#2d3c66'
            }
          }
        }
      }
    }
  </script>
  <style>
    body {
      background-color: #080c14;
      color: #e2e8f0;
      background-image: 
        radial-gradient(at 0% 0%, rgba(16, 185, 129, 0.07) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(99, 102, 241, 0.06) 0px, transparent 50%);
      background-attachment: fixed;
    }
    .glass-panel {
      background: rgba(13, 19, 34, 0.85);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }
    .glass-card {
      background: rgba(17, 24, 44, 0.65);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .pulse-green {
      box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
      animation: pulse-green 2s infinite cubic-bezier(0.66, 0, 0, 1);
    }
    @keyframes pulse-green {
      to {
        box-shadow: 0 0 0 10px rgba(16, 185, 129, 0);
      }
    }
    .mode-card {
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      cursor: pointer;
    }
    .mode-card:hover {
      border-color: rgba(16, 185, 129, 0.4);
      background: rgba(23, 32, 56, 0.6);
    }
    .mode-card.active {
      border-color: #10b981;
      background: rgba(16, 185, 129, 0.08);
      box-shadow: 0 0 20px -5px rgba(16, 185, 129, 0.2);
    }
    .ip-chip-card {
      transition: all 0.15s ease-in-out;
      cursor: pointer;
    }
    .ip-chip-card.selected {
      border-color: rgba(139, 92, 246, 0.6);
      background: rgba(139, 92, 246, 0.12);
    }
    button:disabled, select:disabled, input:disabled {
      opacity: 0.6 !important;
      cursor: not-allowed !important;
      pointer-events: none !important;
    }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #090d16; }
    ::-webkit-scrollbar-thumb { background: #24304d; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #33436b; }
  </style>
</head>
<body class="min-h-screen font-sans antialiased flex flex-col selection:bg-brand-500 selection:text-black">

  <!-- Toast Notification Container -->
  <div id="toastContainer" class="fixed top-5 right-5 z-50 flex flex-col gap-2 pointer-events-none"></div>

  <!-- Auth Key Modal -->
  <div id="authModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md hidden">
    <div class="glass-panel w-full max-w-md p-8 rounded-2xl shadow-2xl border border-white/10 text-center">
      <div class="w-16 h-16 bg-brand-500/10 border border-brand-500/30 rounded-2xl flex items-center justify-center mx-auto mb-5 text-brand-400 text-2xl shadow-lg shadow-brand-500/10">
        <i class="fa-solid fa-shield-halved"></i>
      </div>
      <h2 class="text-2xl font-bold text-white tracking-tight mb-2">SquidMan Panel</h2>
      <p class="text-sm text-slate-400 mb-6">Enter administrative <span class="font-mono text-emerald-400">API Key</span> to manage proxy users, IP pools, and ACLs.</p>
      
      <div class="space-y-4">
        <div class="relative">
          <input type="password" id="authKeyInput" placeholder="Enter API Key (X-API-Key)" 
                 class="w-full px-4 py-3 bg-dark-900/90 border border-slate-700/80 rounded-xl text-white font-mono placeholder:text-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 text-center transition-all">
          <button onclick="togglePasswordVisibility('authKeyInput')" class="absolute right-3 top-3.5 text-slate-400 hover:text-white">
            <i class="fa-regular fa-eye"></i>
          </button>
        </div>
        
        <button id="authSubmitBtn" onclick="submitAuthKey()" 
                class="w-full py-3.5 px-4 bg-gradient-to-r from-brand-600 to-emerald-500 hover:from-brand-500 hover:to-emerald-400 text-black font-bold rounded-xl shadow-lg shadow-brand-500/25 transition-all transform active:scale-98 flex items-center justify-center gap-2">
          <i class="fa-solid fa-unlock-keyhole"></i>
          <span>Authenticate & Access Dashboard</span>
        </button>
      </div>
    </div>
  </div>

  <!-- Main Navigation Bar -->
  <header class="sticky top-0 z-40 border-b border-white/5 bg-dark-950/80 backdrop-blur-xl">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-brand-500/20 to-emerald-600/10 border border-brand-500/30 flex items-center justify-center text-brand-400 font-bold shadow-md shadow-brand-500/10">
          <i class="fa-solid fa-server text-lg"></i>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <span class="font-extrabold text-white tracking-tight text-lg">Squid<span class="text-brand-400">Man</span></span>
            <span class="px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase bg-brand-500/10 text-brand-400 border border-brand-500/20 rounded-full">Multi-Port & IP Pool</span>
          </div>
          <p class="text-xs text-slate-400 font-mono hidden sm:block">Proxy Gateway Manager </p>
        </div>
      </div>

      <div class="flex items-center gap-3">
        <button onclick="startOrRestartSquid()" id="squidStatusBadge" title="Click to start/restart Squid" class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-dark-900 border border-slate-700/60 text-xs transition-all hover:border-brand-500/40 cursor-pointer active:scale-95">
          <span id="squidStatusDot" class="w-2.5 h-2.5 rounded-full bg-slate-500"></span>
          <span id="squidStatusText" class="font-medium text-slate-300">Checking...</span>
        </button>

        <button onclick="copyPublicIp()" title="Click to copy server IP" 
                class="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-dark-900/90 border border-white/10 hover:border-brand-500/40 text-xs font-mono text-slate-300 hover:text-white transition-all group">
          <i class="fa-solid fa-globe text-brand-400"></i>
          <span id="headerPublicIp">0.0.0.0</span>
          <span class="text-slate-500 group-hover:text-brand-400 transition-colors"><i class="fa-regular fa-copy"></i></span>
        </button>

        <button onclick="triggerReload()" title="Reload Squid Configuration" 
                class="p-2.5 rounded-xl bg-dark-900 border border-slate-700/60 text-slate-300 hover:text-brand-400 hover:border-brand-500/30 transition-all active:scale-95">
          <i class="fa-solid fa-rotate"></i>
        </button>

        <button onclick="changeApiKey()" title="Change API Key" 
                class="p-2.5 rounded-xl bg-dark-900 border border-slate-700/60 text-slate-300 hover:text-amber-400 hover:border-amber-500/30 transition-all active:scale-95">
          <i class="fa-solid fa-key"></i>
        </button>
      </div>
    </div>
  </header>

  <!-- Main Content Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
    
    <!-- Top Statistics Overview -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
      
      <!-- Card 1: Proxy Engine & Primary Port Config -->
      <div class="glass-card p-5 rounded-2xl relative overflow-hidden group hover:border-brand-500/30 transition-all">
        <div class="flex items-center justify-between mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Primary Engine & Port</span>
          <button onclick="openChangePortModal()" title="Change Primary Proxy Listening Port" class="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500 hover:text-black flex items-center justify-center transition-all">
            <i class="fa-solid fa-gear"></i>
          </button>
        </div>
        <div class="flex items-baseline gap-2 cursor-pointer group/state" onclick="startOrRestartSquid()" title="Click to start/restart Squid">
          <span id="statSquidState" class="text-2xl font-bold text-white tracking-tight group-hover/state:underline">Active</span>
          <span id="statSquidUptime" class="text-xs text-slate-400 font-mono">--</span>
        </div>
        <div class="flex items-center justify-between mt-2 pt-2 border-t border-white/5">
          <span class="text-xs text-slate-400">Primary Port:</span>
          <button onclick="openChangePortModal()" class="font-mono text-emerald-300 font-bold text-xs hover:underline flex items-center gap-1">
            <span id="statProxyPort">:3128</span>
            <i class="fa-solid fa-pen text-[10px] text-slate-500"></i>
          </button>
        </div>
      </div>

      <!-- Card 2: Users & IP Mappings -->
      <div class="glass-card p-5 rounded-2xl relative overflow-hidden group hover:border-brand-500/30 transition-all">
        <div class="flex items-center justify-between mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Proxy Users</span>
          <div class="w-8 h-8 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
            <i class="fa-solid fa-users"></i>
          </div>
        </div>
        <div class="flex items-baseline justify-between">
          <span id="statTotalUsers" class="text-2xl font-bold text-white tracking-tight">0</span>
          <button onclick="openAddUserModal()" class="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
            <i class="fa-solid fa-plus"></i> Add User
          </button>
        </div>
        <p class="text-xs text-slate-400 mt-2"><span id="statDedicatedUsers" class="text-cyan-300 font-mono font-semibold">0</span> with dedicated Outbound IPs</p>
      </div>

      <!-- Card 3: Network Interfaces & Dedicated Ports -->
      <div class="glass-card p-5 rounded-2xl relative overflow-hidden group hover:border-brand-500/30 transition-all">
        <div class="flex items-center justify-between mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Network IPs & Ports</span>
          <div class="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center">
            <i class="fa-solid fa-network-wired"></i>
          </div>
        </div>
        <div class="flex items-baseline justify-between">
          <span id="statTotalBoundIps" class="text-2xl font-bold text-white tracking-tight">0</span>
          <div class="flex gap-2">
            <button onclick="openBatchAddIpModal()" class="text-xs font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1">
              <i class="fa-solid fa-layer-group"></i> +Pool
            </button>
          </div>
        </div>
        <p class="text-xs text-slate-400 mt-2"><span id="statDedicatedPorts" class="text-indigo-300 font-mono font-semibold">0</span> dedicated IP-port routes active</p>
      </div>

      <!-- Card 4: System Load -->
      <div class="glass-card p-5 rounded-2xl relative overflow-hidden group hover:border-brand-500/30 transition-all">
        <div class="flex items-center justify-between mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Host Resources</span>
          <div class="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center">
            <i class="fa-solid fa-microchip"></i>
          </div>
        </div>
        <div class="space-y-2">
          <div class="flex justify-between text-xs font-mono">
            <span class="text-slate-400">CPU: <span id="statCpuPct" class="text-slate-200">0%</span></span>
            <span class="text-slate-400">RAM: <span id="statRamPct" class="text-slate-200">0%</span></span>
          </div>
          <div class="w-full bg-dark-900 rounded-full h-1.5 overflow-hidden flex">
            <div id="statCpuBar" class="bg-amber-400 h-full transition-all duration-500" style="width: 10%"></div>
            <div id="statRamBar" class="bg-brand-500 h-full transition-all duration-500" style="width: 25%"></div>
          </div>
        </div>
        <p class="text-[11px] text-slate-500 mt-2 font-mono" id="statRamDetail">Memory: -- / -- MB</p>
      </div>

    </div>

    <!-- Navigation Tabs -->
    <div class="flex flex-wrap gap-2 border-b border-white/5 pb-3">
      <button onclick="switchTab('users')" id="tabBtn-users" 
              class="tab-button px-4 py-2.5 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 bg-brand-500 text-black shadow-lg shadow-brand-500/20">
        <i class="fa-solid fa-user-lock"></i>
        <span>Proxy Users (htpasswd)</span>
      </button>
      <button onclick="switchTab('interfaces')" id="tabBtn-interfaces" 
              class="tab-button px-4 py-2.5 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 bg-dark-900 text-slate-300 hover:text-white border border-transparent hover:border-white/10">
        <i class="fa-solid fa-ethernet"></i>
        <span>Network Interfaces & Port-IP Pool</span>
      </button>
      <button onclick="switchTab('ips')" id="tabBtn-ips" 
              class="tab-button px-4 py-2.5 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 bg-dark-900 text-slate-300 hover:text-white border border-transparent hover:border-white/10">
        <i class="fa-solid fa-shield-halved"></i>
        <span>Client Whitelisting (ACL)</span>
      </button>
      <button onclick="switchTab('generator')" id="tabBtn-generator" 
              class="tab-button px-4 py-2.5 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 bg-dark-900 text-slate-300 hover:text-white border border-transparent hover:border-white/10">
        <i class="fa-solid fa-code"></i>
        <span>Code Generator & Connect</span>
      </button>
    </div>

    <!-- ========================================================================= -->
    <!-- TAB 1: USERS MANAGEMENT & MULTI-IP ROUTING -->
    <!-- ========================================================================= -->
    <section id="tab-users" class="tab-content space-y-4">
      <div class="glass-panel p-6 rounded-2xl shadow-xl">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-users text-brand-400"></i>
              <span>Proxy Users & Multi-IP Routing</span>
            </h3>
            <p class="text-xs text-slate-400 mt-1">Manage htpasswd credentials. Click on any assigned IP pool to inspect authorized IPs. Use <span class="text-brand-400 font-semibold">Edit</span> to change pool settings.</p>
          </div>
          <div class="flex items-center gap-3">
            <button onclick="openAddUserModal()" 
                    class="px-4 py-2.5 bg-brand-500 hover:bg-brand-400 text-black font-bold text-sm rounded-xl shadow-lg shadow-brand-500/20 transition-all flex items-center gap-2 active:scale-95">
              <i class="fa-solid fa-user-plus"></i>
              <span>Create Proxy User</span>
            </button>
          </div>
        </div>

        <!-- Users Table -->
        <div class="overflow-x-auto rounded-xl border border-white/5">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-dark-950/80 text-xs uppercase font-semibold text-slate-400 font-mono">
              <tr>
                <th class="px-5 py-3.5">Username</th>
                <th class="px-5 py-3.5">Assigned IP Pool & Routing (Click to View)</th>
                <th class="px-5 py-3.5">Notes / Client ID</th>
                <th class="px-5 py-3.5">Created Date</th>
                <th class="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="usersTableBody" class="divide-y divide-white/5 bg-dark-900/40">
              <tr>
                <td colspan="5" class="px-5 py-8 text-center text-slate-500">
                  <i class="fa-solid fa-circle-notch fa-spin text-lg mb-2"></i>
                  <p>Loading proxy users...</p>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ========================================================================= -->
    <!-- TAB 2: NETWORK INTERFACES & BATCH IP POOL MANAGER (nmcli + myip + myport) -->
    <!-- ========================================================================= -->
    <section id="tab-interfaces" class="tab-content space-y-6 hidden">
      <div class="glass-panel p-6 rounded-2xl shadow-xl">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-ethernet text-indigo-400"></i>
              <span>Network Interfaces, IP Pools & Port Mappings</span>
            </h3>
            <p class="text-xs text-slate-400 mt-1">Bind multiple IPs via subnets (/29, /30) or ranges in 1-click. Every inbound IP automatically uses itself as outbound address (<code class="font-mono text-indigo-400">myip</code>), or via dedicated sequential/shared ports (<code class="font-mono text-indigo-400">myport</code>).</p>
          </div>
        </div>

        <!-- Interfaces Cards / Container -->
        <div id="interfacesContainer" class="space-y-4">
          <div class="p-8 text-center text-slate-500">
            <i class="fa-solid fa-circle-notch fa-spin text-2xl mb-2"></i>
            <p>Scanning network interfaces...</p>
          </div>
        </div>
      </div>
    </section>

    <!-- ========================================================================= -->
    <!-- TAB 3: IP WHITELIST MANAGEMENT -->
    <!-- ========================================================================= -->
    <section id="tab-ips" class="tab-content space-y-4 hidden">
      <div class="glass-panel p-6 rounded-2xl shadow-xl">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-shield-halved text-violet-400"></i>
              <span>Source IP Whitelisting (No Auth Bypass)</span>
            </h3>
            <p class="text-xs text-slate-400 mt-1">Client requests originating from these IP addresses bypass credentials via <code class="font-mono text-violet-400">/etc/squid/allowed_ips.txt</code>.</p>
          </div>
          <div class="flex items-center gap-3">
            <button onclick="openAddIpModal()" 
                    class="px-4 py-2.5 bg-violet-600 hover:bg-violet-500 text-white font-bold text-sm rounded-xl shadow-lg shadow-violet-600/25 transition-all flex items-center gap-2 active:scale-95">
              <i class="fa-solid fa-plus"></i>
              <span>Whitelist New IP / Subnet</span>
            </button>
          </div>
        </div>

        <!-- IP Table -->
        <div class="overflow-x-auto rounded-xl border border-white/5">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-dark-950/80 text-xs uppercase font-semibold text-slate-400 font-mono">
              <tr>
                <th class="px-5 py-3.5">IP Address / CIDR</th>
                <th class="px-5 py-3.5">Type</th>
                <th class="px-5 py-3.5">Device / Client Label</th>
                <th class="px-5 py-3.5">Added Date</th>
                <th class="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="ipsTableBody" class="divide-y divide-white/5 bg-dark-900/40">
              <tr>
                <td colspan="5" class="px-5 py-8 text-center text-slate-500">
                  <i class="fa-solid fa-circle-notch fa-spin text-lg mb-2"></i>
                  <p>Loading whitelisted IPs...</p>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ========================================================================= -->
    <!-- TAB 4: CODE & CONNECTION GENERATOR -->
    <!-- ========================================================================= -->
    <section id="tab-generator" class="tab-content space-y-6 hidden">
      <div class="glass-panel p-6 rounded-2xl shadow-xl">
        <div class="mb-6">
          <h3 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-code text-cyan-400"></i>
            <span>Connection String & Code Generator</span>
          </h3>
          <p class="text-xs text-slate-400 mt-1">Generate plug-and-play proxy configuration for any programming language, scraper, or dedicated IP port.</p>
        </div>

        <!-- Options Selector -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6 bg-dark-900/70 p-4 rounded-xl border border-white/5">
          <div>
            <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Authentication Mode</label>
            <select id="genAuthMode" onchange="updateGeneratedSnippets()" class="w-full bg-dark-950 border border-slate-700/80 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-brand-500">
              <option value="user">Username & Password Auth</option>
              <option value="ip">IP Whitelist Auth (No Credentials)</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Inbound IP / Port Route</label>
            <select id="genPortSelect" onchange="updateGeneratedSnippets()" class="w-full bg-dark-950 border border-slate-700/80 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-brand-500">
              <option value="">Default Server Host & Port (:3128)</option>
            </select>
          </div>
          <div id="genUserSelectWrapper">
            <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Select User</label>
            <select id="genUserSelect" onchange="onUserSelectionChanged()" class="w-full bg-dark-950 border border-slate-700/80 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-brand-500">
              <option value="">(Custom / Enter Manually)</option>
            </select>
          </div>
        </div>

        <!-- Language Code Tabs -->
        <div class="space-y-4">
          <div class="flex flex-wrap gap-2 border-b border-white/10 pb-2">
            <button onclick="showCodeTab('curl')" id="codeTab-curl" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">cURL</button>
            <button onclick="showCodeTab('python')" id="codeTab-python" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-dark-900 text-slate-400 hover:text-white">Python (Requests)</button>
            <button onclick="showCodeTab('httpx')" id="codeTab-httpx" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-dark-900 text-slate-400 hover:text-white">Python (HTTPX / Async)</button>
            <button onclick="showCodeTab('node')" id="codeTab-node" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-dark-900 text-slate-400 hover:text-white">Node.js (Axios)</button>
            <button onclick="showCodeTab('golang')" id="codeTab-golang" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-dark-900 text-slate-400 hover:text-white">Go (Golang)</button>
            <button onclick="showCodeTab('env')" id="codeTab-env" class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-dark-900 text-slate-400 hover:text-white">CLI / Environment Variables</button>
          </div>

          <!-- Code Box -->
          <div class="relative group">
            <button onclick="copyCurrentCodeSnippet()" 
                    class="absolute right-3 top-3 px-3 py-1.5 bg-dark-800/90 hover:bg-brand-500 hover:text-black border border-white/10 rounded-lg text-xs font-mono text-slate-300 transition-all flex items-center gap-1.5 shadow-md">
              <i class="fa-regular fa-copy"></i>
              <span>Copy Code</span>
            </button>
            <pre class="bg-dark-950 p-5 rounded-xl border border-white/5 overflow-x-auto text-xs font-mono text-emerald-400 leading-relaxed max-h-96" id="codeSnippetBox">// Select an option above to generate snippet...</pre>
          </div>
        </div>
      </div>
    </section>

  </main>

  <!-- ========================================================================= -->
  <!-- MODAL: VIEW ASSIGNED IP POOL (Inspect Only) -->
  <!-- ========================================================================= -->
  <div id="viewUserIpsModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md hidden">
    <div class="glass-panel w-full max-w-2xl p-7 rounded-3xl shadow-2xl border border-white/15 max-h-[90vh] overflow-y-auto">
      <div class="flex items-center justify-between mb-5">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-violet-500/20 text-violet-400 flex items-center justify-center font-bold text-lg border border-violet-500/30">
            <i class="fa-solid fa-list-check"></i>
          </div>
          <div>
            <h3 id="viewUserIpsTitle" class="text-xl font-bold text-white">Assigned IP Pool</h3>
            <p class="text-xs text-slate-400 font-mono" id="viewUserIpsSubtitle">User Allowed IPs & Exit Routes</p>
          </div>
        </div>
        <button onclick="closeViewUserIpsModal()" class="text-slate-400 hover:text-white text-2xl">&times;</button>
      </div>

      <div class="space-y-4">
        <!-- Summary Bar & Search -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-dark-900/90 p-4 rounded-2xl border border-white/5">
          <div>
            <span class="text-xs text-slate-400 block">Access Strategy</span>
            <span id="viewUserIpsModeBadge" class="text-xs font-bold text-white font-mono">--</span>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="copyViewUserIpsList('ips')" class="px-3 py-1.5 rounded-xl bg-dark-950 border border-slate-700 hover:border-violet-500 text-xs font-semibold text-slate-300 hover:text-white transition-all flex items-center gap-1.5">
              <i class="fa-regular fa-copy"></i>
              <span>Copy IPs</span>
            </button>
            <button onclick="copyViewUserIpsList('endpoints')" class="px-3 py-1.5 rounded-xl bg-violet-600/30 hover:bg-violet-600 border border-violet-500/40 text-xs font-bold text-violet-300 hover:text-white transition-all flex items-center gap-1.5">
              <i class="fa-solid fa-network-wired"></i>
              <span>Copy IP:Port List</span>
            </button>
          </div>
        </div>

        <!-- Filter Input -->
        <div class="relative">
          <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-3 text-xs text-slate-500"></i>
          <input type="text" id="viewUserIpsFilter" oninput="filterViewUserIpsTable()" placeholder="Search assigned IPs..." 
                 class="w-full pl-9 pr-3.5 py-2 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-violet-500">
        </div>

        <!-- Assigned IPs Table -->
        <div class="bg-dark-950 rounded-xl border border-white/5 max-h-60 overflow-y-auto">
          <table class="w-full text-left text-xs font-mono text-slate-300">
            <thead class="bg-dark-900 uppercase text-slate-500 text-[11px] sticky top-0">
              <tr>
                <th class="py-2 px-3">#</th>
                <th class="py-2 px-3">Allowed Inbound IP</th>
                <th class="py-2 px-3">Listening Port</th>
                <th class="py-2 px-3">Outbound Exit IP</th>
                <th class="py-2 px-3 text-right">Access Status</th>
              </tr>
            </thead>
            <tbody id="viewUserIpsTableBody" class="divide-y divide-white/5">
              <tr>
                <td colspan="5" class="py-6 text-center text-slate-500">Loading assigned IPs...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Actions -->
        <div class="flex gap-3 pt-2">
          <button type="button" onclick="closeViewUserIpsModal()" class="w-1/2 py-2.5 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Close</button>
          <button type="button" id="viewUserEditBtn" class="w-1/2 py-2.5 bg-brand-500 hover:bg-brand-400 text-black font-bold rounded-xl text-sm transition-all shadow-lg shadow-brand-500/20 flex items-center justify-center gap-1.5">
            <i class="fa-solid fa-pen-to-square"></i>
            <span>Edit User Pool Settings</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODAL: BATCH ADD IP POOL / SUBNET / RANGE (1-Click) -->
  <!-- ========================================================================= -->
  <div id="batchAddIpModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md hidden">
    <div class="glass-panel w-full max-w-2xl p-7 rounded-3xl shadow-2xl border border-white/15 max-h-[90vh] overflow-y-auto">
      <div class="flex items-center justify-between mb-5">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-lg border border-indigo-500/30">
            <i class="fa-solid fa-layer-group"></i>
          </div>
          <div>
            <h3 class="text-xl font-bold text-white">Batch Add IP Pool & Port Mapping</h3>
            <p class="text-xs text-slate-400 font-mono">Expand CIDR (/29, /30) or Range &bull; Sequential or Shared Ports</p>
          </div>
        </div>
        <button onclick="closeBatchAddIpModal()" class="text-slate-400 hover:text-white text-2xl">&times;</button>
      </div>

      <div class="space-y-5">
        <!-- Target Interface -->
        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Target Network Interface</label>
          <select id="modalBatchIfaceSelect" class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-indigo-500">
          </select>
        </div>

        <!-- Mode Selector -->
        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">IP Pool Input Format</label>
          <div class="grid grid-cols-3 gap-2">
            <button type="button" onclick="setBatchMode('cidr')" id="batchModeBtn-cidr" class="py-2 px-3 text-xs font-bold rounded-xl border border-indigo-500 bg-indigo-500/20 text-indigo-300">
              CIDR Subnet (/29, /30)
            </button>
            <button type="button" onclick="setBatchMode('range')" id="batchModeBtn-range" class="py-2 px-3 text-xs font-bold rounded-xl border border-slate-700 bg-dark-900 text-slate-400 hover:text-white">
              IP Range (Start - End)
            </button>
            <button type="button" onclick="setBatchMode('list')" id="batchModeBtn-list" class="py-2 px-3 text-xs font-bold rounded-xl border border-slate-700 bg-dark-900 text-slate-400 hover:text-white">
              List (Comma / Newline)
            </button>
          </div>
        </div>

        <!-- Input Box -->
        <div>
          <div class="flex items-center justify-between mb-1.5">
            <label id="batchInputLabel" class="text-xs font-semibold uppercase tracking-wider text-slate-400">CIDR Subnet Block</label>
            <span id="batchPreviewCount" class="text-xs font-mono text-emerald-400 font-bold">0 IPs detected</span>
          </div>
          <textarea id="batchInputText" oninput="debouncePreviewBatchIps()" rows="3" placeholder="e.g. 192.168.1.0/29 (expands 6 usable host IPs)" 
                    class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-indigo-500 leading-relaxed"></textarea>
        </div>

        <!-- Port Assignment Configuration (Sequential vs Same Port) -->
        <div class="bg-dark-900/90 p-4 rounded-2xl border border-white/5 space-y-3">
          <label class="block text-xs font-bold text-white uppercase tracking-wider">Inbound Port Assignment Strategy</label>
          
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <!-- Mode 1: Sequential -->
            <label class="flex items-center gap-2 p-2.5 rounded-xl border border-slate-700 bg-dark-950 cursor-pointer hover:border-indigo-500 transition-all" id="batchPortModeLabel-seq">
              <input type="radio" name="batchPortMode" value="sequential" checked onchange="onBatchPortModeChanged()" class="text-indigo-600 bg-dark-900 border-slate-700 focus:ring-indigo-500">
              <div>
                <span class="text-xs font-bold text-white block">Sequential Ports</span>
                <span class="text-[10px] text-slate-400 block">:3129, :3130, :3131...</span>
              </div>
            </label>

            <!-- Mode 2: Same Port for all -->
            <label class="flex items-center gap-2 p-2.5 rounded-xl border border-slate-700 bg-dark-950 cursor-pointer hover:border-indigo-500 transition-all" id="batchPortModeLabel-same">
              <input type="radio" name="batchPortMode" value="same" onchange="onBatchPortModeChanged()" class="text-indigo-600 bg-dark-900 border-slate-700 focus:ring-indigo-500">
              <div>
                <span class="text-xs font-bold text-white block">Same Port for All</span>
                <span class="text-[10px] text-slate-400 block">:3129 for all pool IPs</span>
              </div>
            </label>

            <!-- Mode 3: None -->
            <label class="flex items-center gap-2 p-2.5 rounded-xl border border-slate-700 bg-dark-950 cursor-pointer hover:border-indigo-500 transition-all" id="batchPortModeLabel-none">
              <input type="radio" name="batchPortMode" value="none" onchange="onBatchPortModeChanged()" class="text-indigo-600 bg-dark-900 border-slate-700 focus:ring-indigo-500">
              <div>
                <span class="text-xs font-bold text-white block">Default Port Only</span>
                <span class="text-[10px] text-slate-400 block">Primary :3128 port</span>
              </div>
            </label>
          </div>
          
          <div id="batchPortInputWrapper" class="grid grid-cols-2 gap-3 pt-2">
            <div>
              <label id="batchPortLabel" class="block text-[11px] font-semibold text-slate-400 mb-1">Starting Inbound Port</label>
              <input type="number" id="batchStartPort" oninput="debouncePreviewBatchIps()" value="3129" min="1" max="65500" 
                     class="w-full px-3 py-2 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-indigo-500">
            </div>
            <div>
              <label class="block text-[11px] font-semibold text-slate-400 mb-1">Label Prefix</label>
              <input type="text" id="batchLabelPrefix" value="Pool IP" placeholder="e.g. Residential Pool" 
                     class="w-full px-3 py-2 bg-dark-950 border border-slate-700/80 rounded-xl text-white text-xs focus:outline-none focus:border-indigo-500">
            </div>
          </div>
        </div>

        <!-- Live Expansion Preview Box -->
        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Live Pool Expansion & Port Binding Preview</label>
          <div class="bg-dark-950 rounded-xl border border-white/5 max-h-44 overflow-y-auto p-3">
            <table class="w-full text-left text-xs font-mono text-slate-300">
              <thead class="text-[11px] uppercase text-slate-500 border-b border-white/5 pb-1">
                <tr>
                  <th class="py-1 px-2">#</th>
                  <th class="py-1 px-2">IP Address</th>
                  <th class="py-1 px-2">Inbound Listening Port</th>
                  <th class="py-1 px-2">Outgoing Exit IP</th>
                </tr>
              </thead>
              <tbody id="batchPreviewTableBody" class="divide-y divide-white/5">
                <tr>
                  <td colspan="4" class="py-4 text-center text-slate-500">Enter a subnet or range above to preview expanded IPs.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex gap-3 pt-2">
          <button type="button" id="batchCancelBtn" onclick="closeBatchAddIpModal()" class="w-1/3 py-3 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Cancel</button>
          <button type="button" id="batchSubmitBtn" onclick="submitBatchAddIps()" 
                  class="w-2/3 py-3 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white font-bold rounded-xl text-sm transition-all shadow-lg shadow-indigo-600/25 flex items-center justify-center gap-2">
            <i class="fa-solid fa-bolt"></i>
            <span>Bind All Pool IPs & Ports</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODAL: ADD / EDIT PROXY USER (User-Friendly Multi-IP & Pool Setup) -->
  <!-- ========================================================================= -->
  <div id="userModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md hidden">
    <div class="glass-panel w-full max-w-2xl p-7 rounded-3xl shadow-2xl border border-white/15 max-h-[92vh] overflow-y-auto">
      <div class="flex items-center justify-between mb-5">
        <div class="flex items-center gap-3">
          <div id="userModalIcon" class="w-10 h-10 rounded-xl bg-brand-500/20 text-brand-400 flex items-center justify-center font-bold text-lg border border-brand-500/30">
            <i class="fa-solid fa-user-gear"></i>
          </div>
          <div>
            <h3 id="userModalTitle" class="text-xl font-bold text-white">Create Proxy User</h3>
            <p class="text-xs text-slate-400 font-mono">Configure credentials and allowed outgoing IP pool</p>
          </div>
        </div>
        <button onclick="closeUserModal()" class="text-slate-400 hover:text-white text-2xl">&times;</button>
      </div>

      <div class="space-y-4">
        <!-- Credentials Box -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Username</label>
            <input type="text" id="modalUsername" placeholder="e.g. crawler_bot_01" 
                   class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-brand-500">
          </div>

          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="text-xs font-semibold uppercase tracking-wider text-slate-400">Password</label>
              <button onclick="generateRandomPassword()" class="text-xs text-brand-400 hover:underline flex items-center gap-1 font-mono">
                <i class="fa-solid fa-dice"></i> Generate Strong
              </button>
            </div>
            <input type="text" id="modalPassword" placeholder="Enter or generate password" 
                   class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-brand-500">
            <p id="modalPasswordHelp" class="text-[11px] text-slate-500 mt-1 hidden">Leave blank to keep existing password, or enter new password.</p>
          </div>
        </div>

        <!-- IP Access Mode & Pool Settings (User-Friendly Cards) -->
        <div class="bg-dark-900/90 p-5 rounded-2xl border border-white/5 space-y-4">
          <div class="flex items-center justify-between">
            <label class="block text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <i class="fa-solid fa-network-wired text-brand-400"></i>
              <span>IP Pool Access & Routing Mode</span>
            </label>
            <span class="text-xs font-mono text-slate-400" id="userModalSelectedSummary">All Server IPs</span>
          </div>
          
          <!-- 4 Visual Selection Mode Cards -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <!-- Mode 1: All Server IPs -->
            <div onclick="selectUserIpModeCard('all')" id="modeCard-all" class="mode-card p-3.5 rounded-2xl border border-slate-700/80 bg-dark-950 active">
              <div class="flex items-center justify-between mb-1.5">
                <div class="flex items-center gap-2">
                  <i class="fa-solid fa-globe text-emerald-400 text-sm"></i>
                  <span class="text-xs font-bold text-white">All Server IPs</span>
                </div>
                <span class="px-1.5 py-0.5 text-[9px] font-extrabold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded">Recommended</span>
              </div>
              <p class="text-[11px] text-slate-400 leading-snug">Access ANY server IP/port with automatic dynamic self-outgoing match.</p>
            </div>

            <!-- Mode 2: Multi-Select Checkbox Pool -->
            <div onclick="selectUserIpModeCard('custom_list')" id="modeCard-custom_list" class="mode-card p-3.5 rounded-2xl border border-slate-700/80 bg-dark-950">
              <div class="flex items-center justify-between mb-1.5">
                <div class="flex items-center gap-2">
                  <i class="fa-solid fa-list-check text-violet-400 text-sm"></i>
                  <span class="text-xs font-bold text-white">Specific IP Selection</span>
                </div>
                <span class="px-1.5 py-0.5 text-[9px] font-bold uppercase bg-violet-500/20 text-violet-300 border border-violet-500/30 rounded" id="userIpSelectionCountBadge">0 Chosen</span>
              </div>
              <p class="text-[11px] text-slate-400 leading-snug">Select specific bound server IPs to create a dedicated pool.</p>
            </div>

            <!-- Mode 3: Subnet / Range Pool -->
            <div onclick="selectUserIpModeCard('range')" id="modeCard-range" class="mode-card p-3.5 rounded-2xl border border-slate-700/80 bg-dark-950">
              <div class="flex items-center justify-between mb-1.5">
                <div class="flex items-center gap-2">
                  <i class="fa-solid fa-layer-group text-amber-400 text-sm"></i>
                  <span class="text-xs font-bold text-white">Subnet / Range Pool</span>
                </div>
                <span class="px-1.5 py-0.5 text-[9px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded">CIDR / Range</span>
              </div>
              <p class="text-[11px] text-slate-400 leading-snug">Define pool by CIDR (/29, /30) or IP range with auto-expansion.</p>
            </div>

            <!-- Mode 4: Dedicated Single Fixed IP -->
            <div onclick="selectUserIpModeCard('single')" id="modeCard-single" class="mode-card p-3.5 rounded-2xl border border-slate-700/80 bg-dark-950">
              <div class="flex items-center justify-between mb-1.5">
                <div class="flex items-center gap-2">
                  <i class="fa-solid fa-lock text-cyan-400 text-sm"></i>
                  <span class="text-xs font-bold text-white">Dedicated Single IP</span>
                </div>
                <span class="px-1.5 py-0.5 text-[9px] font-bold uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded">Fixed Route</span>
              </div>
              <p class="text-[11px] text-slate-400 leading-snug">Lock user to strictly exit through one specific public IP.</p>
            </div>
          </div>

          <!-- Hidden Radio for Form State -->
          <input type="hidden" id="modalUserIpModeHidden" value="all">

          <!-- Container for Custom List Selection (Searchable & Filterable) -->
          <div id="userCustomListWrapper" class="hidden pt-3 border-t border-white/5 space-y-3">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div class="relative flex-1">
                <i class="fa-solid fa-magnifying-glass absolute left-3 top-2.5 text-xs text-slate-500"></i>
                <input type="text" id="userIpSearchInput" oninput="filterUserIpCheckboxes()" placeholder="Filter IPs by address, port, or interface..." 
                       class="w-full pl-8 pr-3 py-1.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-violet-500">
              </div>
              <div class="flex items-center gap-2">
                <button type="button" onclick="selectAllUserIps(true)" class="px-2.5 py-1 text-xs font-semibold bg-violet-500/20 hover:bg-violet-500 hover:text-black text-violet-300 border border-violet-500/30 rounded-lg transition-all">Select All</button>
                <button type="button" onclick="selectAllUserIps(false)" class="px-2.5 py-1 text-xs font-semibold bg-dark-950 hover:bg-dark-850 text-slate-400 hover:text-white border border-slate-700 rounded-lg transition-all">Deselect All</button>
              </div>
            </div>

            <div id="userIpCheckboxesContainer" class="max-h-48 overflow-y-auto space-y-1.5 p-2 bg-dark-950 rounded-xl border border-white/5">
              <!-- Rendered dynamically -->
            </div>
          </div>

          <!-- Container for Custom Range / CIDR with Presets & Live Preview -->
          <div id="userRangeWrapper" class="hidden pt-3 border-t border-white/5 space-y-3">
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-xs font-semibold text-slate-300">Enter Pool CIDR Subnet or IP Range</label>
                <span id="userRangePreviewBadge" class="text-xs font-mono text-emerald-400 font-bold">0 IPs detected</span>
              </div>
              <input type="text" id="modalUserRangeText" oninput="debounceUserRangePreview()" placeholder="e.g. 192.168.1.5 - 192.168.1.12 or 192.168.1.0/29" 
                     class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-amber-500">
            </div>

            <!-- Quick Subnet Helper Buttons -->
            <div class="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
              <span class="text-[11px]">Quick Helpers:</span>
              <button type="button" onclick="setSubnetHelper('/29')" class="px-2 py-0.5 rounded-md bg-dark-950 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[11px] font-mono">+ /29 (6 IPs)</button>
              <button type="button" onclick="setSubnetHelper('/30')" class="px-2 py-0.5 rounded-md bg-dark-950 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[11px] font-mono">+ /30 (2 IPs)</button>
              <button type="button" onclick="setSubnetHelper('/28')" class="px-2 py-0.5 rounded-md bg-dark-950 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[11px] font-mono">+ /28 (14 IPs)</button>
            </div>

            <div id="userRangeLivePreviewBox" class="text-[11px] font-mono text-slate-400 p-2.5 bg-dark-950 rounded-xl border border-white/5 max-h-24 overflow-y-auto leading-relaxed">
              Enter a subnet (e.g. 192.168.1.0/29) or range (192.168.1.5 - 192.168.1.10) to preview expanded IPs.
            </div>
          </div>

          <!-- Container for Single Fixed IP -->
          <div id="userSingleIpWrapper" class="hidden pt-3 border-t border-white/5 space-y-2">
            <label class="block text-xs font-semibold text-slate-300">Select Fixed Outgoing Public IP</label>
            <select id="modalUserSingleIpSelect" class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-500">
            </select>
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Notes / Description (Optional)</label>
          <input type="text" id="modalUserNotes" placeholder="e.g. Scraper Team UK" 
                 class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white text-sm focus:outline-none focus:border-brand-500">
        </div>

        <div class="flex gap-3 pt-2">
          <button type="button" id="userModalCancelBtn" onclick="closeUserModal()" class="w-1/3 py-3 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Cancel</button>
          <button type="button" id="userModalSubmitBtn" onclick="submitUserForm()" class="w-2/3 py-3 bg-brand-500 hover:bg-brand-400 text-black font-bold rounded-xl text-sm transition-all shadow-lg shadow-brand-500/20 flex items-center justify-center gap-2">
            <i class="fa-solid fa-floppy-disk"></i>
            <span>Save User & IP Access</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODAL: CHANGE USER PASSWORD -->
  <!-- ========================================================================= -->
  <div id="changeUserPasswordModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="glass-panel w-full max-w-md p-6 rounded-2xl shadow-2xl border border-white/10">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-key text-amber-400"></i>
          <span>Change User Password</span>
        </h3>
        <button onclick="closeChangePasswordModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
      </div>

      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Target Username</label>
          <input type="text" id="modalChangePassUsername" readonly 
                 class="w-full px-3.5 py-2.5 bg-dark-900 border border-slate-700/50 rounded-xl text-amber-300 font-mono text-sm cursor-not-allowed font-bold">
        </div>

        <div>
          <div class="flex items-center justify-between mb-1">
            <label class="text-xs font-semibold uppercase tracking-wider text-slate-400">New Password</label>
            <button onclick="generateRandomPasswordForChange()" class="text-xs text-amber-400 hover:underline flex items-center gap-1 font-mono">
              <i class="fa-solid fa-dice"></i> Generate Strong
            </button>
          </div>
          <div class="relative">
            <input type="text" id="modalChangePassInput" placeholder="Enter or generate new password" 
                   class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-amber-500">
          </div>
          <p class="text-[11px] text-slate-500 mt-1">Updates <code class="text-amber-400">users.pwd</code> with a new bcrypt hash.</p>
        </div>

        <div class="flex gap-3 pt-2">
          <button type="button" id="changePassCancelBtn" onclick="closeChangePasswordModal()" class="w-1/2 py-2.5 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Cancel</button>
          <button type="button" id="changePassSubmitBtn" onclick="submitChangeUserPassword()" class="w-1/2 py-2.5 bg-amber-500 hover:bg-amber-400 text-black font-bold rounded-xl text-sm transition-all shadow-lg shadow-amber-500/20 flex items-center justify-center gap-2">
            <i class="fa-solid fa-key"></i>
            <span>Update Password</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODAL: CHANGE PRIMARY PROXY PORT -->
  <!-- ========================================================================= -->
  <div id="changePortModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="glass-panel w-full max-w-sm p-6 rounded-2xl shadow-2xl border border-white/10">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-gear text-emerald-400"></i>
          <span>Change Primary Port</span>
        </h3>
        <button onclick="closeChangePortModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
      </div>

      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Primary Listening Port</label>
          <input type="number" id="modalProxyPortInput" min="1" max="65535" placeholder="e.g. 3128, 8080, 1080" 
                 class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-brand-500">
          <p class="text-[11px] text-slate-500 mt-1">Updates primary <code class="text-emerald-400">http_port</code> and restarts Squid service.</p>
        </div>

        <div class="flex gap-3 pt-2">
          <button type="button" id="changePortCancelBtn" onclick="closeChangePortModal()" class="w-1/2 py-2.5 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Cancel</button>
          <button type="button" id="changePortSubmitBtn" onclick="submitChangeProxyPort()" class="w-1/2 py-2.5 bg-brand-500 hover:bg-brand-400 text-black font-bold rounded-xl text-sm transition-all shadow-lg shadow-brand-500/20 flex items-center justify-center gap-2">
            <i class="fa-solid fa-rotate"></i>
            <span>Apply & Restart</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODAL: ASSIGN PORT TO OUTGOING IP -->
  <!-- ========================================================================= -->
  <div id="assignIpPortModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="glass-panel w-full max-w-sm p-6 rounded-2xl shadow-2xl border border-white/10">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-network-wired text-indigo-400"></i>
          <span>Dedicated Port for IP</span>
        </h3>
        <button onclick="closeAssignIpPortModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
      </div>

      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Outgoing IP Address</label>
          <input type="text" id="modalAssignIpTarget" readonly 
                 class="w-full px-3.5 py-2.5 bg-dark-900 border border-slate-700/50 rounded-xl text-indigo-300 font-mono text-sm cursor-not-allowed">
        </div>

        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Inbound Listening Port</label>
          <input type="number" id="modalAssignPortInput" min="1" max="65535" placeholder="e.g. 3129, 3130 (leave blank to unbind)" 
                 class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-indigo-500">
          <p class="text-[11px] text-slate-500 mt-1">Requests connecting on this port will exit Squid through this specific outgoing IP automatically.</p>
        </div>

        <div class="flex gap-3 pt-2">
          <button type="button" id="assignPortCancelBtn" onclick="closeAssignIpPortModal()" class="w-1/2 py-2.5 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Cancel</button>
          <button type="button" id="assignPortSubmitBtn" onclick="submitAssignIpPort()" class="w-1/2 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl text-sm transition-all shadow-lg shadow-indigo-600/20 flex items-center justify-center gap-2">
            <i class="fa-solid fa-floppy-disk"></i>
            <span>Save Mapping</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODAL: ADD SINGLE SECONDARY IP -->
  <!-- ========================================================================= -->
  <div id="addSecondaryIpModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="glass-panel w-full max-w-md p-6 rounded-2xl shadow-2xl border border-white/10">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-plus text-indigo-400"></i>
          <span>Add Single Secondary IP</span>
        </h3>
        <button onclick="closeAddSecondaryIpModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
      </div>

      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Target Network Interface</label>
          <select id="modalSecIfaceSelect" class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-indigo-500">
          </select>
        </div>

        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Secondary IPv4 Address</label>
          <input type="text" id="modalSecIp" placeholder="e.g. 198.51.100.15" 
                 class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-indigo-500">
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Inbound Port (Optional)</label>
            <input type="number" id="modalSecPort" min="1" max="65535" placeholder="e.g. 3129" 
                   class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">CIDR Prefix</label>
            <input type="number" id="modalSecCidr" value="32" min="1" max="32" 
                   class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-indigo-500">
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Label / Alias Note (Optional)</label>
          <input type="text" id="modalSecLabel" placeholder="e.g. Dedicated Public IP #2" 
                 class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white text-sm focus:outline-none focus:border-indigo-500">
        </div>

        <div class="flex gap-3 pt-2">
          <button type="button" id="modalSecCancelBtn" onclick="closeAddSecondaryIpModal()" class="w-1/2 py-2.5 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Cancel</button>
          <button type="button" id="modalSecSubmitBtn" onclick="submitAddSecondaryIp()" class="w-1/2 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl text-sm transition-all shadow-lg shadow-indigo-600/20 flex items-center justify-center gap-2">
            <i class="fa-solid fa-plus"></i>
            <span>Bind IP & Port</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODAL: ADD CLIENT IP WHITELIST -->
  <!-- ========================================================================= -->
  <div id="addIpModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm hidden">
    <div class="glass-panel w-full max-w-md p-6 rounded-2xl shadow-2xl border border-white/10">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <i class="fa-solid fa-shield-halved text-violet-400"></i>
          <span>Whitelist Client IP / Subnet</span>
        </h3>
        <button onclick="closeAddIpModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
      </div>

      <div class="space-y-4">
        <div>
          <div class="flex items-center justify-between mb-1">
            <label class="text-xs font-semibold uppercase tracking-wider text-slate-400">Client IP Address or CIDR</label>
            <button type="button" id="detectIpBtn" onclick="detectMyIpForModal()" class="text-xs text-violet-400 hover:underline flex items-center gap-1 font-mono">
              <i class="fa-solid fa-crosshairs"></i> <span>Auto-Detect My IP</span>
            </button>
          </div>
          <input type="text" id="modalIpAddress" placeholder="e.g. 198.51.100.45 or 10.0.0.0/24" 
                 class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:outline-none focus:border-violet-500">
        </div>

        <div>
          <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Device Label / Notes (Optional)</label>
          <input type="text" id="modalIpLabel" placeholder="e.g. Office VPN Gateway" 
                 class="w-full px-3.5 py-2.5 bg-dark-950 border border-slate-700/80 rounded-xl text-white text-sm focus:outline-none focus:border-violet-500">
        </div>

        <div class="flex gap-3 pt-2">
          <button type="button" id="addIpCancelBtn" onclick="closeAddIpModal()" class="w-1/2 py-2.5 bg-dark-900 hover:bg-dark-800 text-slate-300 font-semibold rounded-xl text-sm transition-all">Cancel</button>
          <button type="button" id="addIpSubmitBtn" onclick="submitAddIp()" class="w-1/2 py-2.5 bg-violet-600 hover:bg-violet-500 text-white font-bold rounded-xl text-sm transition-all shadow-lg shadow-violet-600/20 flex items-center justify-center gap-2">
            <i class="fa-solid fa-shield-halved"></i>
            <span>Whitelist IP</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <footer class="border-t border-white/5 py-6 mt-auto">
    <div class="max-w-7xl mx-auto px-4 text-center text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
      <p>SquidMan &bull; Crafted with ❤️ by <a target="_blank" rel="noopener noreferrer" href="https://github.com/magicrana">MagicRana</a></p>
      <p class="font-mono text-slate-400">Multi IP &bull; Zero-Leakage</p>
    </div>
  </footer>

  <!-- ========================================================================= -->
  <!-- DASHBOARD JAVASCRIPT LOGIC -->
  <!-- ========================================================================= -->
  <script>
    let currentApiKey = localStorage.getItem('squid_api_key') || '';
    let currentStatus = null;
    let cachedUsers = [];
    let cachedIps = [];
    let cachedInterfaces = [];
    let cachedPorts = {};
    let currentSnippets = {};
    let activeCodeTab = 'curl';
    let currentBatchMode = 'cidr';
    let previewDebounceTimer = null;
    let userRangeDebounceTimer = null;
    let isEditingUser = false;
    let currentViewingUserIpsData = [];

    document.addEventListener('DOMContentLoaded', () => {
      const urlParams = new URLSearchParams(window.location.search);
      const queryKey = urlParams.get('api_key');
      if (queryKey) {
        currentApiKey = queryKey;
        localStorage.setItem('squid_api_key', queryKey);
        window.history.replaceState({}, document.title, window.location.pathname);
      }

      if (!currentApiKey) {
        document.getElementById('authModal').classList.remove('hidden');
      } else {
        initDashboard();
      }
    });

    async function submitAuthKey() {
      const input = document.getElementById('authKeyInput').value.trim();
      if (!input) {
        showToast('Please enter an API Key', 'error');
        return;
      }
      const btn = document.getElementById('authSubmitBtn');
      const origHtml = btn ? btn.innerHTML : '';
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>Authenticating...</span>';
      }
      try {
        currentApiKey = input;
        localStorage.setItem('squid_api_key', input);
        document.cookie = `squid_panel_key=${input}; path=/; max-age=2592000; SameSite=Strict`;
        document.getElementById('authModal').classList.add('hidden');
        await initDashboard();
      } catch (e) {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = origHtml;
        }
      }
    }

    function changeApiKey() {
      localStorage.removeItem('squid_api_key');
      document.getElementById('authKeyInput').value = '';
      document.getElementById('authModal').classList.remove('hidden');
    }

    async function apiRequest(endpoint, options = {}) {
      const headers = {
        'X-API-Key': currentApiKey,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      };

      try {
        const resp = await fetch(endpoint, { ...options, headers });
        if (resp.status === 401) {
          showToast('Invalid API Key', 'error');
          changeApiKey();
          throw new Error('Unauthorized');
        }
        return await resp.json();
      } catch (err) {
        console.error('API Error:', err);
        throw err;
      }
    }

    async function initDashboard() {
      await refreshAllData();
      setInterval(refreshStatus, 10000);
    }

    async function refreshAllData() {
      await Promise.all([
        refreshStatus(),
        loadUsers(),
        loadPorts(),
        loadInterfaces(),
        loadIps(),
        updateGeneratedSnippets()
      ]);
    }

    async function refreshStatus() {
      try {
        const data = await apiRequest('/api/v1/status');
        currentStatus = data;

        document.getElementById('headerPublicIp').textContent = data.network.public_ip;
        
        const isRunning = data.squid.is_running;
        const statusDot = document.getElementById('squidStatusDot');
        const statusText = document.getElementById('squidStatusText');
        const statState = document.getElementById('statSquidState');
        const statUptime = document.getElementById('statSquidUptime');

        if (isRunning) {
          statusDot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-400 pulse-green';
          statusText.textContent = 'Squid Active';
          statusText.className = 'font-medium text-emerald-300';
          const badge = document.getElementById('squidStatusBadge');
          if (badge) {
            badge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-xs transition-all hover:border-emerald-500/60 hover:bg-emerald-500/20 cursor-pointer active:scale-95';
            badge.title = 'Squid is active. Click to restart.';
          }
          statState.textContent = 'Active';
          statState.className = 'text-2xl font-bold text-emerald-400 tracking-tight';
          const maxUptime = Math.max(...data.squid.details.map(p => p.uptime_seconds), 0);
          statUptime.textContent = formatUptime(maxUptime);
        } else {
          statusDot.className = 'w-2.5 h-2.5 rounded-full bg-rose-500';
          statusText.textContent = 'Squid Inactive (Click to Start)';
          statusText.className = 'font-medium text-rose-300 animate-pulse';
          const badge = document.getElementById('squidStatusBadge');
          if (badge) {
            badge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/50 text-xs transition-all hover:border-emerald-500/60 hover:bg-emerald-500/20 hover:text-emerald-300 cursor-pointer active:scale-95 shadow-lg shadow-rose-500/10';
            badge.title = 'Squid is stopped! Click to start Squid service.';
          }
          statState.textContent = 'Stopped';
          statState.className = 'text-2xl font-bold text-rose-400 tracking-tight';
          statUptime.textContent = 'Click to Start';
        }

        document.getElementById('statProxyPort').textContent = `:${data.network.proxy_port}`;
        document.getElementById('statTotalUsers').textContent = data.stats.total_users;
        document.getElementById('statDedicatedUsers').textContent = data.stats.users_with_dedicated_ip;
        document.getElementById('statTotalBoundIps').textContent = data.network.total_bound_ips;
        document.getElementById('statDedicatedPorts').textContent = data.network.dedicated_ports_count || 0;

        document.getElementById('statCpuPct').textContent = `${data.system.cpu_percent}%`;
        document.getElementById('statRamPct').textContent = `${data.system.ram_percent}%`;
        document.getElementById('statCpuBar').style.width = `${Math.min(data.system.cpu_percent, 100)}%`;
        document.getElementById('statRamBar').style.width = `${Math.min(data.system.ram_percent, 100)}%`;
        document.getElementById('statRamDetail').textContent = `Memory: ${data.system.ram_used_mb} / ${data.system.ram_total_mb} MB (${data.system.ram_percent}%)`;

      } catch (e) {
        console.error("Status load failed", e);
      }
    }

    function formatUptime(sec) {
      if (sec < 60) return `${sec}s uptime`;
      if (sec < 3600) return `${Math.floor(sec/60)}m uptime`;
      if (sec < 86400) return `${Math.floor(sec/3600)}h ${Math.floor((sec%3600)/60)}m`;
      return `${Math.floor(sec/86400)}d ${Math.floor((sec%86400)/3600)}h`;
    }

    async function startOrRestartSquid() {
      const isRunning = currentStatus && currentStatus.squid && currentStatus.squid.is_running;
      const statusText = document.getElementById('squidStatusText');
      const statusDot = document.getElementById('squidStatusDot');
      
      if (statusDot) statusDot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse';
      if (statusText) statusText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin text-xs mr-1"></i> ${isRunning ? 'Restarting...' : 'Starting Squid...'}`;
      showToast(isRunning ? 'Restarting Squid engine...' : 'Starting Squid engine...', 'info');

      try {
        const endpoint = isRunning ? '/api/v1/proxy/restart' : '/api/v1/proxy/start';
        const res = await apiRequest(endpoint, { method: 'POST' });
        if (res.success) {
          showToast(isRunning ? 'Squid engine restarted successfully!' : 'Squid engine started and verified active!', 'success');
        } else {
          showToast(res.message || 'Squid service command issued', 'info');
        }
      } catch (e) {
        showToast(e.message || 'Failed to start Squid service', 'error');
      } finally {
        await refreshStatus();
      }
    }

    // -------------------------------------------------------------------------
    // View Assigned IP Pool Modal (Inspector Only)
    // -------------------------------------------------------------------------
    function viewUserAssignedIps(username) {
      const user = cachedUsers.find(u => u.username === username);
      if (!user) return;

      const primaryPort = (currentStatus && currentStatus.network.proxy_port) || 3128;
      document.getElementById('viewUserIpsTitle').textContent = `Assigned IP Pool: ${username}`;
      
      const badge = document.getElementById('viewUserIpsModeBadge');
      const tbody = document.getElementById('viewUserIpsTableBody');
      const editBtn = document.getElementById('viewUserEditBtn');
      document.getElementById('viewUserIpsFilter').value = '';

      editBtn.onclick = () => {
        closeViewUserIpsModal();
        openEditUserModal(username);
      };

      currentViewingUserIpsData = [];

      if (user.outgoing_ip) {
        badge.innerHTML = '<span class="text-cyan-400">Fixed Outgoing IP Route</span>';
        const p = user.assigned_port || cachedPorts[user.outgoing_ip] || primaryPort;
        currentViewingUserIpsData.push({
          ip: user.outgoing_ip,
          port: p,
          exitIp: user.outgoing_ip
        });
      } else if (user.ip_access_mode === 'custom_list' || (user.assigned_ips && user.assigned_ips.length > 0)) {
        badge.innerHTML = `<span class="text-violet-400">Custom Multi-IP Pool (${user.assigned_ips.length} IPs)</span>`;
        user.assigned_ips.forEach(ip => {
          const p = cachedPorts[ip] || primaryPort;
          currentViewingUserIpsData.push({
            ip: ip,
            port: p,
            exitIp: ip
          });
        });
      } else if (user.ip_access_mode === 'range' && user.ip_range_or_cidr) {
        badge.innerHTML = `<span class="text-amber-400">Subnet / Range Pool (${user.assigned_ips ? user.assigned_ips.length : 0} IPs)</span>`;
        const ips = user.assigned_ips || [];
        ips.forEach(ip => {
          const p = cachedPorts[ip] || primaryPort;
          currentViewingUserIpsData.push({
            ip: ip,
            port: p,
            exitIp: ip
          });
        });
      } else {
        badge.innerHTML = '<span class="text-emerald-400">All Server IPs (Full Dynamic Pool)</span>';
        cachedInterfaces.forEach(iface => {
          iface.ipv4_addresses.forEach(addr => {
            const p = addr.assigned_port || cachedPorts[addr.ip] || primaryPort;
            currentViewingUserIpsData.push({
              ip: addr.ip,
              port: p,
              exitIp: addr.ip
            });
          });
        });
      }

      renderViewUserIpsTable(currentViewingUserIpsData);
      document.getElementById('viewUserIpsModal').classList.remove('hidden');
    }

    function closeViewUserIpsModal() {
      document.getElementById('viewUserIpsModal').classList.add('hidden');
    }

    function renderViewUserIpsTable(ipList) {
      const tbody = document.getElementById('viewUserIpsTableBody');
      if (ipList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-slate-500">No matching IP addresses in pool.</td></tr>';
        return;
      }

      tbody.innerHTML = ipList.map((item, idx) => `
        <tr class="hover:bg-dark-900/60 transition-colors">
          <td class="py-2.5 px-3 text-slate-500 font-bold">${idx + 1}</td>
          <td class="py-2.5 px-3 font-bold text-white">${escapeHtml(item.ip)}</td>
          <td class="py-2.5 px-3 text-indigo-300 font-bold">:${item.port}</td>
          <td class="py-2.5 px-3 text-emerald-400 font-bold flex items-center gap-1.5">
            <i class="fa-solid fa-arrow-right-from-bracket text-[10px]"></i>
            <span>${escapeHtml(item.exitIp)}</span>
          </td>
          <td class="py-2.5 px-3 text-right">
            <span class="px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold">
              <i class="fa-solid fa-check"></i> Authorized
            </span>
          </td>
        </tr>
      `).join('');
    }

    function filterViewUserIpsTable() {
      const query = document.getElementById('viewUserIpsFilter').value.trim().toLowerCase();
      const filtered = currentViewingUserIpsData.filter(item => {
        return item.ip.toLowerCase().includes(query) || String(item.port).includes(query);
      });
      renderViewUserIpsTable(filtered);
    }

    async function copyViewUserIpsList(mode) {
      if (!currentViewingUserIpsData || currentViewingUserIpsData.length === 0) return;
      const nl = String.fromCharCode(10);
      let text = '';
      if (mode === 'ips') {
        text = currentViewingUserIpsData.map(item => item.ip).join(nl);
      } else {
        text = currentViewingUserIpsData.map(item => `${item.ip}:${item.port}`).join(nl);
      }
      await copyToClipboard(text);
      showToast(`Copied ${currentViewingUserIpsData.length} IP records to clipboard!`, 'success');
    }

    // -------------------------------------------------------------------------
    // Batch IP Pool Modal & Live Preview
    // -------------------------------------------------------------------------
    function openBatchAddIpModal(selectedIface = '') {
      const select = document.getElementById('modalBatchIfaceSelect');
      select.innerHTML = cachedInterfaces.map(i => `<option value="${escapeHtml(i.name)}">${escapeHtml(i.name)} (${escapeHtml(i.connection_name)})</option>`).join('');
      if (selectedIface) select.value = selectedIface;

      setBatchMode('cidr');
      document.getElementById('batchInputText').value = '';
      document.querySelector('input[name="batchPortMode"][value="sequential"]').checked = true;
      document.getElementById('batchStartPort').value = '3129';
      onBatchPortModeChanged();
      document.getElementById('batchPreviewCount').textContent = '0 IPs detected';
      document.getElementById('batchPreviewTableBody').innerHTML = '<tr><td colspan="4" class="py-4 text-center text-slate-500">Enter a subnet or range above to preview expanded IPs.</td></tr>';
      
      const submitBtn = document.getElementById('batchSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> <span>Bind All Pool IPs & Ports</span>';
      }
      const cancelBtn = document.getElementById('batchCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;

      document.getElementById('batchAddIpModal').classList.remove('hidden');
    }

    function closeBatchAddIpModal() {
      document.getElementById('batchAddIpModal').classList.add('hidden');
    }

    function onBatchPortModeChanged() {
      const portMode = document.querySelector('input[name="batchPortMode"]:checked').value;
      const portWrapper = document.getElementById('batchPortInputWrapper');
      const portLabel = document.getElementById('batchPortLabel');

      if (portMode === 'none') {
        portWrapper.classList.add('opacity-40', 'pointer-events-none');
      } else {
        portWrapper.classList.remove('opacity-40', 'pointer-events-none');
        if (portMode === 'sequential') {
          portLabel.textContent = 'Starting Inbound Port';
        } else {
          portLabel.textContent = 'Shared Inbound Port';
        }
      }

      ['seq', 'same', 'none'].forEach(k => {
        const el = document.getElementById(`batchPortModeLabel-${k}`);
        if (el) {
          if ((k === 'seq' && portMode === 'sequential') || (k === portMode)) {
            el.className = 'flex items-center gap-2 p-2.5 rounded-xl border border-indigo-500 bg-indigo-500/15 cursor-pointer transition-all';
          } else {
            el.className = 'flex items-center gap-2 p-2.5 rounded-xl border border-slate-700 bg-dark-950 cursor-pointer hover:border-indigo-500 transition-all';
          }
        }
      });

      debouncePreviewBatchIps();
    }

    function setBatchMode(mode) {
      currentBatchMode = mode;
      ['cidr', 'range', 'list'].forEach(m => {
        const btn = document.getElementById(`batchModeBtn-${m}`);
        if (m === mode) {
          btn.className = 'py-2 px-3 text-xs font-bold rounded-xl border border-indigo-500 bg-indigo-500/20 text-indigo-300';
        } else {
          btn.className = 'py-2 px-3 text-xs font-bold rounded-xl border border-slate-700 bg-dark-900 text-slate-400 hover:text-white';
        }
      });

      const label = document.getElementById('batchInputLabel');
      const input = document.getElementById('batchInputText');
      if (mode === 'cidr') {
        label.textContent = 'CIDR Subnet Block (/29, /30, /24)';
        input.placeholder = 'e.g. 192.168.1.0/29 (expands 6 usable host IPs)';
      } else if (mode === 'range') {
        label.textContent = 'IP Range (Start - End)';
        input.placeholder = 'e.g. 192.168.1.5 - 192.168.1.20';
      } else {
        label.textContent = 'List of IPs (Comma or Newline Separated)';
        input.placeholder = 'e.g. 192.168.1.5, 192.168.1.6, 192.168.1.7';
      }

      debouncePreviewBatchIps();
    }

    function debouncePreviewBatchIps() {
      clearTimeout(previewDebounceTimer);
      previewDebounceTimer = setTimeout(previewBatchIps, 400);
    }

    async function previewBatchIps() {
      const rawText = document.getElementById('batchInputText').value.trim();
      const portMode = document.querySelector('input[name="batchPortMode"]:checked').value;
      const portInput = document.getElementById('batchStartPort').value.trim();
      const startPort = (portMode !== 'none' && portInput) ? parseInt(portInput, 10) : null;

      const countBadge = document.getElementById('batchPreviewCount');
      const tbody = document.getElementById('batchPreviewTableBody');

      if (!rawText) {
        countBadge.textContent = '0 IPs detected';
        tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-slate-500">Enter a subnet or range above to preview expanded IPs.</td></tr>';
        return;
      }

      if (rawText.length < 7 && !rawText.includes('/')) {
        countBadge.textContent = 'Typing...';
        return;
      }

      try {
        const res = await apiRequest('/api/v1/network/ips/preview', {
          method: 'POST',
          body: JSON.stringify({
            mode: currentBatchMode,
            raw_text: rawText,
            start_port: startPort,
            port_mode: portMode
          })
        });

        if (res.success && res.ips.length > 0) {
          countBadge.textContent = `${res.total_ips} IPs in Pool${res.is_truncated ? ' (showing first 128)' : ''}`;
          tbody.innerHTML = res.ips.map((item, idx) => `
            <tr class="hover:bg-dark-900/50">
              <td class="py-1.5 px-2 text-slate-500 font-bold">${idx + 1}</td>
              <td class="py-1.5 px-2 text-white font-bold">${escapeHtml(item.ip)}</td>
              <td class="py-1.5 px-2 text-indigo-300 font-bold">${item.port ? ':' + item.port + (portMode === 'same' ? ' <span class="text-[10px] text-slate-500">(Shared)</span>' : '') : '<span class="text-slate-600">Default (:3128)</span>'}</td>
              <td class="py-1.5 px-2 text-emerald-400 font-bold flex items-center gap-1">
                <i class="fa-solid fa-arrow-right-from-bracket text-[10px]"></i>
                <span>${escapeHtml(item.ip)}</span>
              </td>
            </tr>
          `).join('');
          if (res.is_truncated) {
            tbody.innerHTML += `<tr><td colspan="4" class="py-2 text-center text-slate-500 font-mono text-[11px] italic">... and ${res.total_ips - res.ips.length} more IPs in this subnet block</td></tr>`;
          }
        }
      } catch (e) {
        countBadge.textContent = 'Invalid format';
        tbody.innerHTML = `<tr><td colspan="4" class="py-4 text-center text-rose-400">${escapeHtml(e.message || 'Invalid format')}</td></tr>`;
      }
    }

    async function submitBatchAddIps() {
      const iface = document.getElementById('modalBatchIfaceSelect').value;
      const rawText = document.getElementById('batchInputText').value.trim();
      const portMode = document.querySelector('input[name="batchPortMode"]:checked').value;
      const portInput = document.getElementById('batchStartPort').value.trim();
      const startPort = (portMode !== 'none' && portInput) ? parseInt(portInput, 10) : null;
      const labelPrefix = document.getElementById('batchLabelPrefix').value.trim() || 'Pool IP';

      if (!rawText) {
        showToast('Please enter a subnet, range, or list of IPs', 'error');
        return;
      }

      const btn = document.getElementById('batchSubmitBtn');
      const cancelBtn = document.getElementById('batchCancelBtn');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>Binding IP Pool...</span>';
      }
      if (cancelBtn) cancelBtn.disabled = true;

      try {
        const res = await apiRequest('/api/v1/network/ips/batch', {
          method: 'POST',
          body: JSON.stringify({
            interface: iface,
            mode: currentBatchMode,
            raw_text: rawText,
            label_prefix: labelPrefix,
            persistent: true,
            start_port: startPort,
            port_mode: portMode
          })
        });

        showToast(res.message || `Successfully added ${res.total_added} IPs!`, 'success');
        closeBatchAddIpModal();
        await loadPorts();
        await loadInterfaces();
        await refreshStatus();
        await updateGeneratedSnippets();
      } catch (e) {
        showToast(e.message || 'Failed to batch add IPs', 'error');
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<i class="fa-solid fa-bolt"></i> <span>Bind All Pool IPs & Ports</span>';
        }
        if (cancelBtn) cancelBtn.disabled = false;
      }
    }

    // -------------------------------------------------------------------------
    // Primary Port Configuration Modal
    // -------------------------------------------------------------------------
    function openChangePortModal() {
      const currentPort = (currentStatus && currentStatus.network.proxy_port) || 3128;
      document.getElementById('modalProxyPortInput').value = currentPort;
      const submitBtn = document.getElementById('changePortSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-rotate"></i> <span>Apply & Restart</span>';
      }
      const cancelBtn = document.getElementById('changePortCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;
      document.getElementById('changePortModal').classList.remove('hidden');
    }

    function closeChangePortModal() {
      document.getElementById('changePortModal').classList.add('hidden');
    }

    async function submitChangeProxyPort() {
      const portVal = parseInt(document.getElementById('modalProxyPortInput').value, 10);
      if (!portVal || portVal < 1 || portVal > 65535) {
        showToast('Please enter a valid port between 1 and 65535', 'error');
        return;
      }

      const submitBtn = document.getElementById('changePortSubmitBtn');
      const cancelBtn = document.getElementById('changePortCancelBtn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>Applying & Restarting...</span>';
      }
      if (cancelBtn) cancelBtn.disabled = true;

      try {
        const res = await apiRequest('/api/v1/config/port', {
          method: 'POST',
          body: JSON.stringify({ port: portVal })
        });
        showToast(res.message || `Primary proxy port updated to :${portVal}`, 'success');
        closeChangePortModal();
        await refreshAllData();
      } catch (e) {
        showToast(e.message || 'Failed to update proxy port', 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fa-solid fa-rotate"></i> <span>Apply & Restart</span>';
        }
        if (cancelBtn) cancelBtn.disabled = false;
      }
    }

    // -------------------------------------------------------------------------
    // Dedicated IP Port Mapping (myport -> tcp_outgoing_address)
    // -------------------------------------------------------------------------
    async function loadPorts() {
      try {
        const data = await apiRequest('/api/v1/network/ports');
        cachedPorts = data.ports || {};
        populatePortDropdown();
      } catch (e) {
        console.error("Failed to load ports", e);
      }
    }

    function populatePortDropdown() {
      const portSelect = document.getElementById('genPortSelect');
      const primaryPort = (currentStatus && currentStatus.network.proxy_port) || 3128;
      const currentVal = portSelect.value;

      portSelect.innerHTML = `<option value="">Default Server Host & Port (:${primaryPort})</option>`;
      
      for (const [ip, port] of Object.entries(cachedPorts)) {
        portSelect.innerHTML += `<option value="${port}">Port :${port} -> Exits via ${escapeHtml(ip)}</option>`;
      }

      cachedInterfaces.forEach(iface => {
        iface.ipv4_addresses.forEach(addr => {
          if (!addr.is_primary) {
            portSelect.innerHTML += `<option value="host_${addr.ip}">Direct IP ${escapeHtml(addr.ip)}:${primaryPort} -> Exits via ${escapeHtml(addr.ip)}</option>`;
          }
        });
      });

      if (currentVal) portSelect.value = currentVal;
    }

    function openAssignIpPortModal(ipAddress, currentPort = null) {
      document.getElementById('modalAssignIpTarget').value = ipAddress;
      let p = '';
      if (currentPort && currentPort !== 'null' && currentPort !== 'undefined') {
        p = currentPort;
      } else if (cachedPorts[ipAddress]) {
        p = cachedPorts[ipAddress];
      }
      document.getElementById('modalAssignPortInput').value = p;
      const submitBtn = document.getElementById('assignPortSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> <span>Save Mapping</span>';
      }
      const cancelBtn = document.getElementById('assignPortCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;
      document.getElementById('assignIpPortModal').classList.remove('hidden');
    }

    function closeAssignIpPortModal() {
      document.getElementById('assignIpPortModal').classList.add('hidden');
    }

    async function submitAssignIpPort() {
      const ip = document.getElementById('modalAssignIpTarget').value.trim();
      const portInput = document.getElementById('modalAssignPortInput').value.trim();
      const portVal = portInput ? parseInt(portInput, 10) : null;

      if (!ip) {
        showToast('Target IP address is missing', 'error');
        return;
      }

      const submitBtn = document.getElementById('assignPortSubmitBtn');
      const cancelBtn = document.getElementById('assignPortCancelBtn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>Saving Mapping...</span>';
      }
      if (cancelBtn) cancelBtn.disabled = true;

      try {
        const res = await apiRequest('/api/v1/network/ports', {
          method: 'POST',
          body: JSON.stringify({ ip: ip, port: portVal })
        });

        if (res.success) {
          showToast('Port mapping saved successfully.', 'success');
        } else {
          showToast(res.detail || res.message || 'Port mapping Error', 'error');
        }
        closeAssignIpPortModal();
        await loadPorts();
        await loadInterfaces();
        await refreshStatus();
        await updateGeneratedSnippets();
      } catch (e) {
        showToast(e.message || 'Failed to save port mapping', 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> <span>Save Mapping</span>';
        }
        if (cancelBtn) cancelBtn.disabled = false;
      }
    }

    // -------------------------------------------------------------------------
    // Users Management Logic & User-Friendly Multi-IP Assignment
    // -------------------------------------------------------------------------
    async function loadUsers() {
      try {
        const data = await apiRequest('/api/v1/users');
        cachedUsers = data.users || [];
        renderUsersTable(cachedUsers);
        populateUserDropdown(cachedUsers);
      } catch (e) {
        console.error("Failed to load users", e);
      }
    }

    function renderUsersTable(users) {
      const tbody = document.getElementById('usersTableBody');
      if (users.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="5" class="px-5 py-8 text-center text-slate-500">
              <i class="fa-solid fa-user-slash text-2xl mb-2"></i>
              <p>No proxy users registered yet. Click <span class="text-brand-400 font-semibold cursor-pointer" onclick="openAddUserModal()">"Create Proxy User"</span> to add one.</p>
            </td>
          </tr>
        `;
        return;
      }

      tbody.innerHTML = users.map(u => {
        let poolBadge = '';
        if (u.outgoing_ip) {
          poolBadge = `
            <button onclick="viewUserAssignedIps('${escapeHtml(u.username)}')" title="Click to view assigned IP" 
                    class="px-2.5 py-1 text-xs font-mono rounded-lg bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 hover:border-indigo-500/50 flex items-center gap-1.5 font-bold w-max transition-all group">
              <i class="fa-solid fa-lock text-indigo-400"></i>
              <span>Fixed IP: ${escapeHtml(u.outgoing_ip)}</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-[10px] text-slate-500 group-hover:text-indigo-300 ml-0.5"></i>
            </button>
          `;
        } else if (u.ip_access_mode === 'custom_list' || (u.assigned_ips && u.assigned_ips.length > 0)) {
          const count = u.assigned_ips.length;
          poolBadge = `
            <button onclick="viewUserAssignedIps('${escapeHtml(u.username)}')" title="Click to view all ${count} assigned IPs" 
                    class="px-2.5 py-1 text-xs font-mono rounded-lg bg-violet-500/10 text-violet-300 border border-violet-500/20 hover:border-violet-500/50 flex items-center gap-1.5 font-bold w-max transition-all group">
              <i class="fa-solid fa-list-check text-violet-400"></i>
              <span>Pool: ${count} Assigned IPs</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-[10px] text-slate-500 group-hover:text-violet-300 ml-0.5"></i>
            </button>
          `;
        } else if (u.ip_access_mode === 'range' && u.ip_range_or_cidr) {
          poolBadge = `
            <button onclick="viewUserAssignedIps('${escapeHtml(u.username)}')" title="Click to view expanded subnet pool" 
                    class="px-2.5 py-1 text-xs font-mono rounded-lg bg-amber-500/10 text-amber-300 border border-amber-500/20 hover:border-amber-500/50 flex items-center gap-1.5 font-bold w-max transition-all group">
              <i class="fa-solid fa-layer-group text-amber-400"></i>
              <span>Pool: ${escapeHtml(u.ip_range_or_cidr)}</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-[10px] text-slate-500 group-hover:text-amber-300 ml-0.5"></i>
            </button>
          `;
        } else {
          poolBadge = `
            <button onclick="viewUserAssignedIps('${escapeHtml(u.username)}')" title="Click to view all server IPs" 
                    class="px-2.5 py-1 text-xs font-mono rounded-lg bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 hover:border-emerald-500/50 flex items-center gap-1.5 w-max transition-all group">
              <i class="fa-solid fa-globe text-emerald-400"></i>
              <span>All Server IPs (Full Access)</span>
              <i class="fa-solid fa-arrow-up-right-from-square text-[10px] text-slate-500 group-hover:text-emerald-300 ml-0.5"></i>
            </button>
          `;
        }

        return `
          <tr class="hover:bg-dark-850/60 transition-colors">
            <td class="px-5 py-4 font-mono font-bold text-white flex items-center gap-2">
              <div class="w-7 h-7 rounded-lg bg-brand-500/10 text-brand-400 flex items-center justify-center text-xs">
                <i class="fa-solid fa-user"></i>
              </div>
              <span>${escapeHtml(u.username)}</span>
            </td>
            <td class="px-5 py-4">
              ${poolBadge}
            </td>
            <td class="px-5 py-4 text-xs text-slate-300">
              ${escapeHtml(u.notes || '--')}
            </td>
            <td class="px-5 py-4 text-xs font-mono text-slate-400">
              ${escapeHtml(u.created_at || 'N/A')}
            </td>
            <td class="px-5 py-4 text-right">
              <div class="flex items-center justify-end gap-1.5">
                <button onclick="openEditUserModal('${escapeHtml(u.username)}')" title="Edit User & IP Access Pool" 
                        class="px-2.5 py-1.5 rounded-lg bg-dark-800 hover:bg-brand-500/20 text-brand-400 hover:text-brand-300 text-xs font-semibold transition-all flex items-center gap-1">
                  <i class="fa-solid fa-pen-to-square"></i>
                  <span class="hidden sm:inline">Edit</span>
                </button>
                <button onclick="openChangePasswordModal('${escapeHtml(u.username)}')" title="Change User Password" 
                        class="px-2.5 py-1.5 rounded-lg bg-dark-800 hover:bg-amber-500/20 text-amber-400 hover:text-amber-300 text-xs font-semibold transition-all flex items-center gap-1">
                  <i class="fa-solid fa-key"></i>
                  <span class="hidden sm:inline">Password</span>
                </button>
                <button onclick="deleteUser('${escapeHtml(u.username)}', this)" title="Delete User" 
                        class="p-1.5 rounded-lg bg-dark-800 hover:bg-rose-500/20 text-rose-400 hover:text-rose-300 text-xs transition-all">
                  <i class="fa-regular fa-trash-can"></i>
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    function populateUserDropdown(users) {
      const select = document.getElementById('genUserSelect');
      const currentVal = select.value;
      select.innerHTML = '<option value="">(Enter Manually / Custom)</option>' + 
        users.map(u => `<option value="${escapeHtml(u.username)}">${escapeHtml(u.username)} ${u.outgoing_ip ? ' [Route: ' + escapeHtml(u.outgoing_ip) + ']' : ''}</option>`).join('');
      if (currentVal) select.value = currentVal;
    }

    function onUserSelectionChanged() {
      updateGeneratedSnippets();
    }

    // -------------------------------------------------------------------------
    // User Modal IP Mode Selector & Rendering
    // -------------------------------------------------------------------------
    function selectUserIpModeCard(mode) {
      document.getElementById('modalUserIpModeHidden').value = mode;

      ['all', 'custom_list', 'range', 'single'].forEach(m => {
        const card = document.getElementById(`modeCard-${m}`);
        if (card) {
          if (m === mode) {
            card.classList.add('active');
          } else {
            card.classList.remove('active');
          }
        }
      });

      const summary = document.getElementById('userModalSelectedSummary');
      document.getElementById('userCustomListWrapper').classList.add('hidden');
      document.getElementById('userRangeWrapper').classList.add('hidden');
      document.getElementById('userSingleIpWrapper').classList.add('hidden');

      if (mode === 'all') {
        summary.textContent = 'All Server IPs (Dynamic Pool)';
        summary.className = 'text-xs font-mono text-emerald-400 font-bold';
      } else if (mode === 'custom_list') {
        document.getElementById('userCustomListWrapper').classList.remove('hidden');
        updateUserIpCountBadge();
      } else if (mode === 'range') {
        document.getElementById('userRangeWrapper').classList.remove('hidden');
        debounceUserRangePreview();
      } else if (mode === 'single') {
        document.getElementById('userSingleIpWrapper').classList.remove('hidden');
        summary.textContent = 'Fixed Single IP Route';
        summary.className = 'text-xs font-mono text-cyan-400 font-bold';
      }
    }

    function renderUserIpCheckboxes(selectedIps = []) {
      const container = document.getElementById('userIpCheckboxesContainer');
      const allIps = [];
      cachedInterfaces.forEach(iface => {
        iface.ipv4_addresses.forEach(addr => {
          const portVal = addr.assigned_port || cachedPorts[addr.ip] || null;
          allIps.push({
            ip: addr.ip,
            iface: iface.name,
            label: addr.label || '',
            port: portVal
          });
        });
      });

      if (allIps.length === 0) {
        container.innerHTML = '<p class="text-xs text-slate-500 p-3 text-center">No bound IPs detected on server interfaces.</p>';
        return;
      }

      container.innerHTML = allIps.map(item => {
        const isChecked = selectedIps.includes(item.ip);
        const portTag = item.port ? ` <span class="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-bold">Port :${item.port}</span>` : '';
        return `
          <div onclick="toggleUserIpChip(this)" data-ip="${escapeHtml(item.ip)}" 
               class="ip-chip-card flex items-center justify-between p-2.5 rounded-xl border border-slate-700/60 bg-dark-900 hover:border-violet-500/50 ${isChecked ? 'selected' : ''}">
            <div class="flex items-center gap-2.5">
              <input type="checkbox" name="userAssignedIpCheckbox" value="${escapeHtml(item.ip)}" ${isChecked ? 'checked' : ''}
                     onclick="event.stopPropagation(); updateUserIpCountBadge();" 
                     class="w-4 h-4 rounded text-violet-600 bg-dark-950 border-slate-700 focus:ring-violet-500">
              <div>
                <span class="text-white font-mono font-bold text-xs">${escapeHtml(item.ip)}</span>
                <span class="text-slate-500 text-[11px] ml-1.5">(${escapeHtml(item.iface)} &bull; ${escapeHtml(item.label || 'Secondary')})</span>
              </div>
            </div>
            <div>
              ${portTag}
            </div>
          </div>
        `;
      }).join('');

      updateUserIpCountBadge();
    }

    function toggleUserIpChip(cardEl) {
      const cb = cardEl.querySelector('input[name="userAssignedIpCheckbox"]');
      if (cb) {
        cb.checked = !cb.checked;
        if (cb.checked) {
          cardEl.classList.add('selected');
        } else {
          cardEl.classList.remove('selected');
        }
        updateUserIpCountBadge();
      }
    }

    function filterUserIpCheckboxes() {
      const query = document.getElementById('userIpSearchInput').value.trim().toLowerCase();
      document.querySelectorAll('#userIpCheckboxesContainer .ip-chip-card').forEach(card => {
        const text = card.textContent.toLowerCase();
        if (!query || text.includes(query)) {
          card.classList.remove('hidden');
        } else {
          card.classList.add('hidden');
        }
      });
    }

    function selectAllUserIps(check) {
      document.querySelectorAll('input[name="userAssignedIpCheckbox"]').forEach(cb => {
        cb.checked = check;
        const parent = cb.closest('.ip-chip-card');
        if (parent) {
          if (check) parent.classList.add('selected');
          else parent.classList.remove('selected');
        }
      });
      updateUserIpCountBadge();
    }

    function updateUserIpCountBadge() {
      const total = document.querySelectorAll('input[name="userAssignedIpCheckbox"]').length;
      const checked = document.querySelectorAll('input[name="userAssignedIpCheckbox"]:checked').length;
      
      const badge = document.getElementById('userIpSelectionCountBadge');
      if (badge) badge.textContent = `${checked} of ${total} Selected`;

      const summary = document.getElementById('userModalSelectedSummary');
      if (summary) {
        summary.textContent = `Custom Pool (${checked} IPs Selected)`;
        summary.className = 'text-xs font-mono text-violet-400 font-bold';
      }
    }

    function setSubnetHelper(suffix) {
      const input = document.getElementById('modalUserRangeText');
      const val = input.value.trim();
      if (val && !val.includes('/')) {
        const baseIp = val.split(/[-,\\s]/)[0].trim();
        input.value = baseIp + suffix;
      } else {
        input.value = '192.168.1.0' + suffix;
      }
      debounceUserRangePreview();
    }

    function debounceUserRangePreview() {
      clearTimeout(userRangeDebounceTimer);
      userRangeDebounceTimer = setTimeout(previewUserRangePool, 400);
    }

    async function previewUserRangePool() {
      const rawText = document.getElementById('modalUserRangeText').value.trim();
      const badge = document.getElementById('userRangePreviewBadge');
      const previewBox = document.getElementById('userRangeLivePreviewBox');
      const summary = document.getElementById('userModalSelectedSummary');

      if (!rawText) {
        badge.textContent = '0 IPs detected';
        previewBox.innerHTML = 'Enter a subnet (e.g. 192.168.1.0/29) or range (192.168.1.5 - 192.168.1.10) to preview expanded IPs.';
        return;
      }

      if (rawText.length < 7 && !rawText.includes('/')) {
        badge.textContent = 'Typing...';
        return;
      }

      try {
        const res = await apiRequest('/api/v1/network/ips/preview', {
          method: 'POST',
          body: JSON.stringify({
            mode: 'cidr',
            raw_text: rawText,
            port_mode: 'none'
          })
        });

        if (res.success && res.ips.length > 0) {
          badge.textContent = `${res.total_ips} IPs in Pool${res.is_truncated ? ' (showing 128)' : ''}`;
          summary.textContent = `Subnet Pool (${res.total_ips} IPs)`;
          summary.className = 'text-xs font-mono text-amber-400 font-bold';

          previewBox.innerHTML = `
            <div class="text-emerald-400 font-bold mb-1"><i class="fa-solid fa-check"></i> Validated ${res.total_ips} Usable Host IPs:</div>
            <div class="flex flex-wrap gap-1 text-white max-h-36 overflow-y-auto pr-1">
              ${res.ips.map(item => `<span class="px-1.5 py-0.5 rounded bg-dark-900 border border-slate-700 text-[10px] font-mono">${escapeHtml(item.ip)}</span>`).join('')}
              ${res.is_truncated ? `<span class="px-1.5 py-0.5 rounded bg-dark-950 border border-slate-800 text-[10px] font-mono text-slate-500 italic">+${res.total_ips - res.ips.length} more</span>` : ''}
            </div>
          `;
        }
      } catch (e) {
        badge.textContent = 'Invalid format';
        previewBox.innerHTML = `<span class="text-rose-400"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(e.message || 'Invalid format')}</span>`;
      }
    }

    function populateSingleIpSelect(selectedIp = '') {
      const select = document.getElementById('modalUserSingleIpSelect');
      select.innerHTML = '<option value="">Default Server Route</option>';
      cachedInterfaces.forEach(iface => {
        iface.ipv4_addresses.forEach(addr => {
          const isSel = (addr.ip === selectedIp) ? 'selected' : '';
          const portVal = addr.assigned_port || cachedPorts[addr.ip] || null;
          const portTag = portVal ? ` [Port :${portVal}]` : '';
          select.innerHTML += `<option value="${escapeHtml(addr.ip)}" ${isSel}>${escapeHtml(addr.ip)}${portTag} (${iface.name} - ${escapeHtml(addr.label)})</option>`;
        });
      });
    }

    function openAddUserModal() {
      isEditingUser = false;
      document.getElementById('userModalTitle').textContent = 'Create Proxy User';
      document.getElementById('userModalIcon').innerHTML = '<i class="fa-solid fa-user-plus"></i>';
      document.getElementById('modalUsername').value = '';
      document.getElementById('modalUsername').removeAttribute('readonly');
      document.getElementById('modalUsername').classList.remove('cursor-not-allowed', 'text-amber-300');
      document.getElementById('modalPassword').value = '';
      document.getElementById('modalPasswordHelp').classList.add('hidden');
      document.getElementById('modalUserNotes').value = '';
      document.getElementById('modalUserRangeText').value = '';
      document.getElementById('userIpSearchInput').value = '';

      renderUserIpCheckboxes([]);
      populateSingleIpSelect('');
      selectUserIpModeCard('all');

      const submitBtn = document.getElementById('userModalSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> <span>Save User & IP Access</span>';
      }
      const cancelBtn = document.getElementById('userModalCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;

      document.getElementById('userModal').classList.remove('hidden');
    }

    function openEditUserModal(username) {
      const user = cachedUsers.find(u => u.username === username);
      if (!user) return;

      isEditingUser = true;
      document.getElementById('userModalTitle').textContent = `Edit User & IP Pool: ${username}`;
      document.getElementById('userModalIcon').innerHTML = '<i class="fa-solid fa-pen-to-square"></i>';
      document.getElementById('modalUsername').value = username;
      document.getElementById('modalUsername').setAttribute('readonly', 'true');
      document.getElementById('modalUsername').classList.add('cursor-not-allowed', 'text-amber-300');
      document.getElementById('modalPassword').value = '';
      document.getElementById('modalPasswordHelp').classList.remove('hidden');
      document.getElementById('modalUserNotes').value = user.notes || '';
      document.getElementById('modalUserRangeText').value = user.ip_range_or_cidr || '';
      document.getElementById('userIpSearchInput').value = '';

      renderUserIpCheckboxes(user.assigned_ips || []);
      populateSingleIpSelect(user.outgoing_ip || '');

      const mode = user.ip_access_mode || (user.outgoing_ip ? 'single' : (user.assigned_ips && user.assigned_ips.length > 0 ? 'custom_list' : 'all'));
      selectUserIpModeCard(mode);

      const submitBtn = document.getElementById('userModalSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> <span>Save User & IP Access</span>';
      }
      const cancelBtn = document.getElementById('userModalCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;

      document.getElementById('userModal').classList.remove('hidden');
    }

    function closeUserModal() {
      document.getElementById('userModal').classList.add('hidden');
    }

    async function submitUserForm() {
      const username = document.getElementById('modalUsername').value.trim();
      const password = document.getElementById('modalPassword').value.trim();
      const notes = document.getElementById('modalUserNotes').value.trim();
      const ipMode = document.getElementById('modalUserIpModeHidden').value;

      if (!username) {
        showToast('Username is required', 'error');
        return;
      }
      if (!isEditingUser && !password) {
        showToast('Password is required for new users', 'error');
        return;
      }

      let outgoing_ip = null;
      let assigned_ips = [];
      let ip_range_or_cidr = null;

      if (ipMode === 'single') {
        outgoing_ip = document.getElementById('modalUserSingleIpSelect').value.trim() || null;
      } else if (ipMode === 'custom_list') {
        document.querySelectorAll('input[name="userAssignedIpCheckbox"]:checked').forEach(cb => {
          assigned_ips.push(cb.value);
        });
      } else if (ipMode === 'range') {
        ip_range_or_cidr = document.getElementById('modalUserRangeText').value.trim() || null;
      }

      const submitBtn = document.getElementById('userModalSubmitBtn');
      const cancelBtn = document.getElementById('userModalCancelBtn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>${isEditingUser ? 'Updating User Config...' : 'Creating User...'}</span>`;
      }
      if (cancelBtn) cancelBtn.disabled = true;

      try {
        const payload = {
          username,
          password: password || undefined,
          notes,
          outgoing_ip,
          ip_access_mode: ipMode,
          assigned_ips,
          ip_range_or_cidr
        };

        const res = await apiRequest('/api/v1/users', {
          method: 'POST',
          body: JSON.stringify(payload)
        });

        showToast(res.message || (isEditingUser ? 'Proxy user updated successfully' : 'Proxy user saved successfully'), 'success');
        closeUserModal();
        await loadUsers();
        await refreshStatus();
      } catch (e) {
        showToast(e.message || 'Failed to save proxy user', 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> <span>Save User & IP Access</span>';
        }
        if (cancelBtn) cancelBtn.disabled = false;
      }
    }

    function openChangePasswordModal(username) {
      document.getElementById('modalChangePassUsername').value = username;
      document.getElementById('modalChangePassInput').value = '';
      const submitBtn = document.getElementById('changePassSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-key"></i> <span>Update Password</span>';
      }
      const cancelBtn = document.getElementById('changePassCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;
      document.getElementById('changeUserPasswordModal').classList.remove('hidden');
    }

    function closeChangePasswordModal() {
      document.getElementById('changeUserPasswordModal').classList.add('hidden');
    }

    function generateRandomPasswordForChange() {
      const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";
      let pass = "";
      for (let i = 0; i < 16; i++) {
        pass += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      document.getElementById('modalChangePassInput').value = pass;
    }

    async function submitChangeUserPassword() {
      const username = document.getElementById('modalChangePassUsername').value;
      const newPassword = document.getElementById('modalChangePassInput').value.trim();

      if (!newPassword) {
        showToast('Please enter or generate a new password', 'error');
        return;
      }

      const submitBtn = document.getElementById('changePassSubmitBtn');
      const cancelBtn = document.getElementById('changePassCancelBtn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>Updating Password...</span>';
      }
      if (cancelBtn) cancelBtn.disabled = true;

      try {
        const res = await apiRequest(`/api/v1/users/${encodeURIComponent(username)}/password`, {
          method: 'POST',
          body: JSON.stringify({ password: newPassword })
        });
        showToast(res.message || `Password for ${username} updated successfully`, 'success');
        closeChangePasswordModal();
        await loadUsers();
      } catch (e) {
        showToast(e.message || 'Failed to update password', 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fa-solid fa-key"></i> <span>Update Password</span>';
        }
        if (cancelBtn) cancelBtn.disabled = false;
      }
    }

    function generateRandomPassword() {
      const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";
      let pass = "";
      for (let i = 0; i < 16; i++) {
        pass += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      document.getElementById('modalPassword').value = pass;
    }

    async function deleteUser(username, btn = null) {
      if (!confirm(`Are you sure you want to permanently delete proxy user '${username}'?`)) return;
      
      let origHtml = '';
      if (btn) {
        btn.disabled = true;
        origHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-rose-400 text-xs"></i>';
      }

      try {
        const res = await apiRequest(`/api/v1/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
        showToast(res.message || 'User deleted successfully', 'success');
        await loadUsers();
        await refreshStatus();
      } catch (e) {
        showToast(e.message || 'Failed to delete user', 'error');
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = origHtml;
        }
      }
    }

    // -------------------------------------------------------------------------
    // Network Interfaces & Secondary IP Logic (nmcli / iproute2)
    // -------------------------------------------------------------------------
    async function loadInterfaces() {
      try {
        const data = await apiRequest('/api/v1/network/interfaces');
        cachedInterfaces = data.interfaces || [];
        renderInterfaces(cachedInterfaces);
      } catch (e) {
        console.error("Failed to load interfaces", e);
      }
    }

    function renderInterfaces(interfaces) {
      const container = document.getElementById('interfacesContainer');
      if (interfaces.length === 0) {
        container.innerHTML = `<div class="p-8 text-center text-slate-500">No active network interfaces detected.</div>`;
        return;
      }

      container.innerHTML = interfaces.map(iface => `
        <div class="glass-card p-5 rounded-2xl border border-white/5 space-y-4">
          <div class="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 pb-3">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center font-bold">
                <i class="fa-solid fa-network-wired"></i>
              </div>
              <div>
                <div class="flex items-center gap-2">
                  <span class="font-mono font-bold text-white text-base">${escapeHtml(iface.name)}</span>
                  <span class="px-2 py-0.5 text-[10px] font-mono rounded-md ${iface.is_up ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400'}">
                    ${iface.is_up ? 'UP' : 'DOWN'}
                  </span>
                </div>
                <p class="text-xs text-slate-400 font-mono">Connection: ${escapeHtml(iface.connection_name)} &bull; MTU: ${iface.mtu} ${iface.mac_address ? '&bull; MAC: ' + escapeHtml(iface.mac_address) : ''}</p>
              </div>
            </div>
            <div class="flex items-center gap-2">
              <button onclick="openBatchAddIpModal('${escapeHtml(iface.name)}')" 
                      class="px-3 py-1.5 rounded-xl bg-indigo-600/30 hover:bg-indigo-600 text-indigo-300 hover:text-white border border-indigo-500/40 text-xs font-bold transition-all flex items-center gap-1.5">
                <i class="fa-solid fa-layer-group"></i>
                <span>Batch Pool</span>
              </button>
              <button onclick="openAddSecondaryIpModal('${escapeHtml(iface.name)}')" 
                      class="px-3 py-1.5 rounded-xl bg-dark-900 border border-slate-700 hover:border-slate-500 text-xs font-semibold text-slate-300 hover:text-white transition-all flex items-center gap-1">
                <i class="fa-solid fa-plus"></i>
                <span>Single IP</span>
              </button>
            </div>
          </div>

          <!-- Bound IP & Port Table -->
          <div class="overflow-x-auto rounded-xl border border-white/5">
            <table class="w-full text-left text-xs text-slate-300 font-mono">
              <thead class="bg-dark-950/70 uppercase text-slate-500">
                <tr>
                  <th class="px-4 py-2.5">Bound IP / CIDR</th>
                  <th class="px-4 py-2.5">Type</th>
                  <th class="px-4 py-2.5">Inbound Listening Port</th>
                  <th class="px-4 py-2.5">Self-Outgoing Match</th>
                  <th class="px-4 py-2.5">Label / Note</th>
                  <th class="px-4 py-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-white/5 bg-dark-900/30">
                ${iface.ipv4_addresses.map(addr => {
                  const portNum = addr.assigned_port || cachedPorts[addr.ip] || null;
                  return `
                  <tr class="hover:bg-dark-850/40">
                    <td class="px-4 py-3 font-bold text-white">
                      ${escapeHtml(addr.ip_cidr)}
                    </td>
                    <td class="px-4 py-3">
                      <span class="px-2 py-0.5 rounded-md ${addr.is_primary ? 'bg-brand-500/10 text-brand-400 border border-brand-500/20' : 'bg-indigo-500/10 text-indigo-300 border border-indigo-500/20'}">
                        ${addr.is_primary ? 'Primary Host IP' : 'Secondary Pool IP'}
                      </span>
                    </td>
                    <td class="px-4 py-3">
                      ${portNum ? `
                        <button onclick="openAssignIpPortModal('${escapeHtml(addr.ip)}', ${portNum})" class="px-2 py-1 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-bold hover:bg-indigo-500 hover:text-white transition-all flex items-center gap-1">
                          <i class="fa-solid fa-door-open text-xs"></i>
                          <span>:${portNum}</span>
                        </button>
                      ` : `
                        <button onclick="openAssignIpPortModal('${escapeHtml(addr.ip)}', null)" class="text-slate-500 hover:text-indigo-400 text-[11px] underline">
                          + Assign Port
                        </button>
                      `}
                    </td>
                    <td class="px-4 py-3 text-emerald-400 font-bold">
                      <span class="flex items-center gap-1 text-[11px]">
                        <i class="fa-solid fa-arrow-right-from-bracket text-[10px]"></i>
                        <span>${escapeHtml(addr.ip)}</span>
                      </span>
                    </td>
                    <td class="px-4 py-3 text-slate-400">
                      ${escapeHtml(addr.label || '--')}
                    </td>
                    <td class="px-4 py-3 text-right">
                      <div class="flex items-center justify-end gap-1.5">
                        <button onclick="openAssignIpPortModal('${escapeHtml(addr.ip)}', ${portNum ? portNum : 'null'})" title="Configure Port for this IP" 
                                class="p-1.5 rounded bg-dark-800 hover:bg-indigo-500/30 text-indigo-400 text-xs transition-all">
                          <i class="fa-solid fa-gear"></i>
                        </button>
                        ${addr.is_secondary ? `
                          <button onclick="deleteSecondaryIp('${escapeHtml(iface.name)}', '${escapeHtml(addr.ip)}', ${addr.cidr}, this)" title="Remove Secondary IP" 
                                  class="p-1.5 rounded bg-dark-800 hover:bg-rose-500/20 text-rose-400 text-xs transition-all">
                            <i class="fa-regular fa-trash-can"></i>
                          </button>
                        ` : `
                          <span class="text-slate-600 px-1">Fixed</span>
                        `}
                      </div>
                    </td>
                  </tr>
                `}).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `).join('');
    }

    function openAddSecondaryIpModal(selectedIface = '') {
      const select = document.getElementById('modalSecIfaceSelect');
      select.innerHTML = cachedInterfaces.map(i => `<option value="${escapeHtml(i.name)}">${escapeHtml(i.name)} (${escapeHtml(i.connection_name)})</option>`).join('');
      if (selectedIface) select.value = selectedIface;

      document.getElementById('modalSecIp').value = '';
      document.getElementById('modalSecLabel').value = '';
      document.getElementById('modalSecPort').value = '';
      document.getElementById('modalSecCidr').value = '32';

      const submitBtn = document.getElementById('modalSecSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-plus"></i> <span>Bind IP & Port</span>';
      }
      const cancelBtn = document.getElementById('modalSecCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;

      document.getElementById('addSecondaryIpModal').classList.remove('hidden');
    }

    function closeAddSecondaryIpModal() {
      document.getElementById('addSecondaryIpModal').classList.add('hidden');
    }

    async function submitAddSecondaryIp() {
      const iface = document.getElementById('modalSecIfaceSelect').value;
      const ip = document.getElementById('modalSecIp').value.trim();
      const cidr = parseInt(document.getElementById('modalSecCidr').value, 10) || 32;
      const portInput = document.getElementById('modalSecPort').value.trim();
      const port = portInput ? parseInt(portInput, 10) : null;
      const label = document.getElementById('modalSecLabel').value.trim();

      if (!ip) {
        showToast('Please enter an IP address', 'error');
        return;
      }

      const submitBtn = document.getElementById('modalSecSubmitBtn');
      const cancelBtn = document.getElementById('modalSecCancelBtn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>Binding IP & Port...</span>';
      }
      if (cancelBtn) cancelBtn.disabled = true;

      try {
        const res = await apiRequest('/api/v1/network/ips', {
          method: 'POST',
          body: JSON.stringify({ interface: iface, ip, cidr, label, persistent: true, port })
        });
        showToast(res.message || 'Secondary IP bound successfully', 'success');
        closeAddSecondaryIpModal();
        await loadPorts();
        await loadInterfaces();
        await refreshStatus();
        await updateGeneratedSnippets();
      } catch (e) {
        showToast(e.message || 'Failed to bind secondary IP', 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fa-solid fa-plus"></i> <span>Bind IP & Port</span>';
        }
        if (cancelBtn) cancelBtn.disabled = false;
      }
    }

    async function deleteSecondaryIp(iface, ip, cidr, btn = null) {
      if (!confirm(`Are you sure you want to unbind secondary IP '${ip}/${cidr}' from ${iface}?`)) return;

      let origHtml = '';
      if (btn) {
        btn.disabled = true;
        origHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-rose-400 text-xs"></i>';
      }

      try {
        const res = await apiRequest('/api/v1/network/ips', {
          method: 'DELETE',
          body: JSON.stringify({ interface: iface, ip, cidr })
        });
        showToast(res.message || 'Secondary IP unpinned successfully', 'success');
        await loadPorts();
        await loadInterfaces();
        await refreshStatus();
        await updateGeneratedSnippets();
      } catch (e) {
        showToast(e.message || 'Failed to remove secondary IP', 'error');
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = origHtml;
        }
      }
    }

    // -------------------------------------------------------------------------
    // IP Whitelist Management Logic
    // -------------------------------------------------------------------------
    async function loadIps() {
      try {
        const data = await apiRequest('/api/v1/ips');
        cachedIps = data.ips || [];
        renderIpsTable(cachedIps);
      } catch (e) {
        console.error("Failed to load IPs", e);
      }
    }

    function renderIpsTable(ips) {
      const tbody = document.getElementById('ipsTableBody');
      if (ips.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="5" class="px-5 py-8 text-center text-slate-500">
              <i class="fa-solid fa-shield-virus text-2xl mb-2"></i>
              <p>No IP addresses whitelisted. Click <span class="text-violet-400 font-semibold cursor-pointer" onclick="openAddIpModal()">"Whitelist New IP"</span> to bypass auth for trusted clients.</p>
            </td>
          </tr>
        `;
        return;
      }

      tbody.innerHTML = ips.map(item => `
        <tr class="hover:bg-dark-850/60 transition-colors">
          <td class="px-5 py-4 font-mono font-bold text-white flex items-center gap-2">
            <div class="w-7 h-7 rounded-lg bg-violet-500/10 text-violet-400 flex items-center justify-center text-xs">
              <i class="fa-solid fa-network-wired"></i>
            </div>
            <span>${escapeHtml(item.ip)}</span>
          </td>
          <td class="px-5 py-4">
            <span class="px-2.5 py-1 text-xs font-mono rounded-lg ${item.is_subnet ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20' : 'bg-dark-950 text-slate-300 border border-white/10'}">
              ${item.is_subnet ? 'Subnet (CIDR)' : 'Single Host'}
            </span>
          </td>
          <td class="px-5 py-4 text-xs text-slate-300">
            ${escapeHtml(item.label || '--')}
          </td>
          <td class="px-5 py-4 text-xs font-mono text-slate-400">
            ${escapeHtml(item.created_at || 'N/A')}
          </td>
          <td class="px-5 py-4 text-right">
            <button onclick="deleteIp('${escapeHtml(item.ip)}', this)" title="Remove from Whitelist" 
                    class="p-1.5 rounded-lg bg-dark-800 hover:bg-rose-500/20 text-rose-400 hover:text-rose-300 text-xs transition-all">
              <i class="fa-regular fa-trash-can"></i>
            </button>
          </td>
        </tr>
      `).join('');
    }

    function openAddIpModal() {
      document.getElementById('modalIpAddress').value = '';
      document.getElementById('modalIpLabel').value = '';
      const submitBtn = document.getElementById('addIpSubmitBtn');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> <span>Whitelist IP</span>';
      }
      const cancelBtn = document.getElementById('addIpCancelBtn');
      if (cancelBtn) cancelBtn.disabled = false;
      document.getElementById('addIpModal').classList.remove('hidden');
    }

    function closeAddIpModal() {
      document.getElementById('addIpModal').classList.add('hidden');
    }

    async function detectMyIpForModal() {
      const detectBtn = document.getElementById('detectIpBtn');
      const origHtml = detectBtn ? detectBtn.innerHTML : '';
      if (detectBtn) {
        detectBtn.disabled = true;
        detectBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-xs"></i> <span>Detecting...</span>';
      }
      try {
        const resp = await fetch('https://api.ipify.org?format=json');
        const data = await resp.json();
        if (data.ip) {
          document.getElementById('modalIpAddress').value = data.ip;
          document.getElementById('modalIpLabel').value = 'My Current Public IP';
          showToast(`Detected IP: ${data.ip}`, 'info');
        }
      } catch (e) {
        showToast('Could not auto-detect client IP', 'error');
      } finally {
        if (detectBtn) {
          detectBtn.disabled = false;
          detectBtn.innerHTML = origHtml;
        }
      }
    }

    async function submitAddIp() {
      const ip = document.getElementById('modalIpAddress').value.trim();
      const label = document.getElementById('modalIpLabel').value.trim();

      if (!ip) {
        showToast('Please enter an IP address or CIDR', 'error');
        return;
      }

      const submitBtn = document.getElementById('addIpSubmitBtn');
      const cancelBtn = document.getElementById('addIpCancelBtn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin mr-2"></i> <span>Whitelisting IP...</span>';
      }
      if (cancelBtn) cancelBtn.disabled = true;

      try {
        const res = await apiRequest('/api/v1/ips', {
          method: 'POST',
          body: JSON.stringify({ ip, label })
        });
        showToast(res.message || 'IP whitelisted successfully', 'success');
        closeAddIpModal();
        await loadIps();
        await refreshStatus();
      } catch (e) {
        showToast(e.message || 'Failed to whitelist IP', 'error');
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> <span>Whitelist IP</span>';
        }
        if (cancelBtn) cancelBtn.disabled = false;
      }
    }

    async function deleteIp(ipVal, btn = null) {
      if (!confirm(`Are you sure you want to remove '${ipVal}' from the IP whitelist?`)) return;

      let origHtml = '';
      if (btn) {
        btn.disabled = true;
        origHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-rose-400 text-xs"></i>';
      }

      try {
        const res = await apiRequest(`/api/v1/ips/${encodeURIComponent(ipVal)}`, { method: 'DELETE' });
        showToast(res.message || 'IP removed and Squid reconfigured', 'success');
        await loadIps();
        await refreshStatus();
      } catch (e) {
        showToast(e.message || 'Failed to remove IP', 'error');
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = origHtml;
        }
      }
    }

    // -------------------------------------------------------------------------
    // Code Generator Logic
    // -------------------------------------------------------------------------
    async function updateGeneratedSnippets() {
      const mode = document.getElementById('genAuthMode').value;
      const portOrHost = document.getElementById('genPortSelect').value;
      const userWrapper = document.getElementById('genUserSelectWrapper');
      const selectedUser = document.getElementById('genUserSelect').value;

      if (mode === 'ip') {
        userWrapper.classList.add('opacity-50', 'pointer-events-none');
      } else {
        userWrapper.classList.remove('opacity-50', 'pointer-events-none');
      }

      let url = '/api/v1/connection-strings?';
      const params = [];
      if (mode === 'user') {
        const u = selectedUser || 'username';
        const p = 'password';
        params.push(`username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`);
      }
      if (portOrHost) {
        if (portOrHost.startsWith('host_')) {
          const h = portOrHost.replace('host_', '');
          params.push(`host_override=${encodeURIComponent(h)}`);
        } else {
          params.push(`port_override=${encodeURIComponent(portOrHost)}`);
        }
      }
      url += params.join('&');

      try {
        currentSnippets = await apiRequest(url);
        renderActiveCodeSnippet();
      } catch (e) {
        console.error("Snippets load failed", e);
      }
    }

    function showCodeTab(tab) {
      activeCodeTab = tab;
      ['curl', 'python', 'httpx', 'node', 'golang', 'env'].forEach(t => {
        const btn = document.getElementById(`codeTab-${t}`);
        if (t === tab) {
          btn.className = 'px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/30';
        } else {
          btn.className = 'px-3 py-1.5 text-xs font-semibold rounded-lg bg-dark-900 text-slate-400 hover:text-white';
        }
      });
      renderActiveCodeSnippet();
    }

    function renderActiveCodeSnippet() {
      const box = document.getElementById('codeSnippetBox');
      if (!currentSnippets) return;

      let code = '';
      switch (activeCodeTab) {
        case 'curl':
          code = `${currentSnippets.curl}\n\n# Inbound Endpoint: ${currentSnippets.host}:${currentSnippets.port}\n# Outbound Exit Public IP: ${currentSnippets.assigned_outgoing_ip}\n# Verbose header inspection:\n${currentSnippets.curl_verbose}`;
          break;
        case 'python':
          code = currentSnippets.python_requests;
          break;
        case 'httpx':
          code = currentSnippets.python_httpx;
          break;
        case 'node':
          code = currentSnippets.node_axios;
          break;
        case 'golang':
          code = currentSnippets.golang;
          break;
        case 'env':
          code = `# Linux / macOS Bash:\n${currentSnippets.linux_export}\n\n# Windows PowerShell:\n${currentSnippets.powershell_export}`;
          break;
      }
      box.textContent = code;
    }

    async function copyToClipboard(text) {
      if (!text) return false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch (err) {
        // Fallback to execCommand
      }

      try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-999999px';
        textarea.style.top = '-999999px';
        textarea.setAttribute('readonly', '');
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        const successful = document.execCommand('copy');
        document.body.removeChild(textarea);
        return successful;
      } catch (err) {
        console.error('Fallback clipboard copy failed:', err);
        return false;
      }
    }

    async function copyCurrentCodeSnippet() {
      const text = document.getElementById('codeSnippetBox').textContent;
      await copyToClipboard(text);
      showToast('Code snippet copied to clipboard', 'success');
    }

    // -------------------------------------------------------------------------
    // General UI Helpers
    // -------------------------------------------------------------------------
    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.tab-button').forEach(el => {
        el.className = 'tab-button px-4 py-2.5 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 bg-dark-900 text-slate-300 hover:text-white border border-transparent hover:border-white/10';
      });

      document.getElementById(`tab-${tabId}`).classList.remove('hidden');
      const activeBtn = document.getElementById(`tabBtn-${tabId}`);
      activeBtn.className = 'tab-button px-4 py-2.5 rounded-xl font-semibold text-sm transition-all flex items-center gap-2 bg-brand-500 text-black shadow-lg shadow-brand-500/20';
    }

    async function triggerReload() {
      const btn = document.querySelector('button[onclick="triggerReload()"]');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-brand-400"></i>';
      }

      try {
        const isRunning = currentStatus && currentStatus.squid && currentStatus.squid.is_running;
        const endpoint = isRunning ? '/api/v1/proxy/reload' : '/api/v1/proxy/start';
        const res = await apiRequest(endpoint, { method: 'POST' });
        if (res.success) {
          showToast(isRunning ? 'Squid configuration reloaded successfully' : 'Squid started successfully', 'success');
        } else {
          const errMsg = (res.result && res.result.error) || res.message || 'Reload encountered an issue';
          showToast(errMsg, 'error');
        }
      } catch (e) {
        showToast(e.message || 'Reload trigger failed', 'error');
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<i class="fa-solid fa-rotate"></i>';
        }
        await refreshStatus();
      }
    }

    async function copyPublicIp() {
      const ip = document.getElementById('headerPublicIp').textContent;
      await copyToClipboard(ip);
      showToast(`Copied IP: ${ip}`, 'info');
    }

    async function copyConnectionString(username, dedicatedPort = 0) {
      const host = (currentStatus && currentStatus.network.public_ip) || '0.0.0.0';
      const port = dedicatedPort || (currentStatus && currentStatus.network.proxy_port) || 3128;
      const str = `http://${username}:YOUR_PASSWORD@${host}:${port}`;
      await copyToClipboard(str);
      showToast(`Copied: ${str}`, 'success');
    }

    function togglePasswordVisibility(id) {
      const el = document.getElementById(id);
      el.type = el.type === 'password' ? 'text' : 'password';
    }

    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      
      let bg = 'bg-dark-850 border-slate-700 text-slate-200';
      let icon = '<i class="fa-solid fa-circle-info text-blue-400"></i>';
      
      if (type === 'success') {
        bg = 'bg-dark-850 border-emerald-500/40 text-white shadow-lg shadow-emerald-500/10';
        icon = '<i class="fa-solid fa-circle-check text-emerald-400"></i>';
      } else if (type === 'error') {
        bg = 'bg-dark-850 border-rose-500/40 text-white shadow-lg shadow-rose-500/10';
        icon = '<i class="fa-solid fa-circle-exclamation text-rose-400"></i>';
      }

      toast.className = `pointer-events-auto flex items-center gap-2.5 px-4 py-3 rounded-xl border text-sm shadow-xl transition-all transform duration-300 translate-y-2 opacity-0 ${bg}`;
      toast.innerHTML = `${icon} <span class="font-medium">${escapeHtml(message)}</span>`;
      
      container.appendChild(toast);
      setTimeout(() => toast.classList.remove('translate-y-2', 'opacity-0'), 10);
      setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-2');
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the single-page admin application."""
    return HTMLResponse(content=DASHBOARD_HTML, status_code=200)


# ------------------------------------------------------------------------------
# Server Entry Point
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    ensure_squid_conf_structure()
    ensure_squid_startup_service()
    logger.info(f"Starting SquidMan Management Panel on http://{PANEL_HOST}:{PANEL_PORT}")
    logger.info(f"Squid Config: {SQUID_CONF_PATH}")
    logger.info(f"Outgoing IPs Config: {SQUID_OUTGOING_IPS_PATH}")
    logger.info(f"Proxy Port: {PROXY_PORT}")
    uvicorn.run(app, host=PANEL_HOST, port=PANEL_PORT)
