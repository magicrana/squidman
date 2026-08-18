#!/usr/bin/env bash
# ==============================================================================
# SquidMan & Squid Proxy Server Complete Uninstaller
# Target OS: Ubuntu 20.04 / 22.04 / 24.04 & Debian 11 / 12
# Usage:
#   sudo ./uninstall.sh [-y] [--purge]
#   or remote:
#   curl -sSL https://your-server.com/uninstall.sh | sudo bash -s -- -y --purge
# ==============================================================================

set -eo pipefail

# Visual Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "=============================================================================="
echo "      Squid Proxy Server & Management Panel Complete Uninstaller              "
echo "=============================================================================="
echo -e "${NC}"

# 1. Root privilege check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This script must be run as root (use sudo).${NC}" 
   exit 1
fi

AUTO_CONFIRM=false
PURGE_PACKAGES=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes|-f|--force)
            AUTO_CONFIRM=true
            ;;
        --purge)
            PURGE_PACKAGES=true
            ;;
        --help|-h)
            echo "Usage: sudo ./uninstall.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -y, --yes      Non-interactive mode (auto-confirm all prompts)"
            echo "  --purge        Purge Squid and Apache utils apt packages completely"
            echo "  -h, --help     Show this help message"
            exit 0
            ;;
    esac
done

if [[ "$AUTO_CONFIRM" != true ]]; then
    echo -e "${YELLOW}[WARNING] This will completely remove SquidMan Management Panel,"
    echo -e "          stop services, and remove all user accounts, IP pools & configs.${NC}"
    echo ""
    read -rp "Are you sure you want to proceed with uninstallation? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "${BLUE}[INFO] Uninstallation cancelled.${NC}"
        exit 0
    fi

    if [[ "$PURGE_PACKAGES" != true ]]; then
        read -rp "Do you also want to purge Squid engine & dependencies from apt? [y/N]: " PURGE_CONFIRM
        if [[ "$PURGE_CONFIRM" =~ ^[yY]([eE][sS])?$ ]]; then
            PURGE_PACKAGES=true
        fi
    fi
fi

INSTALL_DIR="/opt/squid-panel"
SQUID_CONF_DIR="/etc/squid"
SYSTEMD_SERVICE="/etc/systemd/system/squid-panel.service"

# 2. Stop and Disable Systemd Services
echo -e "${BLUE}[1/6] Stopping and disabling services...${NC}"
if systemctl is-active --quiet squid-panel 2>/dev/null; then
    systemctl stop squid-panel 2>/dev/null || true
    echo -e "${GREEN}[OK] Stopped squid-panel service.${NC}"
fi
systemctl disable squid-panel 2>/dev/null || true

if systemctl is-active --quiet squid 2>/dev/null; then
    systemctl stop squid 2>/dev/null || true
    echo -e "${GREEN}[OK] Stopped squid service.${NC}"
fi
systemctl disable squid 2>/dev/null || true

# Remove systemd service unit
if [[ -f "${SYSTEMD_SERVICE}" ]]; then
    rm -f "${SYSTEMD_SERVICE}"
    systemctl daemon-reload 2>/dev/null || true
    echo -e "${GREEN}[OK] Removed systemd service unit.${NC}"
fi

# 3. Clean Up Secondary IPs (if recorded in metadata)
echo -e "${BLUE}[2/6] Cleaning up secondary network interface IP bindings...${NC}"
INTERFACES_META="${INSTALL_DIR}/data/interfaces_meta.json"
if [[ -f "${INTERFACES_META}" ]] && command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, subprocess, os
meta_path = '${INTERFACES_META}'
try:
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    for key, val in meta.items():
        iface = val.get('interface')
        ip = val.get('ip')
        cidr = val.get('cidr', 32)
        if iface and ip:
            ip_cidr = f'{ip}/{cidr}'
            subprocess.run(['ip', 'addr', 'del', ip_cidr, 'dev', iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            conn_res = subprocess.run(['nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', iface], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            conn_name = conn_res.stdout.strip() if conn_res.returncode == 0 else iface
            if conn_name and conn_name != '--':
                subprocess.run(['nmcli', 'connection', 'modify', conn_name, '-ipv4.addresses', ip_cidr], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(['nmcli', 'connection', 'up', conn_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except Exception:
    pass
" 2>/dev/null || true
    echo -e "${GREEN}[OK] Unbound secondary IP addresses.${NC}"
fi

# 4. Remove Firewall (UFW) Rules
echo -e "${BLUE}[3/6] Cleaning up firewall (UFW) rules...${NC}"
if command -v ufw >/dev/null 2>&1; then
    # Remove default proxy and panel ports
    ufw delete allow 3128/tcp 2>/dev/null || true
    ufw delete allow 8080/tcp 2>/dev/null || true

    # Remove any dedicated port rules recorded in metadata
    PORTS_META="${INSTALL_DIR}/data/ports_meta.json"
    if [[ -f "${PORTS_META}" ]] && command -v python3 >/dev/null 2>&1; then
        python3 -c "
import json, subprocess
ports_path = '${PORTS_META}'
try:
    with open(ports_path, 'r', encoding='utf-8') as f:
        ports = json.load(f)
    for ip, port in ports.items():
        if port and port != 3128:
            subprocess.run(['ufw', 'delete', 'allow', f'{port}/tcp'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except Exception:
    pass
" 2>/dev/null || true
    fi
    echo -e "${GREEN}[OK] Removed proxy firewall rules.${NC}"
fi

# 5. Remove Application Files & Metadata
echo -e "${BLUE}[4/6] Removing SquidMan application files and virtual environment...${NC}"
if [[ -d "${INSTALL_DIR}" ]]; then
    rm -rf "${INSTALL_DIR}"
    echo -e "${GREEN}[OK] Deleted ${INSTALL_DIR}${NC}"
fi

# 6. Remove Squid Configurations & Caches
echo -e "${BLUE}[5/6] Removing Squid proxy configuration and credentials...${NC}"
rm -f "${SQUID_CONF_DIR}/users.pwd" "${SQUID_CONF_DIR}/allowed_ips.txt" "${SQUID_CONF_DIR}/outgoing_ips.conf"
rm -f "${SQUID_CONF_DIR}/squid.conf" "${SQUID_CONF_DIR}"/squid.conf.backup.*

# Clean up log and spool directories
rm -rf /var/log/squid/* 2>/dev/null || true
rm -rf /var/spool/squid/* 2>/dev/null || true
echo -e "${GREEN}[OK] Cleaned up Squid configuration and log files.${NC}"

# 7. Optional Package Purge
if [[ "$PURGE_PACKAGES" == true ]]; then
    echo -e "${BLUE}[6/6] Purging Squid packages via apt...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y -qq squid squid-common apache2-utils 2>/dev/null || true
    apt-get autoremove -y -qq 2>/dev/null || true
    rm -rf "${SQUID_CONF_DIR}" 2>/dev/null || true
    echo -e "${GREEN}[OK] Purged Squid and apache2-utils packages.${NC}"
else
    echo -e "${BLUE}[6/6] Keeping base packages (use --purge to remove apt packages).${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo -e "${GREEN}${BOLD}       SQUIDMAN PROXY SERVER UNINSTALLED SUCCESSFULLY!                       ${NC}"
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo -e " ${BOLD}Summary:${NC}"
echo -e "   - Systemd services stopped & removed (${CYAN}squid-panel${NC}, ${CYAN}squid${NC})"
echo -e "   - Application directory deleted (${CYAN}${INSTALL_DIR}${NC})"
echo -e "   - Proxy credentials & IP pool ACL configurations removed"
echo -e "   - Firewall rules cleaned up"
if [[ "$PURGE_PACKAGES" == true ]]; then
    echo -e "   - Squid software packages purged from system"
fi
echo ""
echo -e "${GREEN}System is completely clean.${NC}"
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
