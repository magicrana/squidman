#!/usr/bin/env bash
# ==============================================================================
# SquidMan &bull; High-Anonymity Production Proxy & Panel Installer
# Target OS: Ubuntu 20.04 / 22.04 / 24.04 & Debian 11 / 12
# Usage (Remote 1-Liner):
#   curl -sSL https://raw.githubusercontent.com/magicrana/squidman/main/setup.sh | sudo bash
# ==============================================================================

set -eo pipefail

# Visual Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GREY='\033[0;90m'
LIGHTGREY='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${GREEN}${BOLD}"
echo "=========================================================================================="
echo "  ███████╗ ██████╗ ██╗   ██╗██╗██████╗ ███╗   ███╗ █████╗ ███╗   ██╗"
echo "  ██╔════╝██╔═══██╗██║   ██║██║██╔══██╗████╗ ████║██╔══██╗████╗  ██║"
echo "  ███████╗██║   ██║██║   ██║██║██║  ██║██╔████╔██║███████║██╔██╗ ██║"
echo "  ╚════██║██║▄▄ ██║██║   ██║██║██║  ██║██║╚██╔╝██║██╔══██║██║╚██╗██║"
echo "  ███████║╚██████╔╝╚██████╔╝██║██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║"
echo "  ╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝"
echo "=========================================================================================="
echo "                           SquidMan Server & Panel Installer                              "
echo "=========================================================================================="
echo -e "${NC}"

# 1. Root privilege check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This script must be run as root (use sudo).${NC}" 
   exit 1
fi

INSTALL_DIR="/opt/squid-panel"
SQUID_CONF_DIR="/etc/squid"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "/tmp")"

GITHUB_REPO="${GITHUB_REPO:-magicrana/squidman}"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
RAW_BASE_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}"
TARBALL_URL="https://github.com/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.tar.gz"

echo -e "${LIGHTGREY}[1/9] Installing system dependencies (Squid, Apache2 utils, Python 3, NetworkManager, UFW)...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -qq
apt-get install -y --no-install-recommends -qq \
    squid \
    apache2-utils \
    network-manager \
    iproute2 \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    tar \
    unzip \
    ufw \
    openssl \
    ca-certificates \
    procps

# 2. Detect basic_ncsa_auth binary path
echo -e "${LIGHTGREY}[2/9] Detecting Squid Basic Auth helper binary...${NC}"
AUTH_HELPER=""
CANDIDATES=(
    "/usr/lib/squid/basic_ncsa_auth"
    "/usr/lib64/squid/basic_ncsa_auth"
    "/usr/lib/squid3/basic_ncsa_auth"
    "/usr/libexec/squid/basic_ncsa_auth"
)

for path in "${CANDIDATES[@]}"; do
    if [[ -f "$path" && -x "$path" ]]; then
        AUTH_HELPER="$path"
        break
    fi
done

if [[ -z "$AUTH_HELPER" ]]; then
    FOUND_PATH=$(find /usr -name "basic_ncsa_auth" 2>/dev/null | head -n 1 || true)
    if [[ -n "$FOUND_PATH" && -x "$FOUND_PATH" ]]; then
        AUTH_HELPER="$FOUND_PATH"
    fi
fi

if [[ -z "$AUTH_HELPER" ]]; then
    echo -e "${YELLOW}[WARNING] basic_ncsa_auth not found in default paths. Fallback to /usr/lib/squid/basic_ncsa_auth.${NC}"
    AUTH_HELPER="/usr/lib/squid/basic_ncsa_auth"
else
    echo -e "${GREEN}[OK] Found auth helper: ${AUTH_HELPER}${NC}"
fi

# 3. Prepare Directories
echo -e "${LIGHTGREY}[3/9] Creating application directories...${NC}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/data"
mkdir -p "${SQUID_CONF_DIR}"

# 4. Initialize Squid Auth, IP Whitelist, and Outgoing IP routing storage
echo -e "${LIGHTGREY}[4/9] Initializing Squid ACL and routing storage files...${NC}"
touch "${SQUID_CONF_DIR}/users.pwd"
if [[ ! -s "${SQUID_CONF_DIR}/allowed_ips.txt" ]]; then
    echo -e "# Whitelisted client IPs\n127.0.0.1/32" > "${SQUID_CONF_DIR}/allowed_ips.txt"
fi

if [[ ! -f "${SQUID_CONF_DIR}/outgoing_ips.conf" ]]; then
    cat <<'OUTGOING_EOF' > "${SQUID_CONF_DIR}/outgoing_ips.conf"
# ==============================================================================
# Dedicated Outgoing IP Mappings (tcp_outgoing_address)
# Managed dynamically by SquidMan Proxy Panel
# ==============================================================================
OUTGOING_EOF
fi

# Squid system user detection
SQUID_USER="proxy"
if id "squid" &>/dev/null; then
    SQUID_USER="squid"
elif id "proxy" &>/dev/null; then
    SQUID_USER="proxy"
fi

chown root:"${SQUID_USER}" "${SQUID_CONF_DIR}/users.pwd" "${SQUID_CONF_DIR}/allowed_ips.txt" "${SQUID_CONF_DIR}/outgoing_ips.conf"
chmod 640 "${SQUID_CONF_DIR}/users.pwd" "${SQUID_CONF_DIR}/allowed_ips.txt" "${SQUID_CONF_DIR}/outgoing_ips.conf"

# 5. Deploy Latest Application Source Files to /opt/squid-panel (Live GitHub Fetch or Local Copy)
echo -e "${LIGHTGREY}[5/9] Deploying latest SquidMan source files to ${INSTALL_DIR}...${NC}"

if [[ -f "${SCRIPT_DIR}/server.py" && -f "${SCRIPT_DIR}/squid.conf.template" && "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]]; then
    echo -e "${GREEN}[INFO] Deploying from local directory (${SCRIPT_DIR})...${NC}"
    cp -u "${SCRIPT_DIR}/server.py" "${INSTALL_DIR}/" 2>/dev/null || cp "${SCRIPT_DIR}/server.py" "${INSTALL_DIR}/"
    cp -u "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/" 2>/dev/null || cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
    cp -u "${SCRIPT_DIR}/squid.conf.template" "${INSTALL_DIR}/" 2>/dev/null || cp "${SCRIPT_DIR}/squid.conf.template" "${INSTALL_DIR}/"
    cp -u "${SCRIPT_DIR}/squid-panel.service" "${INSTALL_DIR}/" 2>/dev/null || cp "${SCRIPT_DIR}/squid-panel.service" "${INSTALL_DIR}/"
    cp -u "${SCRIPT_DIR}/uninstall.sh" "${INSTALL_DIR}/" 2>/dev/null || cp "${SCRIPT_DIR}/uninstall.sh" "${INSTALL_DIR}/" || true
    cp -u "${SCRIPT_DIR}/setup.sh" "${INSTALL_DIR}/" 2>/dev/null || cp "${SCRIPT_DIR}/setup.sh" "${INSTALL_DIR}/" || true
else
    echo -e "${PURPLE}[INFO] Downloading latest live files from GitHub (${CYAN}${GITHUB_REPO}@${GITHUB_BRANCH}${BLUE})...${NC}"
    
    # Try downloading full repo tarball first for speed & atomic unpack
    TARBALL_FETCHED=false
    if curl -sSL -f -m 15 "${TARBALL_URL}" -o /tmp/squidman-live.tar.gz 2>/dev/null && [[ -s /tmp/squidman-live.tar.gz ]]; then
        if tar -xzf /tmp/squidman-live.tar.gz --strip-components=1 -C "${INSTALL_DIR}" 2>/dev/null; then
            TARBALL_FETCHED=true
            echo -e "${GREEN}[OK] Successfully unpacked latest live repository files.${NC}"
        fi
        rm -f /tmp/squidman-live.tar.gz
    fi

    # Fallback to individual file raw fetch if tarball was not used
    if [[ "$TARBALL_FETCHED" != true ]]; then
        FILES=("server.py" "squid.conf.template" "requirements.txt" "squid-panel.service" "uninstall.sh" "setup.sh")
        for file in "${FILES[@]}"; do
            echo -e "${GREY} - Fetching ${file}...${NC}"
            curl -sSL -f -m 10 "${RAW_BASE_URL}/${file}" -o "${INSTALL_DIR}/${file}"
        done
        echo -e "${GREEN}[OK] All live files downloaded.${NC}"
    fi
fi

chmod +x "${INSTALL_DIR}/setup.sh" "${INSTALL_DIR}/uninstall.sh" 2>/dev/null || true

# 6. Deploy Squid Configuration
echo -e "${LIGHTGREY}[6/9] Deploying high-anonymity Squid configuration...${NC}"
if [[ -f "${SQUID_CONF_DIR}/squid.conf" ]]; then
    cp "${SQUID_CONF_DIR}/squid.conf" "${SQUID_CONF_DIR}/squid.conf.backup.$(date +%s)"
fi

sed "s|__AUTH_HELPER_PATH__|${AUTH_HELPER}|g" "${INSTALL_DIR}/squid.conf.template" > "${SQUID_CONF_DIR}/squid.conf"

# 7. Generate API Key & .env
echo -e "${LIGHTGREY}[7/9] Configuring master credentials & environment...${NC}"
if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
    GENERATED_KEY=$(openssl rand -hex 16)
    cat <<EOF > "${INSTALL_DIR}/.env"
# Squid Management Panel Configuration
API_KEY=${GENERATED_KEY}
SQUID_CONF_PATH=/etc/squid/squid.conf
SQUID_USERS_PATH=/etc/squid/users.pwd
SQUID_ALLOWED_IPS_PATH=/etc/squid/allowed_ips.txt
SQUID_OUTGOING_IPS_PATH=/etc/squid/outgoing_ips.conf
PANEL_HOST=0.0.0.0
PANEL_PORT=8080
PROXY_PORT=3128
EOF
    echo -e "${GREEN}[OK] Generated new Master API Key in ${INSTALL_DIR}/.env${NC}"
else
    echo -e "${YELLOW}[NOTE] Existing .env file detected, preserving current API Key.${NC}"
    GENERATED_KEY=$(grep -E "^API_KEY=" "${INSTALL_DIR}/.env" | cut -d '=' -f2- || echo "custom-key")
fi

# 8. Set Up Python Virtual Environment
echo -e "${BLUE}[8/9] Setting up Python virtual environment & installing dependencies...${NC}"
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip --quiet
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet

# 9. Configure Systemd Service & Firewall
echo -e "${LIGHTGREY}[9/9] Installing systemd service unit & enabling startup daemons...${NC}"
cp "${INSTALL_DIR}/squid-panel.service" /etc/systemd/system/squid-panel.service
systemctl daemon-reload

if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp comment 'SSH' 2>/dev/null || true
    ufw allow 3128/tcp comment 'Squid Proxy' 2>/dev/null || true
    ufw allow 8080/tcp comment 'Squid Web Panel' 2>/dev/null || true
fi

# Enable and Start Services
systemctl unmask NetworkManager 2>/dev/null || true
systemctl unmask squid 2>/dev/null || true
systemctl unmask squid-panel 2>/dev/null || true

systemctl enable --now NetworkManager 2>/dev/null || true

systemctl reset-failed squid 2>/dev/null || true
squid -z 2>/dev/null || true
systemctl enable squid.service 2>/dev/null || systemctl enable squid 2>/dev/null || true
systemctl restart squid

systemctl enable squid-panel.service 2>/dev/null || systemctl enable squid-panel 2>/dev/null || true
systemctl restart squid-panel

# Service Verification
sleep 2
SQUID_STATUS=$(systemctl is-active squid || true)
PANEL_STATUS=$(systemctl is-active squid-panel || true)

# Detect Public IP
PUBLIC_IP=$(curl -s -m 3 https://api.ipify.org || curl -s -m 3 https://icanhazip.com || hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo -e "${GREEN}${BOLD}       SQUIDMAN SERVER & MANAGEMENT PANEL INSTALLED SUCCESSFULLY!          ${NC}"
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
echo ""
echo -e " ${BOLD}Service Status:${NC}"
echo -e "   - Squid Proxy Engine:   ${GREEN}${SQUID_STATUS}${NC} (Port 3128)"
echo -e "   - Management Dashboard: ${GREEN}${PANEL_STATUS}${NC} (Port 8080)"
echo ""
echo -e " ${BOLD}Access Details:${NC}"
echo -e "   - Server Public IP:     ${CYAN}${PUBLIC_IP}${NC}"
echo -e "   - Web Dashboard URL:    ${GREEN}http://${PUBLIC_IP}:8080/?api_key=${GENERATED_KEY}${NC}"
echo -e "   - Master API Key:       ${YELLOW}${BOLD}${GENERATED_KEY}${NC}"
echo ""
echo -e " ${BOLD}Default Proxy Endpoints:${NC}"
echo -e "   - HTTP/HTTPS Proxy:     ${CYAN}http://${PUBLIC_IP}:3128${NC}"
echo ""
echo -e " ${BOLD}Features Enabled:${NC}"
echo -e "   - Dynamic Secondary IP Management (via nmcli / iproute2)"
echo -e "   - Dedicated Per-User Outbound Routing (via tcp_outgoing_address)"
echo -e "   - Dual ACL Layer (bcrypt htpasswd + IP Whitelisting)"
echo ""
echo -e " ${BOLD}Quick Test Commands:${NC}"
echo -e "   - Connect via proxy:"
echo -e "     ${PURPLE}curl -x http://testuser:secretpass123@${PUBLIC_IP}:3128 https://httpbin.org/ip${NC}"
echo ""
echo -e "${GREEN}${BOLD}==============================================================================${NC}"
