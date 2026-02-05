#!/bin/bash
# AWD Server Recon Script
# Run this on the challenge server to quickly understand the environment
# Usage: curl -s URL | bash  OR  ./recon.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

header() { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"; echo -e "${GREEN}▶ $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
good() { echo -e "${GREEN}[+]${NC} $1"; }
bad() { echo -e "${RED}[-]${NC} $1"; }

header "AWD SERVER RECON"
echo "Time: $(date)"
echo "Host: $(hostname)"
echo "User: $(whoami)"

# ============================================
header "NETWORK - LISTENING PORTS"
# ============================================
info "TCP ports listening (likely challenge services):"
if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | grep LISTEN | awk '{print $4, $6}' | column -t || true
elif command -v netstat &>/dev/null; then
    netstat -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | grep LISTEN | awk '{print $4, $7}' | column -t || true
fi

echo ""
info "All listening ports (including localhost):"
ss -tlnp 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN || true

# ============================================
header "RUNNING SERVICES (Interesting)"
# ============================================
info "Services likely to be challenges:"
ps aux 2>/dev/null | grep -E "(python|node|java|ruby|php|flask|django|express|spring|nginx|apache|httpd|mysql|postgres|redis|mongo)" | grep -v grep | awk '{print $1, $2, $11, $12, $13}' | head -20 || true

echo ""
info "Processes with open ports:"
for pid in $(ss -tlnp 2>/dev/null | grep -oP 'pid=\K\d+' | sort -u); do
    if [ -d "/proc/$pid" ]; then
        cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 80)
        port=$(ss -tlnp 2>/dev/null | grep "pid=$pid" | awk '{print $4}' | head -1)
        [ -n "$cmd" ] && echo "  PID $pid ($port): $cmd"
    fi
done 2>/dev/null | head -15

# ============================================
header "WEB SERVICES"
# ============================================
info "Web server configs:"
for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf; do
    [ -f "$conf" ] && echo "  Found: $conf"
done 2>/dev/null || true

info "Web roots (common locations):"
for dir in /var/www /var/www/html /opt /home/*/app /home/*/web /app /srv; do
    [ -d "$dir" ] && echo "  $dir: $(ls $dir 2>/dev/null | head -5 | tr '\n' ' ')"
done 2>/dev/null || true

# ============================================
header "FLAG LOCATIONS"
# ============================================
info "Searching for flag files..."
find / -name "*flag*" -type f 2>/dev/null | grep -v proc | grep -v sys | head -20 || true

info "Checking common flag locations:"
for f in /flag /flag.txt /home/*/flag* /root/flag* /var/flag* /opt/*/flag* /app/flag*; do
    [ -f "$f" ] && good "FOUND: $f" && head -c 100 "$f" 2>/dev/null && echo ""
done 2>/dev/null || true

# ============================================
header "CHALLENGE SOURCE CODE"
# ============================================
info "Looking for application code..."
find /home /opt /var/www /app /srv -maxdepth 4 \( -name "*.py" -o -name "*.js" -o -name "*.php" -o -name "*.rb" -o -name "*.java" -o -name "*.c" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null | grep -v node_modules | grep -v __pycache__ | grep -v ".pyc" | head -30 || true

# ============================================
header "DOCKER / CONTAINERS"
# ============================================
if command -v docker &>/dev/null; then
    info "Docker containers:"
    docker ps 2>/dev/null || warn "Cannot access docker"
    
    info "Docker images:"
    docker images 2>/dev/null | head -10 || true
else
    info "Docker not available"
fi

# Check if we're in a container
if [ -f /.dockerenv ]; then
    warn "Running inside Docker container"
fi

# ============================================
header "CRON JOBS (Flag rotation?)"
# ============================================
info "System cron:"
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$" || true
ls -la /etc/cron.d/ 2>/dev/null || true

info "User cron:"
crontab -l 2>/dev/null || true

# ============================================
header "WRITABLE LOCATIONS"
# ============================================
info "World-writable directories (for backdoors):"
find / -type d -perm -0002 2>/dev/null | grep -v -E "(proc|sys|tmp|dev|run)" | head -10 || true

info "Writable by current user:"
find /var/www /opt /home /app /srv -writable 2>/dev/null | grep -v -E "(cache|log|tmp|__pycache__|node_modules)" | head -20 || true

# ============================================
header "DATABASES"
# ============================================
info "Database services:"
ps aux 2>/dev/null | grep -E "(mysql|postgres|mongo|redis|sqlite)" | grep -v grep || true

info "Database files:"
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | grep -v proc | head -10 || true

# ============================================
header "ENVIRONMENT & SECRETS"
# ============================================
info "Environment variables (filtered):"
env | grep -iE "(flag|secret|key|pass|token|api|database|db_)" 2>/dev/null || true

info "Config files with secrets:"
for f in /home/*/.env /opt/*/.env /var/www/*/.env /app/.env .env; do
    [ -f "$f" ] && warn "Found .env: $f"
done 2>/dev/null || true

# ============================================
header "QUICK SYSTEM INFO"
# ============================================
info "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -a)"
info "Kernel: $(uname -r)"
info "Architecture: $(uname -m)"

# ============================================
header "SUMMARY - KEY ATTACK SURFACES"
# ============================================
echo -e "${YELLOW}Ports to target:${NC}"
ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | grep LISTEN | awk '{print "  " $4}' | sort -u || true

echo -e "\n${YELLOW}Interesting processes:${NC}"
ps aux 2>/dev/null | grep -E "(python|node|java|ruby|php)" | grep -v grep | awk '{print "  PID " $2 ": " $11 " " $12}' | head -5 || true

echo -e "\n${YELLOW}Likely source code:${NC}"
find /home /opt /var/www /app -maxdepth 3 -name "*.py" -o -name "app.js" -o -name "index.php" -o -name "main.c" 2>/dev/null | head -5 || true

echo ""
good "Recon complete! Review above for attack vectors."
