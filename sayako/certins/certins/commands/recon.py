from certins.base import SECRETS_DIR
import os
import subprocess
import sys

# Embedded recon script
RECON_SCRIPT = r'''#!/bin/bash
# AWD Server Recon Script - Embedded Version
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

header() { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"; echo -e "${GREEN}▶ $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
good() { echo -e "${GREEN}[+]${NC} $1"; }

header "AWD SERVER RECON"
echo "Time: $(date)"
echo "Host: $(hostname)"
echo "User: $(whoami)"

header "NETWORK - LISTENING PORTS"
info "External TCP ports (challenge services):"
ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | grep LISTEN | awk '{print $4, $6}' | column -t || netstat -tlnp 2>/dev/null | grep LISTEN || true

header "XINETD / SOCAT SERVICES"
info "Xinetd configs:"
if [ -d /etc/xinetd.d ]; then
    for f in /etc/xinetd.d/*; do
        [ -f "$f" ] && echo -e "\n${YELLOW}=== $f ===${NC}" && cat "$f"
    done
fi
[ -f /etc/xinetd.conf ] && echo -e "\n${YELLOW}=== /etc/xinetd.conf ===${NC}" && cat /etc/xinetd.conf 2>/dev/null || true
[ -f /etc/inetd.conf ] && echo -e "\n${YELLOW}=== /etc/inetd.conf ===${NC}" && cat /etc/inetd.conf 2>/dev/null || true
info "Socat/ncat:"
ps aux 2>/dev/null | grep -E "(socat|ncat|nc )" | grep -v grep || true

header "RUNNING SERVICES"
info "Challenge processes:"
ps aux 2>/dev/null | grep -E "(python|node|java|ruby|php|flask|django|nginx|apache|mysql|postgres|redis)" | grep -v grep | awk '{print $1, $2, $11, $12, $13}' | head -20 || true

info "Processes with ports:"
for pid in $(ss -tlnp 2>/dev/null | grep -oP 'pid=\K\d+' | sort -u); do
    [ -d "/proc/$pid" ] && cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 80) && port=$(ss -tlnp 2>/dev/null | grep "pid=$pid" | awk '{print $4}' | head -1) && [ -n "$cmd" ] && echo "  PID $pid ($port): $cmd"
done 2>/dev/null | head -15

header "CHALLENGE BINARIES"
info "Setuid binaries:"
find / -perm -4000 -type f 2>/dev/null | grep -v -E "(proc|sys|snap|usr/bin)" | head -10 || true

info "ELF binaries in challenge locations:"
find /home /opt /app /srv /challenge -type f -executable 2>/dev/null | head -20 | while read f; do
    file "$f" 2>/dev/null | grep -qi "elf" && echo "  $f"
done || true

header "FLAG LOCATIONS"
info "Flag files:"
find / -name "*flag*" -type f 2>/dev/null | grep -v -E "(proc|sys)" | head -15 || true
for f in /flag /flag.txt /home/*/flag* /root/flag* /app/flag*; do
    [ -f "$f" ] && good "FOUND: $f" && head -c 100 "$f" 2>/dev/null && echo ""
done 2>/dev/null || true

header "SOURCE CODE"
info "Application files:"
find /home /opt /var/www /app /srv -maxdepth 4 \( -name "*.py" -o -name "*.js" -o -name "*.php" -o -name "*.c" -o -name "Dockerfile" \) 2>/dev/null | grep -v -E "(node_modules|__pycache__|\.pyc)" | head -25 || true

header "WEB SERVICES"
info "Web configs:"
ls -la /etc/nginx/sites-enabled/ /etc/apache2/sites-enabled/ 2>/dev/null || true
info "Web roots:"
for d in /var/www /var/www/html /opt /home/*/app /app; do [ -d "$d" ] && echo "  $d: $(ls $d 2>/dev/null | head -5 | tr '\n' ' ')"; done 2>/dev/null || true

header "DOCKER"
docker ps 2>/dev/null || info "Docker not available/accessible"
[ -f /.dockerenv ] && warn "Running inside container"

header "CRON (Flag rotation)"
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$" || true
crontab -l 2>/dev/null || true

header "WRITABLE LOCATIONS"
info "Writable dirs:"
find /var/www /opt /home /app /srv -writable -type d 2>/dev/null | grep -v -E "(cache|log|tmp|__pycache__|node_modules)" | head -15 || true

header "DATABASES"
ps aux 2>/dev/null | grep -E "(mysql|postgres|mongo|redis)" | grep -v grep || true
find / -name "*.db" -o -name "*.sqlite*" 2>/dev/null | grep -v proc | head -10 || true

header "SECRETS"
env | grep -iE "(flag|secret|key|pass|token|api|db)" 2>/dev/null || true
for f in /home/*/.env /opt/*/.env /app/.env; do [ -f "$f" ] && warn ".env: $f"; done 2>/dev/null || true

header "SUMMARY"
echo -e "${YELLOW}Ports:${NC}"
ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | grep LISTEN | awk '{print "  " $4}' | sort -u || true
echo -e "${YELLOW}Processes:${NC}"
ps aux 2>/dev/null | grep -E "(python|node|java|php)" | grep -v grep | awk '{print "  " $2 ": " $11}' | head -5 || true
good "Recon complete!"
'''


def run_recon(tag, config_data, quick=False):
    """Run recon script on remote server."""
    host = config_data['host']
    pem_filename = config_data['pem_file']
    pem_path = os.path.join(SECRETS_DIR, pem_filename)
    
    if not os.path.exists(pem_path):
        print(f"Error: Key file missing at {pem_path}")
        sys.exit(1)
    
    print(f"\n[*] Running recon on {host}...")
    
    if quick:
        # Quick mode - just essential info
        quick_cmd = '''
echo "=== PORTS ===" && ss -tlnp 2>/dev/null | grep LISTEN
echo "=== XINETD ===" && cat /etc/xinetd.d/* 2>/dev/null
echo "=== PROCESSES ===" && ps aux | grep -E "(python|node|java|php)" | grep -v grep
echo "=== FLAGS ===" && find / -name "*flag*" -type f 2>/dev/null | grep -v proc | head -10
'''
        cmd = ["ssh", "-i", pem_path, "-o", "StrictHostKeyChecking=no", host, quick_cmd]
    else:
        # Full recon
        cmd = ["ssh", "-i", pem_path, "-o", "StrictHostKeyChecking=no", host, "bash -s"]
    
    try:
        if quick:
            subprocess.run(cmd)
        else:
            # Pipe the script to bash
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                text=True
            )
            process.communicate(input=RECON_SCRIPT)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def run_exec(tag, config_data, command):
    """Execute a command on remote server."""
    host = config_data['host']
    pem_filename = config_data['pem_file']
    pem_path = os.path.join(SECRETS_DIR, pem_filename)
    
    if not os.path.exists(pem_path):
        print(f"Error: Key file missing at {pem_path}")
        sys.exit(1)
    
    cmd = ["ssh", "-i", pem_path, "-o", "StrictHostKeyChecking=no", host, command]
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
