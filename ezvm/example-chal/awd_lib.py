#!/usr/bin/env python3
"""
AWD CTF Helper Library
======================
Simple utilities for Attack-Defense CTF competitions.

Usage:
    from awd_lib import *

    # Setup (do once at start)
    setup_auth()
    discord.configure("192.168.1.100", 4545)  # Optional: Discord logging

    # Get targets and exploit
    for ip in targets():
        flag = exploit(ip, PORT)
        if flag:
            submit(flag)  # Auto-logs to Discord if configured

    # Discord logging (pwntools-style)
    discord.info("Starting exploit round")
    discord.success("Got shell!", target=ip)
    discord.flag("Flag captured!", flag=flag, target=ip, points=100)
    discord.attack("SQL injection detected", payload="' OR 1=1--")
    discord.error("Exploit failed", target=ip)
"""

import os
import stat
import re
import sys
import json
import traceback
from typing import Optional, Dict, Any, List, Union
from functools import wraps

try:
    import requests
except ImportError:
    print("Warning: requests not installed. Run: pip install requests")
    requests = None

# === CONFIGURATION ===
# Update these for each competition

API_URL = "https://platform.ctf.hkcert.org/api/ct/web/awd_race/race/4734afdc0363e27749622afa758db50c/flag/robot/"
TOKEN = "6b1b78422325c363704038b207cb8c31"

# Path to credentials file (CSV or XLSX)
CREDS_FILE = "mqda.csv"  # or "mqda.xlsx"

# PEM file settings
PEM_URL = "http://10.30.16.251:80/ct/upload/other/pvt-ctf-546ad20ed70bd27645a8734f6ae1fbe1.pem"
PEM_FILE = "auth.pem"

# === END CONFIGURATION ===


def chal(
    creds_file: str = None,
    api_url: str = None,
    token: str = None,
    pem_url: str = None,
    pem_file: str = None,
    discord_host: str = None,
    discord_port: int = None,
):
    """
    Configure the challenge settings. Call this at the start of your exploit.
    
    Args:
        creds_file: Path to credentials CSV/XLSX file
        api_url: Flag submission API URL
        token: API token
        pem_url: URL to download PEM file
        pem_file: Local path for PEM file
        discord_host: Discord logger host
        discord_port: Discord logger port
        
    Returns:
        dict with current config
        
    Example:
        # Simple - just set creds file
        chal("challenge/creds.csv")
        
        # Full config
        chal(
            creds_file="creds.xlsx",
            api_url="https://ctf.example.com/api/flag",
            token="abc123",
            discord_host="192.168.1.100",
            discord_port=4545,
        )
    """
    global CREDS_FILE, API_URL, TOKEN, PEM_URL, PEM_FILE
    
    if creds_file:
        CREDS_FILE = creds_file
    if api_url:
        API_URL = api_url
    if token:
        TOKEN = token
    if pem_url:
        PEM_URL = pem_url
    if pem_file:
        PEM_FILE = pem_file
    
    # Configure discord if provided
    if discord_host or discord_port:
        discord.configure(host=discord_host, port=discord_port)
    
    return {
        "creds_file": CREDS_FILE,
        "api_url": API_URL,
        "token": TOKEN[:8] + "..." if TOKEN else None,
        "pem_url": PEM_URL,
        "pem_file": PEM_FILE,
        "discord": str(discord),
    }

# =============================================================================
# DISCORD LOGGING (pwntools-style)
# =============================================================================

class Discord:
    """
    Discord logging with pwntools-style API.
    
    Usage:
        discord.configure("192.168.1.100", 4545)
        discord.info("Service started")
        discord.success("Flag captured!", flag="CTF{...}")
        discord.attack("SQL injection", payload="...")
        discord.error("Failed", exc=e)
    
    All methods are safe - they won't crash if Discord is unavailable.
    """
    
    def __init__(self):
        self.host = os.getenv("DISCLOG_HOST", "localhost")
        self.port = int(os.getenv("DISCLOG_PORT", "4545"))
        self.default_channel = os.getenv("DISCLOG_CHANNEL", "general")
        self.enabled = False
        self.timeout = 5.0
        self.service = None  # Auto-set from script name
        self._session = None
    
    def configure(
        self,
        host: str = None,
        port: int = None,
        channel: str = None,
        service: str = None,
        enabled: bool = True,
        timeout: float = 5.0,
    ) -> "Discord":
        """
        Configure Discord logging.
        
        Args:
            host: Discord logger server IP/hostname
            port: Server port (default: 4545)
            channel: Default channel name
            service: Service name (default: script filename)
            enabled: Enable/disable logging
            timeout: Request timeout
            
        Returns:
            self for chaining
            
        Example:
            discord.configure("192.168.1.100", 4545, channel="team1")
        """
        if host:
            self.host = host
        if port:
            self.port = port
        if channel:
            self.default_channel = channel
        if service:
            self.service = service
        else:
            # Auto-detect service name from script
            self.service = os.path.basename(sys.argv[0]).replace('.py', '')
        self.enabled = enabled
        self.timeout = timeout
        self._session = None  # Reset session
        return self
    
    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
    
    @property
    def session(self):
        if self._session is None and requests:
            self._session = requests.Session()
            self._session.headers.update({
                "Content-Type": "application/json",
                "User-Agent": "awd_lib/1.0",
            })
        return self._session
    
    def _send(self, channel: str, data: dict) -> bool:
        """Send log to Discord (internal). Returns True on success."""
        if not self.enabled or not requests:
            return False
        
        try:
            url = f"{self.base_url}/{channel}"
            if self.service:
                data.setdefault("service", self.service)
            
            resp = self.session.post(url, json=data, timeout=self.timeout)
            return resp.status_code == 200
        except Exception:
            return False  # Silent fail - don't break exploits
    
    def log(
        self,
        message: str,
        level: str = "info",
        channel: str = None,
        **kwargs
    ) -> bool:
        """
        Send a log message.
        
        Args:
            message: Log message
            level: Log level (debug, info, warn, error, critical, success, attack, flag)
            channel: Target channel (default: self.default_channel)
            **kwargs: Extra fields (team, service, tags, fields, etc.)
        """
        data = {"message": message, "level": level, **kwargs}
        return self._send(channel or self.default_channel, data)
    
    def debug(self, message: str, **kwargs) -> bool:
        """Debug log (gray)."""
        return self.log(message, "debug", **kwargs)
    
    def info(self, message: str, **kwargs) -> bool:
        """Info log (blue)."""
        return self.log(message, "info", **kwargs)
    
    def warn(self, message: str, **kwargs) -> bool:
        """Warning log (orange)."""
        return self.log(message, "warn", **kwargs)
    
    def error(self, message: str, exc: Exception = None, **kwargs) -> bool:
        """
        Error log (red).
        
        Args:
            message: Error message
            exc: Optional exception to include traceback
            **kwargs: Extra fields
        """
        if exc:
            kwargs["exception"] = f"{type(exc).__name__}: {exc}"
            kwargs["traceback"] = traceback.format_exc()
        return self.log(message, "error", **kwargs)
    
    def critical(self, message: str, ping: bool = True, **kwargs) -> bool:
        """Critical log (purple, pings @everyone by default)."""
        if ping:
            kwargs["ping_everyone"] = True
        return self.log(message, "critical", **kwargs)
    
    def success(self, message: str, **kwargs) -> bool:
        """Success log (green). Use for successful exploits, flags, etc."""
        return self.log(message, "success", **kwargs)
    
    def attack(
        self,
        message: str,
        target: str = None,
        payload: str = None,
        channel: str = "attacks",
        **kwargs
    ) -> bool:
        """
        Log an attack detection (bright red).
        
        Args:
            message: Attack description
            target: Target IP/service
            payload: Attack payload
            channel: Channel (default: "attacks")
            **kwargs: Extra fields
        """
        if target:
            kwargs["target"] = target
        if payload:
            kwargs["payload"] = payload
        return self.log(message, "attack", channel=channel, **kwargs)
    
    def flag(
        self,
        message: str,
        flag: str = None,
        target: str = None,
        points: int = None,
        channel: str = "flags",
        **kwargs
    ) -> bool:
        """
        Log a flag event (gold).
        
        Args:
            message: Flag message
            flag: Flag value
            target: Target that was exploited
            points: Points earned
            channel: Channel (default: "flags")
            **kwargs: Extra fields
        """
        fields = kwargs.pop("fields", {})
        if flag:
            fields["flag"] = flag
        if target:
            fields["target"] = target
        if points:
            fields["points"] = points
        if fields:
            kwargs["fields"] = fields
        return self.log(message, "flag", channel=channel, **kwargs)
    
    def pwned(self, target: str, flag: str = None, exploit: str = None, **kwargs) -> bool:
        """
        Convenience method for logging successful pwn.
        
        Args:
            target: Target IP
            flag: Captured flag
            exploit: Exploit name/number
            **kwargs: Extra fields
        """
        msg = f"🎯 Pwned {target}"
        if exploit:
            msg += f" with {exploit}"
        return self.flag(msg, flag=flag, target=target, **kwargs)
    
    def batch(self, entries: List[dict], channel: str = None) -> bool:
        """Send multiple logs at once."""
        if not self.enabled or not requests:
            return False
        
        try:
            url = f"{self.base_url}/{channel or self.default_channel}/batch"
            resp = self.session.post(url, json={"entries": entries}, timeout=self.timeout)
            return resp.status_code == 200
        except Exception:
            return False
    
    def test(self) -> bool:
        """Test if Discord logging server is reachable."""
        if not requests:
            return False
        try:
            resp = self.session.get(self.base_url, timeout=2)
            return resp.status_code < 500
        except Exception:
            return False
    
    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"Discord({self.host}:{self.port}, {status})"


# Global discord instance (pwntools-style)
discord = Discord()


# =============================================================================
# FLAG SUBMISSION
# =============================================================================

def submit(flag, target: str = None, silent: bool = False):
    """
    Submit a flag to the scoring server.
    
    Args:
        flag: The flag string (str or bytes)
        target: Optional target IP (for logging)
        silent: If True, don't log to Discord
        
    Returns:
        dict with keys:
            - success: bool - whether submission was accepted
            - duplicate: bool - whether flag was already submitted
            - message: str - response message
    """
    if isinstance(flag, bytes):
        flag = flag.decode()
    
    # Clean the flag (remove whitespace)
    flag = flag.strip()
    
    if not requests:
        return {"success": False, "duplicate": False, "message": "requests not installed"}
    
    headers = {"Content-Type": "application/json"}
    data = {"flag": flag, "token": TOKEN}
    
    try:
        response = requests.post(API_URL, headers=headers, json=data, timeout=10)
        result = response.json()
        
        if result.get("code") == "AD-000000":
            is_dup = result.get("data", {}).get("is_duplicate", False)
            ret = {
                "success": True,
                "duplicate": is_dup,
                "message": "duplicate" if is_dup else "NEW FLAG!"
            }
            
            # Auto-log to Discord
            if not silent and discord.enabled:
                if is_dup:
                    discord.info(f"Flag submitted (duplicate)", fields={"flag": flag[:20] + "...", "target": target})
                else:
                    discord.flag(f"🚩 NEW FLAG!", flag=flag, target=target)
            
            return ret
        else:
            msg = result.get("message", "unknown error")
            if not silent and discord.enabled:
                discord.warn(f"Flag rejected: {msg}", fields={"flag": flag[:20] + "..."})
            return {
                "success": False,
                "duplicate": False,
                "message": msg
            }
    except Exception as e:
        if not silent and discord.enabled:
            discord.error(f"Submit error: {e}", exc=e)
        return {
            "success": False,
            "duplicate": False,
            "message": str(e)
        }


def get_targets(creds_file=None, include_self=False):
    """
    Get list of target IP addresses from credentials file.
    
    Args:
        creds_file: Path to CSV/XLSX file (optional, uses CREDS_FILE if not specified)
        include_self: If False (default), automatically excludes our own IP
        
    Returns:
        List of IP address strings (excluding our own IP by default)
    """
    creds_file = creds_file or CREDS_FILE
    
    if not os.path.exists(creds_file):
        raise FileNotFoundError(f"Credentials file not found: {creds_file}")
    
    target_list = []
    
    if creds_file.endswith('.xlsx') or creds_file.endswith('.xls'):
        target_list = _parse_xlsx(creds_file)
    else:
        target_list = _parse_csv(creds_file)
    
    # Auto-filter our own IP
    if not include_self:
        my_ip = get_our_ip(creds_file)
        if my_ip:
            target_list = [ip for ip in target_list if ip != my_ip]
    
    return target_list


def _parse_csv(filepath):
    """Parse CSV file for target IPs."""
    targets = []
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Look for Guest_Node entries (other teams)
        if 'Guest_Node' in line or ('Name,' in line and 'Guest' in line):
            if i + 1 < len(lines):
                ip_line = lines[i + 1].strip()
                if ip_line.startswith('IP,'):
                    ip = ip_line.split(',')[1].strip()
                    if ip and _is_valid_ip(ip):
                        targets.append(ip)
        i += 1
    
    return targets


def _parse_xlsx(filepath):
    """Parse XLSX file for target IPs."""
    try:
        import openpyxl
    except ImportError:
        raise ImportError("openpyxl required for xlsx: pip install openpyxl")
    
    targets = []
    wb = openpyxl.load_workbook(filepath)
    ws = wb.active
    
    for row in ws.iter_rows(values_only=True):
        for i, cell in enumerate(row):
            if cell and 'Guest_Node' in str(cell):
                # Next row should have IP
                pass  # Simplified - CSV parsing is more reliable
            if cell and _is_valid_ip(str(cell)):
                # Check if this looks like a target IP (not our own)
                targets.append(str(cell))
    
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    
    return unique


def _is_valid_ip(s):
    """Check if string is a valid IPv4 address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, s):
        parts = s.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def get_our_ip(creds_file=None):
    """
    Get our team's IP address from credentials file.
    
    Args:
        creds_file: Path to CSV/XLSX file (optional)
        
    Returns:
        Our team's IP address string, or None if not found
    """
    creds_file = creds_file or CREDS_FILE
    
    if not os.path.exists(creds_file):
        raise FileNotFoundError(f"Credentials file not found: {creds_file}")
    
    with open(creds_file, 'r') as f:
        lines = f.readlines()
    
    # Look for "Login Info" section - our IP is usually listed there
    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith('IP,') and i > 0:
            prev_line = lines[i-1].strip() if i > 0 else ""
            # Our IP is in the "Login Info" section, not under Guest_Node
            if 'Guest_Node' not in prev_line:
                ip = line.split(',')[1].strip()
                if _is_valid_ip(ip):
                    return ip
    
    return None


def get_our_credentials(creds_file=None):
    """
    Get our team's full credentials from the file.
    
    Returns:
        dict with keys: ip, name, pem_url (if available)
    """
    creds_file = creds_file or CREDS_FILE
    
    creds = {
        "ip": get_our_ip(creds_file),
        "name": None,
        "pem_url": None
    }
    
    with open(creds_file, 'r') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith('Name,') and 'Guest_Node' not in line:
            creds["name"] = line.split(',')[1].strip()
        if line.startswith('SecretUrl,'):
            creds["pem_url"] = line.split(',')[1].strip()
    
    return creds


def setup_auth(pem_file=None, pem_url=None):
    """
    Download and setup the authentication PEM file with correct permissions.
    
    Args:
        pem_file: Output path for PEM file (default: auth.pem)
        pem_url: URL to download PEM from (default: from config or creds file)
        
    Returns:
        Path to the PEM file
    """
    pem_file = pem_file or PEM_FILE
    
    # If file exists and has correct permissions, we're done
    if os.path.exists(pem_file):
        # Ensure permissions are correct (600)
        os.chmod(pem_file, stat.S_IRUSR | stat.S_IWUSR)
        print(f"[+] Auth file already exists: {pem_file}")
        return pem_file
    
    # Get URL from config or credentials file
    if not pem_url:
        pem_url = PEM_URL
        if not pem_url:
            creds = get_our_credentials()
            pem_url = creds.get("pem_url")
    
    if not pem_url:
        raise ValueError("No PEM URL configured. Set PEM_URL or provide pem_url argument.")
    
    # Download the file
    print(f"[*] Downloading auth file from {pem_url}...")
    try:
        response = requests.get(pem_url, timeout=30)
        response.raise_for_status()
        
        with open(pem_file, 'wb') as f:
            f.write(response.content)
        
        # Set correct permissions (600 - owner read/write only)
        os.chmod(pem_file, stat.S_IRUSR | stat.S_IWUSR)
        
        print(f"[+] Auth file saved: {pem_file}")
        return pem_file
        
    except Exception as e:
        raise RuntimeError(f"Failed to download PEM file: {e}")


def ssh_command(ip, user="ctf", pem_file=None):
    """
    Get the SSH command to connect to a target.
    
    Args:
        ip: Target IP address
        user: SSH username (default: ctf)
        pem_file: Path to PEM file (default: auth.pem)
        
    Returns:
        SSH command string
    """
    pem_file = pem_file or PEM_FILE
    return f"ssh -i {pem_file} {user}@{ip}"


# === Convenience functions ===

def print_targets():
    """Print all target IPs."""
    print("Target IPs:")
    for ip in get_targets():
        print(f"  {ip}")


def print_info():
    """Print competition info."""
    print("=== AWD Competition Info ===")
    print(f"Our IP: {get_our_ip()}")
    print(f"Targets: {len(get_targets())}")
    print(f"API URL: {API_URL}")
    print(f"Discord: {discord}")
    print()
    print_targets()


# =============================================================================
# CONVENIENCE ALIASES (shorter names)
# =============================================================================

# Short aliases for common functions
targets = get_targets
our_ip = get_our_ip


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Config
    "chal",
    
    # Core functions
    "submit",
    "get_targets", 
    "targets",  # alias
    "get_our_ip",
    "our_ip",  # alias
    "get_our_credentials",
    "setup_auth",
    "ssh_command",
    
    # Discord logging
    "discord",
    
    # Info
    "print_info",
    "print_targets",
    
    # Config vars (for advanced use)
    "API_URL",
    "TOKEN",
    "CREDS_FILE",
    "PEM_FILE",
]


if __name__ == "__main__":
    # When run directly, print info
    print_info()
