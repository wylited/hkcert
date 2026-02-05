# AWD Library Documentation

A Python library for Attack-Defense CTF competitions with pwntools-style developer experience.

## Installation

```bash
# Required
pip install requests pwntools

# Optional (for .xlsx support)
pip install openpyxl
```

Copy `awd_lib.py` to your challenge directory, or add its parent folder to your Python path.

---

## Quick Start

```python
#!/usr/bin/env python3
import os
os.environ['PWNLIB_NOTERM'] = '1'  # Suppress pwntools noise

from pwn import *
from awd_lib import chal, submit, targets, our_ip, discord

# Configure (optional - uses defaults if not called)
chal("creds.csv")

# Exploit all targets
for ip in targets():
    try:
        r = remote(ip, 9999, timeout=5)
        r.sendline(b"exploit payload")
        flag = r.recvline().decode().strip()
        submit(flag, target=ip)
        r.close()
    except:
        pass
```

---

## Configuration

### `chal()` - Configure Everything

Call at the start of your exploit to set challenge-specific options.

```python
# Simple - just set credentials file
chal("path/to/creds.csv")

# Full configuration
chal(
    creds_file="creds.csv",           # Target IPs file
    api_url="https://ctf.example.com/api/flag",
    token="your-api-token",
    pem_url="http://ctf.example.com/auth.pem",
    pem_file="auth.pem",
    discord_host="192.168.1.100",     # Discord logger server
    discord_port=4545,
)

# Returns current config dict
config = chal()
print(config)
```

### Environment Variables (Alternative)

```bash
export DISCLOG_HOST="192.168.1.100"
export DISCLOG_PORT="4545"
```

---

## Core Functions

### `submit(flag)` - Submit Flags

```python
from awd_lib import submit

# Basic usage
result = submit("flag{abc123}")
print(result)  # {'success': True, 'duplicate': False, 'message': 'NEW FLAG!'}

# With target tracking (for logging)
result = submit(flag, target="172.24.84.11")

# Silent mode (no Discord logging)
result = submit(flag, silent=True)

# Bytes work too
result = submit(b"flag{abc123}")
```

**Return value:**
```python
{
    "success": bool,    # True if accepted
    "duplicate": bool,  # True if already submitted
    "message": str      # Status message
}
```

### `targets()` / `get_targets()` - Get Target IPs

```python
from awd_lib import targets, get_targets

# Get all target IPs
for ip in targets():
    print(ip)

# With custom credentials file
ips = get_targets("path/to/creds.csv")
```

### `our_ip()` / `get_our_ip()` - Get Your Team's IP

```python
from awd_lib import our_ip

my_ip = our_ip()
print(f"Our IP: {my_ip}")  # 172.24.84.24
```

### `setup_auth()` - Download & Setup PEM File

```python
from awd_lib import setup_auth

# Downloads PEM and sets permissions to 600
pem_path = setup_auth()

# Custom path
pem_path = setup_auth(pem_file="my_key.pem")
```

### `ssh_command()` - Get SSH Command

```python
from awd_lib import ssh_command

cmd = ssh_command("172.24.84.11")
print(cmd)  # ssh -i auth.pem ctf@172.24.84.11

# Custom user
cmd = ssh_command("172.24.84.11", user="root")
```

### `print_info()` / `print_targets()` - Debug Info

```python
from awd_lib import print_info, print_targets

print_info()     # Prints our IP, target count, config
print_targets()  # Lists all target IPs
```

---

## Discord Logging

Pwntools-style logging to Discord channels. Requires running the `discord-bot` logger server.

### Setup

```python
from awd_lib import discord

# Configure (enables logging)
discord.configure("192.168.1.100", 4545)

# Or with more options
discord.configure(
    host="192.168.1.100",
    port=4545,
    channel="team1",      # Default channel
    service="my_exploit", # Service name (default: script name)
)
```

### Log Levels

```python
discord.debug("Low-level details")           # Gray
discord.info("General information")          # Blue
discord.warn("Warning message")              # Orange
discord.error("Error occurred", exc=e)       # Red (with traceback)
discord.critical("CRITICAL!", ping=True)     # Purple (@everyone)
discord.success("It worked!")                # Green
```

### Special Methods

```python
# Attack detection
discord.attack(
    "SQL Injection detected",
    target="172.24.84.11",
    payload="' OR 1=1--"
)

# Flag capture
discord.flag(
    "Got the flag!",
    flag="flag{abc123}",
    target="172.24.84.11",
    points=100
)

# Quick pwn notification
discord.pwned("172.24.84.11", flag="flag{abc}", exploit="backdoor")
# → "🎯 Pwned 172.24.84.11 with backdoor"
```

### Extra Fields

```python
# Add custom fields to any log
discord.info("Service status",
    team="team1",
    service="web",
    fields={
        "uptime": "2h 30m",
        "requests": 1500
    },
    tags=["monitoring", "health"]
)
```

### Batch Logging

```python
discord.batch([
    {"message": "Event 1", "level": "info"},
    {"message": "Event 2", "level": "warn"},
    {"message": "Event 3", "level": "error"},
])
```

### Auto-Logging

When Discord is configured, `submit()` automatically logs:
- 🚩 **NEW FLAG!** - New flag captured (to `#flags`)
- Flag submitted (duplicate) - Already submitted flag
- Flag rejected - Invalid flag
- Submit error - API errors

Disable with `submit(flag, silent=True)`.

### Safe by Design

All Discord methods are safe - they never raise exceptions or crash your exploit:

```python
# These all return False silently if Discord is unavailable
discord.info("test")  # → False (no crash)
discord.flag("flag")  # → False (no crash)

# Check if Discord is working
if discord.test():
    print("Discord server reachable")
```

---

## Complete Exploit Template

```python
#!/usr/bin/env python3
"""
My AWD Exploit
Usage:
    python3 exploit.py              # All targets
    python3 exploit.py 172.24.84.11 # Single target
    python3 exploit.py --loop       # Continuous
"""
import os
import sys
import time
os.environ['PWNLIB_NOTERM'] = '1'

from pwn import *
from awd_lib import chal, submit, targets, our_ip, discord

# === CONFIG ===
PORT = 9999
TIMEOUT = 10
LOOP_DELAY = 60

# chal("creds.csv", discord_host="192.168.1.100")

# === EXPLOIT ===
def exploit(ip):
    """Returns flag on success, None on failure."""
    try:
        r = remote(ip, PORT, timeout=TIMEOUT)
        
        # Your exploit here
        r.sendline(b"PAYLOAD")
        data = r.recvall(timeout=3)
        r.close()
        
        # Extract flag
        match = re.search(rb'(flag\{[^}]+\}|hkcert24\{[^}]+\})', data)
        if match:
            return match.group(1).decode()
        return None
        
    except Exception as e:
        return None

# === MAIN ===
def run_once():
    my_ip = our_ip()
    for ip in targets():
        if ip == my_ip:
            continue
        
        flag = exploit(ip)
        if flag:
            result = submit(flag, target=ip)
            status = "NEW!" if not result['duplicate'] else "dup"
            print(f"[+] {ip}: {flag[:30]}... ({status})")
        else:
            print(f"[-] {ip}: failed")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--loop":
            while True:
                run_once()
                time.sleep(LOOP_DELAY)
        else:
            # Single target
            flag = exploit(sys.argv[1])
            if flag:
                submit(flag, target=sys.argv[1])
    else:
        run_once()
```

---

## Credentials File Format

The library parses CSV files in this format:

```csv
Login Info,
Name,Your_Team_Name
IP,172.24.84.24
SecretUrl,http://example.com/auth.pem

Guest Info,
Name,Guest_Node_01
IP,172.24.84.11

Name,Guest_Node_02
IP,172.24.84.12
...
```

- Your team's IP is identified by NOT being under `Guest_Node_XX`
- Target IPs are those under `Guest_Node_XX` entries
- Both `.csv` and `.xlsx` formats are supported

---

## Tips & Tricks

### Skip Your Own Team
```python
my_ip = our_ip()
for ip in targets():
    if ip == my_ip:
        continue
    exploit(ip)
```

### Parallel Attacks
```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=5) as pool:
    results = pool.map(exploit, targets())
```

### Rate Limiting
```python
import time

for ip in targets():
    flag = exploit(ip)
    if flag:
        submit(flag)
        time.sleep(0.15)  # ~6 submissions/sec
```

### Cooldown (Skip Recent Successes)
```python
import time

pwned = {}  # ip -> timestamp
COOLDOWN = 300  # 5 minutes

for ip in targets():
    if ip in pwned and time.time() - pwned[ip] < COOLDOWN:
        continue  # Skip recently pwned
    
    flag = exploit(ip)
    if flag:
        result = submit(flag)
        if result['success'] and not result['duplicate']:
            pwned[ip] = time.time()
```

---

## API Reference

| Function | Description |
|----------|-------------|
| `chal(creds_file, ...)` | Configure challenge settings |
| `submit(flag, target, silent)` | Submit flag to scoring server |
| `targets()` / `get_targets()` | Get list of target IPs |
| `our_ip()` / `get_our_ip()` | Get your team's IP |
| `setup_auth()` | Download and setup PEM file |
| `ssh_command(ip, user)` | Get SSH command string |
| `print_info()` | Print debug info |
| `print_targets()` | Print all targets |

| Discord Method | Description |
|----------------|-------------|
| `discord.configure(host, port, ...)` | Enable Discord logging |
| `discord.debug/info/warn/error/critical/success(msg)` | Log at level |
| `discord.attack(msg, target, payload)` | Log attack detection |
| `discord.flag(msg, flag, target, points)` | Log flag capture |
| `discord.pwned(target, flag, exploit)` | Quick pwn notification |
| `discord.batch(entries)` | Send multiple logs |
| `discord.test()` | Check server reachability |

---

## Troubleshooting

**"requests not installed"**
```bash
pip install requests
```

**"openpyxl required for xlsx"**
```bash
pip install openpyxl
```

**Pwntools spinners/noise**
```python
import os
os.environ['PWNLIB_NOTERM'] = '1'  # BEFORE importing pwn
from pwn import *
```

**Discord not logging**
- Check `discord.configure()` was called
- Check server is running: `discord.test()`
- Check `discord.enabled` is `True`

**Rate limited (Request Throttled)**
- Add delay between submissions: `time.sleep(0.15)`
