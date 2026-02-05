# CLAUDE.md - AI Assistant Guide

This directory contains an Attack-Defense (AWD) CTF exploit framework for HKCERT competitions.

## Quick Context

- **awd_lib.py**: Core library with flag submission, target parsing, Discord logging, and SSH auth
- **template.py**: Exploit template - copy and modify the `exploit()` function for each challenge

## Key Functions to Know

```python
from awd_lib import *

# Setup (auto-downloads PEM, sets permissions to 600)
setup_auth()

# Get target IPs from credentials file
for ip in targets():
    # exploit each target

# Submit captured flag
submit(flag, target=ip)

# Discord logging (optional)
discord.configure("192.168.1.100", 4545)
discord.success("Got shell!", target=ip)
discord.flag("Captured!", flag=flag)
```

## Common Tasks

### Creating a New Exploit
1. Copy `template.py` to `exploit_name.py`
2. Set `PORT` for the challenge
3. Implement `exploit(ip, port)` function
4. Return the flag string or `None`

### Configuration
Edit `awd_lib.py` top section OR use `chal()`:
```python
chal(
    creds_file="mqda.csv",      # Target credentials
    api_url="https://...",       # Flag submission endpoint
    token="abc123",              # API token
    pem_url="http://...",        # SSH key download URL
    discord_host="192.168.1.1",  # Optional logging
)
```

### Running Exploits
```bash
python3 exploit.py              # All targets once
python3 exploit.py 172.24.84.11 # Single target
python3 exploit.py --loop       # Continuous mode
python3 exploit.py --info       # Show competition info
python3 exploit.py --ssh        # Print SSH command
```

## File Structure

```
example-chal/
├── awd_lib.py      # Core library (don't modify unless needed)
├── template.py     # Copy this for new exploits
├── mqda.csv        # Credentials file (from competition)
└── auth.pem        # Auto-downloaded SSH key
```

## Important Details

- **PEM permissions**: `setup_auth()` automatically sets 600 permissions
- **Flag format**: Handled automatically, supports bytes or string
- **Target filtering**: `our_ip()` returns our team's IP to skip in loops
- **Discord logging**: Silent fail - won't crash exploits if server unavailable

## When Helping with Exploits

1. The `exploit(ip, port)` function should return the flag or `None`
2. Use pwntools (`from pwn import *`) for binary exploitation
3. Use `requests` for web exploits
4. Always handle exceptions gracefully
5. Test against single IP first before running on all targets
