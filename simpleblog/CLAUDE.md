# CLAUDE.md - AI Assistant Guide

This directory contains an Attack-Defense (AWD) CTF exploit framework for HKCERT competitions.

## Quick Context

- **awd_lib.py**: Core library with flag submission, target parsing, Discord logging, and SSH auth
- **pwn_lib.py**: PWN utilities - packing, binary setup, GDB debugging, IO shortcuts
- **pwn.py**: PWN exploit template - copy and modify for binary exploitation
- **web.py**: Web exploit template - copy and modify for web challenges

## Key Functions to Know

### AWD Library (awd_lib.py)
```python
from awd_lib import *

# Setup (auto-downloads PEM, sets permissions to 600)
setup_auth()

# Get target IPs (automatically excludes your own IP)
for ip in targets():
    # exploit each target

# Submit captured flag
submit(flag, target=ip)

# Discord logging (optional)
discord.configure("192.168.1.100", 4545)
discord.success("Got shell!", target=ip)
discord.flag("Captured!", flag=flag)
```

### PWN Library (pwn_lib.py)
```python
from pwn_lib import *

# Setup binary for local testing
bin, rop, libc = setup_binary("./vuln", "./libc.so.6")

# Add GDB breakpoints
add_breakpoint('main', 'vuln+32', '0x401234')

# Get IO (local, debug, or remote)
io = get_io("_local")        # Local process
io = get_io("_debug")        # GDB attached
io = get_io("_remote", ip, port)

# IO shortcuts
s = shortcuts(io)
s.sla(b"> ", payload)  # sendlineafter
s.sl(payload)          # sendline
s.ru(b"flag")          # recvuntil

# Packing utilities
payload = p64(addr) + p32(value)
leaked = uu64(data)    # Padded unpack
```

## Common Tasks

### Creating a New PWN Exploit
1. Copy `pwn.py` to `exploit_name.py`
2. Set `BINARY`, `PORT`, and optionally `LIBC`
3. Implement `exploit(ip, port)` for AWD mode
4. Implement `exploit_dev(io)` for local testing
5. Return the flag string or `None`

### Creating a New Web Exploit
1. Copy `web.py` to `exploit_name.py`
2. Set `PORT` for the challenge
3. Implement `exploit(ip, port)` function
4. Use `extract_flag(text)` to parse flag from response

### Running Exploits
```bash
# AWD modes
python3 exploit.py              # All targets once
python3 exploit.py 172.24.84.11 # Single target
python3 exploit.py --loop       # Continuous mode
python3 exploit.py --info       # Show competition info

# Development modes (PWN only)
python3 exploit.py local        # Test locally
python3 exploit.py debug        # Debug with GDB
```

## File Structure

```
example-chal/
├── awd_lib.py      # Core AWD library (targets, submit, discord)
├── pwn_lib.py      # PWN utilities (packing, IO, GDB)
├── pwn.py          # PWN exploit template
├── web.py          # Web exploit template
├── mqda.csv        # Credentials file (from competition)
└── auth.pem        # Auto-downloaded SSH key
```

## Important Details

- **PEM permissions**: `setup_auth()` automatically sets 600 permissions
- **Flag format**: Handled automatically, supports bytes or string
- **Target filtering**: `targets()` automatically excludes your own IP
- **Discord logging**: Silent fail - won't crash exploits if server unavailable
- **IO shortcuts**: Use `shortcuts(io)` for cleaner exploit code

## When Helping with Exploits

1. The `exploit(ip, port)` function should return the flag or `None`
2. Use `exploit_dev(io)` for local testing with GDB
3. Use pwntools (`from pwn import *`) for binary exploitation
4. Use `requests` for web exploits
5. Always handle exceptions gracefully
6. Test with `local`/`debug` mode before running on all targets
