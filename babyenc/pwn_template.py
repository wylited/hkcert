#!/usr/bin/env python3
"""
AWD PWN Exploit Template
========================
Copy this file and modify the exploit() function for each PWN challenge.

Usage:
    python3 my_exploit.py              # Run against all targets (AWD mode)
    python3 my_exploit.py 172.24.84.11 # Run against specific IP
    python3 my_exploit.py --loop       # Run continuously
    python3 my_exploit.py --info       # Print competition info
    
    # Development/debugging modes:
    python3 my_exploit.py local        # Test locally
    python3 my_exploit.py debug        # Debug with GDB
"""

import sys
import os
import time

# Suppress pwntools noise (must be before import)
os.environ['PWNLIB_NOTERM'] = '1'

from pwn import *
from pwn_lib import (
    setup_binary, add_breakpoint, get_io, shortcuts,
    p64, p32, u64, u32, uu64, uu32, leak_addr,
)
from awd_lib import (
    chal, submit, targets, our_ip, discord,
    setup_auth, ssh_command, print_info, print_targets,
)

# === CHALLENGE CONFIG ===
BINARY = "./vuln"     # Path to binary (for local testing)
LIBC = None           # Path to libc (e.g., "./libc.so.6")
PORT = 9999           # Remote port
TIMEOUT = 10          # Connection timeout
LOOP_DELAY = 60       # Seconds between rounds (for --loop)

# Configure challenge (uncomment and edit as needed)
# Supports .csv, .xlsx, and .xls credential files
# chal("path/to/creds.csv")
# chal("path/to/creds.xls")
# chal(creds_file="creds.xlsx", pem_file="auth.pem")

# Setup binary for local testing/debugging (uncomment when needed)
# bin, rop, libc = setup_binary(BINARY, LIBC, log_level='error')

# GDB breakpoints (for debug mode)
# add_breakpoint('main', 'vuln+32', '0x401234')

# Suppress pwntools output for AWD mode
context.log_level = 'error'
context.timeout = TIMEOUT

# ========================
# YOUR EXPLOIT CODE HERE
# ========================

def exploit(ip, port):
    """
    Exploit a single target and return the flag.
    
    Args:
        ip: Target IP address
        port: Target port
        
    Returns:
        Flag string if successful, None otherwise
    """
    try:
        io = remote(ip, port, timeout=TIMEOUT)
        s = shortcuts(io)
        
        # === YOUR EXPLOIT LOGIC HERE ===
        
        # Example: Simple buffer overflow
        # payload = b"A" * 64
        # payload += p64(win_addr)
        # s.sla(b"> ", payload)
        # s.ru(b"flag{")
        # flag = b"flag{" + s.ru(b"}")
        
        # Example: Format string leak
        # s.sla(b"> ", b"%p " * 20)
        # leaks = s.rl().split()
        
        # Example: ROP chain
        # rop = ROP(bin)
        # rop.call('puts', [bin.got['puts']])
        # rop.call('main')
        # payload = b"A" * offset + rop.chain()
        
        # Example: ret2libc
        # libc.address = leaked_puts - libc.sym['puts']
        # rop = ROP(libc)
        # rop.call('system', [next(libc.search(b'/bin/sh'))])
        
        # Placeholder - replace with your exploit
        flag = None
        
        io.close()
        return flag
        
    except Exception as e:
        # discord.error(f"Exploit failed on {ip}", exc=e)  # Optional
        return None


def exploit_dev(io):
    """
    Development version of exploit for local testing/debugging.
    Use this with 'local' or 'debug' mode.
    
    Args:
        io: process object from get_io()
    """
    s = shortcuts(io)
    
    # === YOUR EXPLOIT LOGIC HERE ===
    # Same as exploit() but with io already connected
    
    # Example:
    # s.sla(b"> ", payload)
    # s.ru(b"flag{")
    # flag = b"flag{" + s.ru(b"}")
    # print(f"[+] Flag: {flag}")
    
    io.interactive()


# ========================
# RUNNER CODE (don't edit)
# ========================

def run_single(ip):
    """Run exploit against a single target."""
    print(f"[*] Attacking {ip}:{PORT}...")
    flag = exploit(ip, PORT)
    
    if flag:
        print(f"[+] Got flag: {flag}")
        result = submit(flag, target=ip)
        if result["success"]:
            if result["duplicate"]:
                print(f"[=] Flag submitted (duplicate)")
            else:
                print(f"[+] NEW FLAG SUBMITTED!")
        else:
            print(f"[-] Submit failed: {result['message']}")
        return True
    else:
        print(f"[-] No flag from {ip}")
        return False


def run_all():
    """Run exploit against all targets."""
    target_list = targets()  # Already excludes our IP
    
    print(f"[*] Our IP: {our_ip()}")
    print(f"[*] Targets: {len(target_list)}")
    print(f"[*] Port: {PORT}")
    print()
    
    success = 0
    failed = 0
    
    for ip in target_list:
        if run_single(ip):
            success += 1
        else:
            failed += 1
    
    print()
    print(f"[*] Done: {success} success, {failed} failed")
    return success, failed


def run_loop():
    """Run exploit continuously."""
    print(f"[*] Running in loop mode (Ctrl+C to stop)")
    print(f"[*] Delay between rounds: {LOOP_DELAY}s")
    
    round_num = 0
    while True:
        round_num += 1
        print(f"\n{'='*50}")
        print(f"ROUND {round_num}")
        print(f"{'='*50}")
        
        try:
            run_all()
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            break
        except Exception as e:
            print(f"[-] Round error: {e}")
        
        print(f"[*] Sleeping {LOOP_DELAY}s...")
        try:
            time.sleep(LOOP_DELAY)
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            break


def main():
    # Auto-setup auth PEM file
    try:
        setup_auth()
    except Exception as e:
        pass  # Silently skip if not in AWD environment
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        # Development modes
        if arg == "local":
            context.log_level = 'debug'
            setup_binary(BINARY, LIBC, log_level='debug')
            io = get_io("_local")
            exploit_dev(io)
            return
        elif arg == "debug":
            context.log_level = 'debug'
            setup_binary(BINARY, LIBC, log_level='debug')
            io = get_io("_debug")
            exploit_dev(io)
            return
        
        # AWD modes
        elif arg == "--loop" or arg == "-l":
            run_loop()
        elif arg == "--help" or arg == "-h":
            print(__doc__)
        elif arg == "--info" or arg == "-i":
            print_info()
        elif arg == "--targets" or arg == "-t":
            print_targets()
        elif arg == "--ssh":
            ip = sys.argv[2] if len(sys.argv) > 2 else targets()[0]
            print(ssh_command(ip))
        else:
            # Attack specific IP
            run_single(arg)
    else:
        # Attack all targets once
        run_all()


if __name__ == "__main__":
    main()
