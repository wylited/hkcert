#!/usr/bin/env python3
"""
AWD Exploit Template
====================
Copy this file and modify the exploit() function for each challenge.

Usage:
    python3 my_exploit.py              # Run against all targets
    python3 my_exploit.py 172.24.84.11 # Run against specific IP
    python3 my_exploit.py --loop       # Run continuously
    python3 my_exploit.py --info       # Print competition info
"""

import sys
import os
import time

# Suppress pwntools noise (must be before import)
os.environ['PWNLIB_NOTERM'] = '1'

from pwn import *
from awd_lib import (
    chal, submit, targets, our_ip, discord,
    setup_auth, ssh_command, print_info, print_targets,
    PEM_FILE
)

# === CHALLENGE CONFIG ===
PORT = 9999           # Change this per challenge
TIMEOUT = 10          # Connection timeout
LOOP_DELAY = 60       # Seconds between rounds (for --loop)

# Configure challenge (uncomment and edit as needed)
# chal("path/to/creds.csv")  # Just set creds file
# chal(
#     creds_file="creds.csv",
#     discord_host="192.168.1.100",
#     discord_port=4545,
# )

# Suppress pwntools output
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
        p = remote(ip, port, timeout=TIMEOUT)
        
        # === YOUR EXPLOIT LOGIC HERE ===
        
        # Example: simple backdoor
        # p.recvuntil(b"> ")
        # p.sendline(b"cat flag")
        # flag = p.recvline().strip()
        
        # Example: buffer overflow
        # payload = b"A" * 64 + p64(win_addr)
        # p.sendline(payload)
        # p.recvuntil(b"flag{")
        # flag = b"flag{" + p.recvuntil(b"}")
        
        # Placeholder - replace with your exploit
        flag = None
        
        p.close()
        return flag
        
    except Exception as e:
        # discord.error(f"Exploit failed on {ip}", exc=e)  # Optional
        return None


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
                # discord.pwned(ip, flag)  # Optional
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
    
    # discord.info(f"Starting exploit round on {len(target_list)} targets")  # Optional
    
    success = 0
    failed = 0
    
    for ip in target_list:
        if run_single(ip):
            success += 1
        else:
            failed += 1
    
    print()
    print(f"[*] Done: {success} success, {failed} failed")
    # discord.info(f"Round complete: {success} success, {failed} failed")  # Optional
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
            # discord.error(f"Round {round_num} error", exc=e)  # Optional
        
        print(f"[*] Sleeping {LOOP_DELAY}s...")
        try:
            time.sleep(LOOP_DELAY)
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            break


def main():
    # Auto-setup auth PEM file with correct permissions
    try:
        setup_auth()
    except Exception as e:
        print(f"[!] Auth setup skipped: {e}")
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--loop" or arg == "-l":
            run_loop()
        elif arg == "--help" or arg == "-h":
            print(__doc__)
        elif arg == "--info" or arg == "-i":
            print_info()
        elif arg == "--targets" or arg == "-t":
            print_targets()
        elif arg == "--ssh":
            # Print SSH command for first target or specified IP
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
