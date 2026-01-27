from certins.base import (
    CONFIG_FILE,
    SECRETS_DIR,
    LOGS_DIR,
    ensure_dirs,
    load_config,
    save_config,
    secure_pem_permissions,
    setup_from_xls,
    setup_new_tag,
)
import os
import datetime
import platform
import subprocess

def run_ssh(tag, config_data):
    host = config_data['host']
    pem_filename = config_data['pem_file']
    pem_path = os.path.join(SECRETS_DIR, pem_filename)
    
    # Verify PEM exists
    if not os.path.exists(pem_path):
        print(f"Error: Key file missing at {pem_path}")
        sys.exit(1)

    # Prepare Log File
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_filename = f"{tag}-{timestamp}.log"
    log_path = os.path.join(LOGS_DIR, log_filename)
    
    print(f"\nConnecting to {host}...")
    print(f"Session will be logged to: {log_path}\n")

    # Construct Command
    
    # Custom prompt command
    # We use -t to force TTY allocation so we can drop into an interactive shell
    base_remote_cmd = r"/bin/bash"

    if platform.system() == "Windows":
        # On Windows, use Powershell Start-Transcript for logging
        # We wrap the ssh command in a powershell session
        # Escape paths for PowerShell
        ps_log_path = log_path.replace("'", "''")
        ps_pem_path = pem_path.replace("'", "''")
        
        # We need to explicitly check for the ssh command or assume it's in PATH
        # Using 'call' (&) operator in powershell
        
        # Escape $ for PowerShell (Backtick)
        remote_cmd_ps = base_remote_cmd.replace("$", "`$")

        ps_command = (
            f"Start-Transcript -Path '{ps_log_path}' -Append; "
            f"Write-Host 'Starting SSH Session...'; "
            f"ssh -t -i '{ps_pem_path}' {host} \"{remote_cmd_ps}\"; "
            f"Stop-Transcript"
        )
        
        cmd = ["powershell", "-NoProfile", "-Command", ps_command]
    else:
        # Linux/MacOS implementation attempt using `script`
        # script syntax varies widely, this is a best-effort for Linux
        # script -c "command" logfile
        
        # Escape for Shell (sh)
        # 1. Escape Backslashes
        remote_cmd_sh = base_remote_cmd.replace("\\", "\\\\")
        # 2. Escape Dollars for sh double-quote context (needs \\$)
        remote_cmd_sh = remote_cmd_sh.replace("$", "\\\\$")
        
        ssh_cmd_str = f"ssh -t -i '{pem_path}' {host} \"{remote_cmd_sh}\""
        
        cmd = ["script", "-q", "-c", ssh_cmd_str, log_path]

    try:
        subprocess.call(cmd)
    except KeyboardInterrupt:
        print("\nDisconnected.")
    except Exception as e:
        print(f"Error executing SSH: {e}")
        # Fallback to direct SSH if wrapping fails
        print("Falling back to direct SSH (no logging)...")
        subprocess.call(["ssh", "-i", pem_path, host])
