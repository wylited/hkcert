from certins.base import (
    SECRETS_DIR,
    LOGS_DIR,
)
import os
import datetime
import platform
import subprocess
import sys

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
        
        try:
            subprocess.call(cmd)
        except KeyboardInterrupt:
            print("\nDisconnected.")
        except Exception as e:
            print(f"Error executing SSH: {e}")
            subprocess.call(["ssh", "-i", pem_path, host])

    else:
        # Linux/MacOS: Use Python's pty module to create a pseudo-terminal
        import pty
        
        ssh_cmd = ["ssh", "-t", "-i", pem_path, host, base_remote_cmd]
        
        try:
            with open(log_path, 'wb') as f_log:
                def read_master_d(fd):
                    data = os.read(fd, 1024)
                    f_log.write(data)
                    f_log.flush()
                    return data
                
                pty.spawn(ssh_cmd, read_master_d)
                
        except KeyboardInterrupt:
            print("\nDisconnected.")
        except Exception as e:
            print(f"Error executing SSH via pty: {e}")
            print(f"SSHing without logging...")
            subprocess.call(ssh_cmd)

    print("Session ended.")
    print(f"Log saved to: {log_path}")
