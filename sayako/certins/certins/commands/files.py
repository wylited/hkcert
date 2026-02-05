from certins.base import (
    SECRETS_DIR,
    BASE_DIR
)
import os
import sys
import subprocess

def run_files(tag, config_data, direction, src, dest):
    host = config_data.get('host')
    pem_filename = config_data.get('pem_file')
    
    if not host or not pem_filename:
        print("Error: Invalid configuration data. Host or PEM file missing.")
        sys.exit(1)

    pem_path = os.path.join(SECRETS_DIR, pem_filename)
    
    # Verify PEM exists
    if not os.path.exists(pem_path):
        print(f"Error: Key file missing at {pem_path}")
        sys.exit(1)

    print(f"\nTransferring files with {host}...")
    
    scp_args = ["scp", "-i", pem_path]
    
    if direction == 'up':
        local_path = src
        remote_path = dest
        if not os.path.exists(local_path):
             print(f"Error: Local file '{local_path}' does not exist.")
             sys.exit(1)
        source_arg = local_path
        dest_arg = f"{host}:{remote_path}"
        print(f"Uploading '{source_arg}' to '{dest_arg}'")
    else:  # direction == 'down'
        remote_path = src
        local_path = dest
        
        if not dest:
            if not os.path.exists(os.path.join(BASE_DIR, "..", "downloads")):
                os.makedirs(os.path.join(BASE_DIR, "..", "downloads"))
            if not os.path.exists(os.path.join(BASE_DIR, "..", "downloads", tag)):
                os.makedirs(os.path.join(BASE_DIR, "..", "downloads", tag))
            local_path = os.path.abspath(os.path.join(BASE_DIR, "..", "downloads", tag, os.path.basename(remote_path)))
        
        # If local_path is a directory, append remote filename
        if os.path.isdir(local_path):
            # Assumes remote path uses forward slash
            filename = remote_path.rstrip('/').split('/')[-1]
            if filename:
                local_path = os.path.join(local_path, filename)
        
        source_arg = f"{host}:{remote_path}"
        dest_arg = local_path
        print(f"Downloading '{source_arg}' to '{dest_arg}'")

    scp_args.append(source_arg)
    scp_args.append(dest_arg)
    
    try:
        subprocess.check_call(scp_args)
        print("Transfer complete.")
    except subprocess.CalledProcessError as e:
        print(f"Error transferring file: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nTransfer cancelled.")
        sys.exit(1)
