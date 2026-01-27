import sys
import os
import json
import shutil
import subprocess
import datetime
import platform
import argparse

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "ssh_config.json")
SECRETS_DIR = os.path.join(BASE_DIR, "connection_secrets")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

def ensure_dirs():
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def secure_pem_permissions(pem_path):
    # Set permissions to 400
    try:
        if platform.system() == "Windows":
            # On Windows, need to use icacls to remove inheritance and grant read to user only
            user = os.environ.get("USERNAME")
            if user:
                subprocess.run(
                    ['icacls', pem_path, '/inheritance:r', '/grant:r', f'{user}:R'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
        else:
            os.chmod(pem_path, 0o400)
    except Exception as e:
        print(f"Warning setting permissions: {e}")

def setup_from_xls(tag, xls_path, config):
    try:
        import pandas as pd
        import requests
    except ImportError:
        print("Error: pandas and requests are required for XLS parsing.")
        print("Please run: pip install -r requirements.txt")
        sys.exit(1)

    print(f"Reading connection info from {xls_path}...")
    try:
        # Load XLS
        df = pd.read_excel(xls_path, header=None)
        
        # Cell 2B -> Row 1, Col 1
        target_ip = str(df.iloc[1, 1]).strip()
        # Cell 3B -> Row 2, Col 1
        username = str(df.iloc[2, 1]).strip()
        # Cell 4B -> Row 3, Col 1
        pem_url = str(df.iloc[3, 1]).strip()
        
        host = f"{username}@{target_ip}"
        
        print(f"  Host: {host}")
        masked_url = pem_url
        if len(pem_url) > 30:
            masked_url = f"{pem_url[:13]}...{pem_url[-8:]}"
        print(f"  PEM URL: {masked_url}")
        
        # Download PEM
        print("Downloading PEM file...")
        r = requests.get(pem_url)
        if r.status_code != 200:
            print(f"Error downloading PEM: HTTP {r.status_code}")
            sys.exit(1)
            
        dest_pem_name = f"{tag}.pem"
        dest_pem_path = os.path.join(SECRETS_DIR, dest_pem_name)

        if os.path.exists(dest_pem_path):
            confirmation = input(f"[ WARNING ] PEM file {dest_pem_path} already exists. Overwrite? (Y/n): ").strip().lower()
            if confirmation != 'y' and confirmation != '':
                print("Aborting setup.")
                sys.exit(1)
            else:
                print(f"Overwriting existing PEM file at {dest_pem_path}...")
                os.remove(dest_pem_path)
        
        with open(dest_pem_path, 'wb') as f:
            f.write(r.content)
            
        secure_pem_permissions(dest_pem_path)
        print(f"Saved key to {dest_pem_path}")
        
        # Update Config
        config[tag] = {
            "host": host,
            "pem_file": dest_pem_name
        }
        save_config(config)
        print(f"Configuration for '{tag}' updated from XLS.")
        return config[tag]

    except Exception as e:
        print(f"Error processing XLS: {e}")
        # Print traceback for debugging if needed, but simple error message is good for now
        import traceback
        traceback.print_exc()
        sys.exit(1)

def setup_new_tag(config, tag=None):
    if tag:
        print(f"Tag '{tag}' not found. Let's configure it.")
    else:
        tag = input("Enter a new configuration tag name: ").strip()
        while not tag or tag in config:
            if not tag:
                print("Tag name cannot be empty.")
            else:
                print(f"Tag '{tag}' already exists. Please choose a different name.")
            tag = input("Enter a new configuration tag name: ").strip()
            
    host = input(f"Enter Host (e.g., user@1.2.3.4): ").strip()
    if not host:
        print("Host cannot be empty.")
        sys.exit(1)
        
    pem_path = input(f"Enter path to PEM file: ").strip()
    # Handle quotes if user dragged and dropped file
    pem_path = pem_path.strip('"').strip("'")
    
    # Expand user path (handle ~/)
    pem_path = os.path.expanduser(pem_path)

    if not os.path.isfile(pem_path):
        print(f"Error: File not found at {pem_path}")
        sys.exit(1)
        
    # Copy PEM file
    dest_pem_name = f"{tag}.pem"
    dest_pem_path = os.path.join(SECRETS_DIR, dest_pem_name)
    
    try:
        shutil.copy2(pem_path, dest_pem_path)
        secure_pem_permissions(dest_pem_path)
        print(f"Securely copied key to {dest_pem_path}")
    except Exception as e:
        print(f"Error copying PEM file: {e}")
        sys.exit(1)

    # Save to config
    config[tag] = {
        "host": host,
        "pem_file": dest_pem_name
    }
    save_config(config)
    print(f"Configuration for '{tag}' saved.")
    return config[tag]

if __name__ == "__main__":
    main()