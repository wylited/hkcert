# entry point for all subcommands
import argparse
import os
import sys
from certins.base import ensure_dirs, save_config, load_config, setup_from_xls, setup_new_tag

# from certins.commands.files import run_files
from certins.commands.ssh import run_ssh

# two subcommands: ssh and files
def main():
    ensure_dirs()
    config = load_config()

    parser = argparse.ArgumentParser(description="CertIns - SSH Connection Manager")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # SSH Subcommand
    ssh_parser = subparsers.add_parser('ssh', help='Connect via SSH using a saved configuration tag')
    ssh_parser.add_argument('tag', type=str, nargs="?", help='Configuration tag to use for SSH connection')
    ssh_parser.add_argument('-x', '--xls', type=str, help='Path to XLS file with connection info (with auto setup)')

    # Setup Subcommand
    setup_parser = subparsers.add_parser('setup', help='Setup a new SSH connection configuration')
    setup_group = setup_parser.add_mutually_exclusive_group(required=True)
    setup_group.add_argument('-x', '--xls', type=str, help='Path to XLS file with connection info')
    setup_group.add_argument('--new', action='store_true', help='Interactively create a new configuration')

    args = parser.parse_args()

    if args.command == 'setup' or args.xls:
        if args.xls:
            tag = args.tag if args.tag else os.path.splitext(os.path.basename(args.xls))[0].split()[0]
            setup_from_xls(tag, args.xls, config)
        elif args.new:
            setup_new_tag(config)
        # Save updated config
        save_config(config)
        print(f"Configuration for {tag} saved.")
        args.tag = tag  # Set tag for potential next step
        
    if args.command == 'ssh':
        tag = args.tag
        if not tag:
            print("Error: You must provide a configuration tag for SSH connection.")
            sys.exit(1)
        if tag not in config:
            print(f"Error: No configuration found for tag '{tag}'.")
            sys.exit(1)
        run_ssh(tag, config[tag])
        
    