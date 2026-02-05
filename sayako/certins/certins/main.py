# entry point for all subcommands
import argparse
import os
import sys
from certins.base import ensure_dirs, save_config, load_config, setup_from_xls, setup_new_tag

from certins.commands.files import run_files
from certins.commands.ssh import run_ssh
from certins.commands.tags import run_tags
from certins.commands.recon import run_recon, run_exec

# two subcommands: ssh and files
def main():
    ensure_dirs()
    config = load_config()

    parser = argparse.ArgumentParser(description="CertIns - SSH Connection Manager")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # SSH Subcommand
    ssh_parser = subparsers.add_parser('ssh', aliases=['s'], help='Connect via SSH using a saved configuration tag')
    ssh_parser.add_argument('tag', type=str, nargs="?", help='Configuration tag to use for SSH connection')
    ssh_parser.add_argument('-x', '--xls', type=str, help='Path to XLS file with connection info (with auto setup)')

    # Files Subcommand
    files_parser = subparsers.add_parser('files', aliases=['f'], help='Transfer files via SCP')
    files_parser.add_argument('tag', type=str, help='Configuration tag')
    files_parser.add_argument('direction', choices=['up', 'down'], help='up (upload local->remote) or down (download remote->local)')
    files_parser.add_argument('src', type=str, help='Source path (Local for up, Remote for down)')
    files_parser.add_argument('dest', type=str, nargs="?", help='Destination path (Remote for up, Local for down)')

    # Setup Subcommand
    setup_parser = subparsers.add_parser('setup', aliases=['su'], help='Setup a new SSH connection configuration')
    setup_group = setup_parser.add_mutually_exclusive_group(required=True)
    setup_parser.add_argument('tag', type=str, nargs="?", help='Configuration tag')
    setup_group.add_argument('-x', '--xls', type=str, help='Path to XLS file with connection info')
    setup_group.add_argument('--new', action='store_true', help='Interactively create a new configuration')

    # Tags Subcommand
    subparsers.add_parser('tags', aliases=['t'], help='List all configured tags')

    # Recon Subcommand
    recon_parser = subparsers.add_parser('recon', aliases=['r'], help='Run reconnaissance on remote server')
    recon_parser.add_argument('tag', type=str, help='Configuration tag')
    recon_parser.add_argument('-q', '--quick', action='store_true', help='Quick recon (ports, xinetd, processes, flags only)')

    # Exec Subcommand
    exec_parser = subparsers.add_parser('exec', aliases=['e'], help='Execute command on remote server')
    exec_parser.add_argument('tag', type=str, help='Configuration tag')
    exec_parser.add_argument('cmd', type=str, help='Command to execute')

    args = parser.parse_args()

    if args.command in ['su', 'setup'] or ("xls" in args and args.xls):
        if args.xls:
            tag = args.tag if ("tag" in args and args.tag) else os.path.splitext(os.path.basename(args.xls))[0].split()[0]
            setup_from_xls(tag, args.xls, config)
            # Save updated config
            save_config(config)
            print(f"Configuration for {tag} saved.")
        args.tag = tag  # Set tag for potential next step
        elif args.new:
            setup_new_tag(config)
        
    if args.command in ['s', 'ssh']:
        tag = args.tag
        if not tag:
            print("Error: You must provide a configuration tag for SSH connection.")
            sys.exit(1)
        if tag not in config:
            print(f"Error: No configuration found for tag '{tag}'.")
            sys.exit(1)
        run_ssh(tag, config[tag])
        
    if args.command in ['f', 'files']:
        tag = args.tag
        if not tag:
            print("Error: You must provide a configuration tag for file operations.")
            sys.exit(1)
        if tag not in config:
            print(f"Error: No configuration found for tag '{tag}'.")
            sys.exit(1)
        run_files(tag, config[tag], args.direction, args.src, args.dest)

    if args.command in ['t', 'tags']:
        run_tags(config)

    if args.command in ['r', 'recon']:
        tag = args.tag
        if tag not in config:
            print(f"Error: No configuration found for tag '{tag}'.")
            sys.exit(1)
        run_recon(tag, config[tag], quick=args.quick)

    if args.command in ['e', 'exec']:
        tag = args.tag
        if tag not in config:
            print(f"Error: No configuration found for tag '{tag}'.")
            sys.exit(1)
        run_exec(tag, config[tag], args.cmd)
