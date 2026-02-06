#!/usr/bin/env python3
"""
PWN Helper Library
==================
Utilities for binary exploitation in AWD CTF.
Based on template by ZD (former helper and PWN player) and many PWN players.

Usage:
    from pwn_lib import *
    
    # Setup binary
    setup_binary("./vuln")
    
    # Get IO based on mode
    io = get_io("_local")      # Local process
    io = get_io("_debug")      # GDB debugging
    io = get_io("_remote", ip, port)  # Remote target
"""

from pwn import *

# =============================================================================
# PACKING UTILITIES
# =============================================================================

# Override with explicit bit-width versions
p64 = lambda n: packing.pack(n, 64)
p32 = lambda n: packing.pack(n, 32)
p16 = lambda n: packing.pack(n, 16)
p8  = lambda n: packing.pack(n, 8)

u64 = lambda n: packing.unpack(n, 64)
u32 = lambda n: packing.unpack(n, 32)
u16 = lambda n: packing.unpack(n, 16)
u8  = lambda n: packing.unpack(n, 8)

# Padded unpack (handles short data)
uu64 = lambda data: u64(data.ljust(8, b'\x00'))
uu32 = lambda data: u32(data.ljust(4, b'\x00'))
uu16 = lambda data: u16(data.ljust(2, b'\x00'))


# =============================================================================
# BINARY SETUP
# =============================================================================

# Global state
_binary = None
_rop = None
_libc = None
_gdb_breakpoints = []


def setup_binary(binary_path, libc_path=None, log_level='debug'):
    """
    Setup the target binary and optional libc.
    
    Args:
        binary_path: Path to the binary (e.g., "./vuln")
        libc_path: Optional path to libc (e.g., "./libc.so.6")
        log_level: Logging level ('debug', 'info', 'warn', 'error')
        
    Returns:
        Tuple of (ELF, ROP, libc_ELF or None)
        
    Example:
        bin, rop, libc = setup_binary("./vuln", "./libc.so.6")
    """
    global _binary, _rop, _libc
    
    _binary = ELF(binary_path)
    _rop = ROP(_binary.path)
    
    context.log_level = log_level
    context.binary = _binary
    
    if libc_path:
        _libc = ELF(libc_path)
    
    return _binary, _rop, _libc


def add_breakpoint(*breakpoints):
    """
    Add GDB breakpoints for debug mode.
    
    Args:
        *breakpoints: Addresses or symbols (e.g., 'main', 'main+16', '0x400500')
        
    Example:
        add_breakpoint('main', 'vuln+32', '0x401234')
    """
    global _gdb_breakpoints
    _gdb_breakpoints.extend(breakpoints)


def clear_breakpoints():
    """Clear all GDB breakpoints."""
    global _gdb_breakpoints
    _gdb_breakpoints = []


# =============================================================================
# IO INITIALIZATION
# =============================================================================

def get_io(mode, remote_host=None, remote_port=None, args=None, terminal=None):
    """
    Get process/remote IO based on mode.
    
    Args:
        mode: "_local", "_debug", or "_remote"
        remote_host: IP for remote mode
        remote_port: Port for remote mode
        args: Arguments for the binary (default: [binary.path])
        terminal: Terminal for GDB (default: ["konsole", "-e"])
        
    Returns:
        process or remote object
        
    Example:
        io = get_io("_local")
        io = get_io("_debug")
        io = get_io("_remote", "172.24.84.11", 9999)
    """
    if _binary is None:
        raise RuntimeError("Call setup_binary() first")
    
    proc_args = args or [_binary.path]
    
    # Build GDB script
    gdbscript = "handle SIGALRM ignore\n"
    for bp in _gdb_breakpoints:
        if bp:
            gdbscript += f"b* {bp}\n"
    
    if mode == "_debug":
        context.terminal = terminal or ["konsole", "-e"]
        # Alternative: ["tmux", "splitw", "-h"] for tmux users
        return gdb.debug(proc_args, gdbscript)
    
    elif mode == "_local":
        return process(proc_args)
    
    elif mode == "_remote":
        if not remote_host or not remote_port:
            raise ValueError("remote_host and remote_port required for _remote mode")
        return remote(remote_host, remote_port)
    
    else:
        raise ValueError(f"Unknown mode: {mode}. Use '_local', '_debug', or '_remote'")


def get_io_auto(remote_host=None, remote_port=None, args=None):
    """
    Auto-select IO mode based on command line args.
    
    Usage:
        python3 exploit.py          # Local mode
        python3 exploit.py debug    # Debug mode  
        python3 exploit.py remote   # Remote mode
        python3 exploit.py 1.2.3.4  # Remote to specific IP
        
    Returns:
        process or remote object
    """
    import sys
    
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "debug" or arg == "-d":
            return get_io("_debug", args=args)
        elif arg == "remote" or arg == "-r":
            return get_io("_remote", remote_host, remote_port, args=args)
        elif arg == "local" or arg == "-l":
            return get_io("_local", args=args)
        else:
            # Assume it's an IP address
            port = int(sys.argv[2]) if len(sys.argv) > 2 else remote_port
            return get_io("_remote", arg, port, args=args)
    
    return get_io("_local", args=args)


# =============================================================================
# IO SHORTCUTS
# =============================================================================

class IOShortcuts:
    """
    Shortcut methods for common IO operations.
    
    Usage:
        io = get_io("_local")
        s = IOShortcuts(io)
        s.sla(b"> ", b"1")
        s.sl(payload)
    """
    def __init__(self, io):
        self.io = io
        
    def sla(self, delim, data):
        """sendlineafter"""
        return self.io.sendlineafter(delim, data)
    
    def sa(self, delim, data):
        """sendafter"""
        return self.io.sendafter(delim, data)
    
    def sl(self, data):
        """sendline"""
        return self.io.sendline(data)
    
    def sd(self, data):
        """send"""
        return self.io.send(data)
    
    def rl(self):
        """recvline"""
        return self.io.recvline()
    
    def ru(self, delim):
        """recvuntil"""
        return self.io.recvuntil(delim)
    
    def rc(self, n=4096):
        """recv"""
        return self.io.recv(n)
    
    def ia(self):
        """interactive"""
        return self.io.interactive()


def shortcuts(io):
    """Create IOShortcuts helper for an IO object."""
    return IOShortcuts(io)


# =============================================================================
# COMMON EXPLOIT HELPERS
# =============================================================================

def leak_addr(io, prefix=b"", suffix=b"\n", bits=64):
    """
    Receive and unpack a leaked address.
    
    Args:
        io: process/remote object
        prefix: Data before the address
        suffix: Data after the address (default: newline)
        bits: Address size (64 or 32)
        
    Returns:
        Leaked address as int
    """
    if prefix:
        io.recvuntil(prefix)
    
    size = bits // 8
    data = io.recv(size)
    
    if suffix:
        io.recvuntil(suffix)
    
    if bits == 64:
        return uu64(data)
    else:
        return uu32(data)


def flat_payload(*args, **kwargs):
    """Alias for pwntools flat() function."""
    return flat(*args, **kwargs)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Packing
    'p64', 'p32', 'p16', 'p8',
    'u64', 'u32', 'u16', 'u8',
    'uu64', 'uu32', 'uu16',
    
    # Setup
    'setup_binary',
    'add_breakpoint',
    'clear_breakpoints',
    
    # IO
    'get_io',
    'get_io_auto',
    'shortcuts',
    'IOShortcuts',
    
    # Helpers
    'leak_addr',
    'flat_payload',
]
