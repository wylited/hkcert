#!/usr/bin/env python3
"""Analyze heap layout in detail"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# Create code that writes at various SP offsets and check behavior
def create_test_code(code_addr):
    code = b''
    
    # Write 0xDEADBEEF at various offsets
    for i in range(8):
        offset = 0xF8 + i  # Test offsets 0xF8 through 0xFF
        sp = code_addr | offset
        # Set SP and push
        code += bytes([0x41, 15]) + p32(sp)  # MOV r15, imm
        code += bytes([0x41, 0]) + p32(0x41414141 + i)  # MOV r0, value
        code += bytes([0x02, 0])  # PUSH r0
    
    code += bytes([0x00])  # HLT
    return code

p = process(['./mqda'])
p.recvuntil(b'Code Address> ')

code_addr = 0x10000
code = create_test_code(code_addr)

p.sendline(str(code_addr).encode())
p.recvuntil(b'Code Length> ')
p.sendline(str(len(code)).encode())
p.recvuntil(b'Code> ')
p.send(code)
p.recvuntil(b'Entry IP> ')
p.sendline(str(code_addr).encode())

output = p.recvall(timeout=2)
print(f"Output: {output}")
p.close()
