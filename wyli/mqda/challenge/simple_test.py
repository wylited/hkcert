#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

def hlt():
    return bytes([0x00])

def mov_reg_imm(reg, imm32):
    return bytes([0x41, reg]) + p32(imm32)

def push_reg(reg):
    return bytes([0x02, reg])

def main():
    code = b''
    # Allocate 3 pages
    for i in range(3):
        addr = i * 0x100
        code += mov_reg_imm(15, addr)
        code += mov_reg_imm(0, 0x41414141)
        code += push_reg(0)
    
    code += hlt()
    
    print(f"[*] Code length: {len(code)}")
    print(f"[*] Code hex: {code.hex()}")
    
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
