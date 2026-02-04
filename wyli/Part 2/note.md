"a" * 8 + ":" + "b" * 0x180 + ";"

struct heap{
	int name_size;
	char name[0x180];
	int passwd_size;
	char passwd[0x180];
	(func*) puts;
	char uid[8];
}

"a" * 8 + ":" + "b" * 0x180 + payload + ";"
passwd_end = ";".index() - ":".index() > 0x180


# payload1 for easyvm(overflow)
1. set passwd to "b" * 0x180
in memory: "b" * 0x180 + puts_func_address
2. use branch to leak the puts_func_address
show()
3. use overflow vulnerability
overwrite the puts_func_addr -> system_plt

# structure add
lower version: shift + F9
IDA 9.0: shift + F1

# patch part for vulnerability 1
1. patch the 0x18B -> 0x180
.text:0000000000001DFC 41 81 FE 8B 01 00 00                    cmp     r14d, 18Bh
->
.text:0000000000001DFC 41 81 FE 80 01 00 00                    cmp     r14d, 180h
2. edit -> patch program -> Apply patches to input file
3. login and upload the patch
4. login information (download information from platform, IP + name + private key)
5. pay attention to the permission of your binary, finally patch it

# payload2 and payload3 for easyvm(overflow)
## payload2(backdoor)
switch(vm->ip[pc]){
	case 1:
		break;
	case 2:
		break;
	...
	case 21:
		//jmp instruction call; jmp parameter
		pc = parameter
	...
	case 0x666:
		system("/bin/sh")
}
pc must be a positive value(> 0)
1. write a 0x666 using login
2. use jmp instruction to change the v6 -> a negative value (after debug, we can find the value is -0x647c)
distance heap_addr vm->ip
>>> hex(-0x191f0 // 4)
'-0x647c'
3. let vm->ip[pc] = 0x666
4. jmp to the backdoor

## payload3(calculate)
1. login first(user)
2. use mov to get the user->function pointer address
3. use sub/add to calculate the backdoor's address
4. use mov to write the user->function pointer address
5. use show to trigger backdoor

mov eax, [-offset]
sub eax, (puts - system)
mov [-offset], eax

login accounts have sent to your emails, practice time: 1/24 18:00 - 2/5 23:59

# 2nd demo - mqda
## payload1
easy access backdoor in function 0x00000000000010B0

## payload2
get_heap_1370 finish a 4-level-page table
the get_heap_1370 use malloc to get a heap, and don't clear the information left.

level-1-page(p)
addr10 | addr11
addr12 | addr13

free(p), malloc(0x800)
level-1-page(p)
addr10(user set address) | (main_arena about address(heap))
addr12 | addr13

visit 0x00010203 -> level10 page -> addr10
visit 0x01010203 -> level11 page -> (main_arena about address(heap))

level3(r)
addr30 | addr31
addr32 | addr33
r 

addr34 = r

### idea
1. use left information to leak libc and heap
2. use left information to build a chain to finish aribtrary read and write
3. leak libc.symbols[environ] to leak stack address
4. write ret_address -> pop_rdi + "/bin/sh" + system

0x23000

1: 0x00
2: 0x02
3: 0x30
4: 0x00

0x23100
1: 0x00
2: 0x02
3: 0x31
4: 0x00

0x4032c
1: 0x00
2: 0x04
3: 0x03
4: 0x2c

level3(p)
addr30 | addr31
addr32 | p
value


w_ins -> value
r_ins <- addr of value(abr)
w_ins -> addr of value(abw)

0x0002 -> level(p)
write(0x00020320) -> value
read(0x00020400) -> data of value address(abr)
write(0x00020400) -> write value address(abw)

# patch theory
## change data
1. patch the 0x18B -> 0x180
.text:0000000000001DFC 41 81 FE 8B 01 00 00                    cmp     r14d, 18Bh
->
.text:0000000000001DFC 41 81 FE 80 01 00 00                    cmp     r14d, 180h


char buf[0x80];
read(0, buf, 0x100
0x100 -> 0x80 (change data)
## add segements
we need to choose a segement to store some instruction(two condition)
(1) the segement has execute permission
(2) change the segement's data doesn't influent the program
-> eh_frame or eh_frame_hdr

### how?
patch function sub_10B0 as an example:

.text:00000000000018E9 E8 C2 F7 FF FF                          call    sub_10B0
.text:00000000000018EE 66 0F EF C0                             pxor    xmm0, xmm0
.text:00000000000018F2 48 8D 3D 2A 17 00 00                    lea     rdi, aCodeLength ; "Code Length> "

call: 5 bytes, 1 byte(E8) + 4 bytes offset
4 bytes offset(target - next_instruction_address)
in the demo:
target = 0x10B0
next_instruction_address: 0x00000000000018E9 + 5
offset = target - next_instruction_address
>>> hex((0x10B0 - (0x00000000000018E9 + 5)) & 0xffffffff)
'0xfffff7c2'

>>> hex(0x000003160 - (0x00000000000018E9 + 5))
'0x1872'

E8 72 18 00 00

>>> hex((0x10B0 - (0x0000000000003162 + 5) & 0xffffffff))
'0xffffdf49'
E8 49 df ff ff

1. choose the address in eh_frame or eh_frame_hdr
2. change the call/jmp instruction to the address choosed
3. add the instructions in the address
4. use ret/jmp instruction to jmp back

refer to patch.py(tools keypatch)

## compress instruction
1. less instruction
2. less length instruction

1. less instruction
movzx   eax, byte ptr [rsp+58h+var_58]
mov     edx, eax
and     edx, 1Fh
cmp     dl, 14h
=>
movzx   edx, byte ptr [rsp+58h+var_58]
and edx, 1Fh
cmp dl, 14h
2. less length instruction
mov eax, 0
>>> len(asm("mov eax, 0"))
5
xor eax, eax (eax = eax ^ eax = 0)
>>> len(asm("xor eax, eax"))
2

## add logic
int v3 < 0x100
1. 0 < v3 < 0x100
2. unsigned int v3 < 0x100

structure of jmp instruction
in x86 assembly:
1. 2 bytes, 1 byte type + 1 byte offset
2. 6 bytes, 2 byte type + 4 byte offset
if(a < b){
	block1;
}
else{
	block2;
}
0x10: je 0x200
offset = 4 byte offset

1. 7e (0x80 - 0x10)

.text:0000000000002732 3B 48 04                                cmp     ecx, [rax+4]
.text:0000000000002735 0F 8F A5 02 00 00                       jg      loc_29E0
=>
.text:0000000000002732 3B 48 04                                cmp     ecx, [rax+4]
.text:0000000000002735 0F 87 A5 02 00 00                       ja      loc_29E0

v3 > result[1] 
=>
v3 > (unsigned int)result[1] 
