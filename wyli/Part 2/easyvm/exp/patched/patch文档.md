# patch1

在memcpy前加一个长度判断，要么将下面的`len-name_len`修改为 `passwd_len-name_len`。要么在memcpy前检查passed_len是否超过0x17f，用于修改数据泄漏和溢出漏洞。

给的patch1，是通过在memcpy前检查passed_len的范围。

```c
  //vul1 
  if((len - name_len) > MAX_PASSWORDS+2+8){
      //printf("packet is wrong len %d\n",len - name_len);
      printf("packet is wrong \n");
      conn_proto->user->name_len = 0;
      conn_proto->user->passwd_len = 0;
      return -1;
  }
  memcpy(conn_proto->user->passwd, name_off+1, passwd_len);
```

# Patch2 

指令运行前，只检查了指令下标的最大值，没有检查是否为负值。

```c
void tvm_vm_run(struct tvm_ctx *vm)
{
	int *instr_idx = &vm->mem->registers[0x8].i32;
	*instr_idx = vm->prog->start;

	for (; vm->prog->instr[*instr_idx] != -0x1; ++(*instr_idx)) {
    //vul2
		if (*instr_idx > vm->prog->num_instr) {
			return;
		}

		tvm_step(vm, instr_idx);
	}
}
```

需要在指令执行前，检查指令下标是否小于0。

```c
int *__fastcall vm_run(int **a1)
{
  int *result; // rax
  int v2; // ecx

  result = *a1;
  v2 = **a1;
  *(_DWORD *)(*((_QWORD *)a1[1] + 3) + 64LL) = v2;
  if ( *(_DWORD *)(*((_QWORD *)result + 1) + 4LL * v2) != -1 )
    JUMPOUT(0x451ALL);
  return result;
}

.eh_frame:000000000000451A loc_451A:                               ; CODE XREF: sub_26A0:loc_2722↑j
.eh_frame:000000000000451A                 cmp     ecx, [rax+4]
.eh_frame:000000000000451D                 jg      loc_29D0
.eh_frame:0000000000004523                 cmp     ecx, 0
.eh_frame:0000000000004526                 jl      loc_29D0
.eh_frame:000000000000452C                 jmp     near ptr loc_272A+1
```

# Patch3

tvm_parse_args 解析指令的操作数时，并没有只检查了内存读取操作的是否超过了内存的最大值，没有检查是否小于最小值。

```c
static int **tvm_parse_args(
	struct tvm_ctx *vm, const char **instr_tokens, int *instr_place)
{
	int **args = calloc(sizeof(int *), MAX_ARGS);

	for (int i = 0; i < MAX_ARGS; ++i) {
		if (!instr_tokens[*instr_place+1 + i]
			|| !strlen(instr_tokens[*instr_place+1 + i]))
			continue;

		char *newline = strchr(instr_tokens[*instr_place+1 + i], '\n');

		if (newline)
			*newline = 0;

		/* Check to see if the token specifies a register */
		int *regp = token_to_register(
			instr_tokens[*instr_place+1 + i], vm->mem);

		if (regp) {
			args[i] = regp;
			continue;
		}

		/* Check to see whether the token specifies an address */
		if (instr_tokens[*instr_place+1 + i][0] == '[') {
			char *end_symbol = strchr(
				instr_tokens[*instr_place+1 + i], ']');

			if (end_symbol) {
				*end_symbol = 0;

				int *dest = &((int *)vm->mem->mem_space)[
					tvm_parse_value(instr_tokens[
						*instr_place+1 + i] + 1)];
				// check mem space boundary
        //vul3
				if ((char *)dest > (char *)vm->mem->mem_space + vm->mem->mem_space_size) {
				//if ((char *)dest < (char *)mem->registers[0x7].i32_ptr) {
					exit(-1);
				}

				args[i] = dest;

				continue;
			}
		}

		/* Check if the argument is a label */
		int addr = tvm_htab_find(
			vm->prog->label_htab, instr_tokens[*instr_place+1 + i]);

		if (addr != -1) {
			args[i] = tvm_add_value(vm, addr);
			continue;
		}

		/* Fuck it, parse it as a value */
		args[i] = tvm_add_value(
			vm, tvm_parse_value(instr_tokens[*instr_place+1 + i]));
	}

	return args;
}
```

需要在取操作数时，检查操作数的范围。但是也可以复杂的方法直接在每条指令执行时，检查内存的地址范围。

```c
__int64 __fastcall sub_2E10(__int64 *a1, const char ***a2)
{
	strtoul(v45, 0LL, v48);
  JUMPOUT(0x4531LL);
}

.eh_frame:0000000000004531 loc_4531:                               ; CODE XREF: sub_2E10+4B7↑j
.eh_frame:0000000000004531                 add     rdx, [rcx+8]
.eh_frame:0000000000004535                 cmp     rdx, rax
.eh_frame:0000000000004538                 jb      loc_3412
.eh_frame:000000000000453E                 mov     rdx, [rcx+8]
.eh_frame:0000000000004542                 cmp     rdx, rax
.eh_frame:0000000000004545                 ja      loc_3412
.eh_frame:000000000000454B                 jmp     loc_32D4
```

