# Binary Analysis Summary: `easyvm`

## Overview
This is a **custom Virtual Machine (VM) interpreter** that:
1. Reads packets from stdin
2. Decrypts/XORs input with a time-seeded key
3. Parses and executes VM bytecode
4. Has a backdoor function that can call `/bin/sh`

## Pseudocode

```c
// main()
void main() {
    setvbuf(stdin/stdout/stderr, NULL, _IONBF, 0);
    context = malloc(0x318);
    init_random_xor_key();  // Seeds with time(), generates 16 random 32-bit keys
    connect(context);       // Main loop
    free(context);
}

// init_random_xor_key() @ 0x1270
void init_random_xor_key() {
    int seed = time(NULL);
    printf("Begin connect: %d\n", seed);  // <-- IMPORTANT: prints seed!
    srand(seed);
    for (int i = 0; i < 16; i++)
        xor_table[i] = rand();  // @ 0x6240
}

// connect() @ 0x22b0 - Main packet loop
int connect(context) {
    char* buf = malloc(0x1000);
    while (1) {
        puts("Input manager packet: ");
        len = read(0, buf, 0x1000);
        if (len <= 0) break;
        
        // XOR decrypt input with rotating key
        for (int i = 0; i < len; i++) {
            key_idx = (some_counter + i) % 16;
            buf[i] ^= xor_table[key_idx][(i % 4)];
        }
        
        process_packet(context, &buf, len);
    }
}

// process_packet() @ 0x2200
void process_packet(ctx, buf_ptr, len) {
    if (len <= 7) error("Packet is too short");
    
    uint32_t version = bswap32(*(uint32_t*)buf);  // Big-endian!
    uint32_t opcode = bswap32(*(uint32_t*)(buf+4));
    
    if (version < 1 || version > 3) error("Packet Version is wrong");
    if (version == 1 && opcode >= 3) error("packet is wrong");
    
    if (version == 1) handle_login(ctx, buf, len);   // type 1: auth
    if (version == 2) handle_vm(ctx, buf, len);      // type 2: VM execution
}

// handle_login() @ 0x2060
void handle_login(ctx, buf, len) {
    switch (opcode) {
        case 0: // Login
            if (ctx->logged_in) return;
            if (login_check(ctx) == 1) {
                ctx->logged_in = 1;
                puts("login ok");
            }
            break;
        case 1: // Execute command (if logged in)
            if (!ctx->logged_in) {
                ctx->func_ptr = puts;  // Sets function pointer!
                puts("someting is wrong\n");
            } else {
                // Validates session, calls ctx->func_ptr(ctx->cmd_buf)
            }
            break;
        case 2: // Logout
            ctx->logged_in = 0;
            puts("logout ok");
            break;
    }
}

// BACKDOOR @ 0x18a0 - Password encoder that overwrites XOR key
void password_encoder(char* input) {
    char* buf = malloc(0x200);
    strcpy(buf, input);  // Copies user password
    // Complex SIMD multiplication/XOR transformation
    // Then OVERWRITES the global XOR key table with derived values!
    // This allows you to predict future packet decryption
}
```

## Packet Structure (Big-Endian!)

```
+0x00: uint32_t version   (1=auth, 2=VM)
+0x04: uint32_t opcode
+0x08: payload...
```

### Login Packet (version=1, opcode=0)
```
+0x00: 0x00000001 (version)
+0x04: 0x00000000 (opcode=login)
+0x08: uint32_t payload_len
+0x0c: "username:password"
+....: uint64_t session_token
```

## VM Instructions (version=2)

The VM supports these opcodes:

| Opcode | Instruction |
|--------|-------------|
| 0 | nop |
| 1 | int |
| 2 | mov |
| 3 | push |
| 4 | pop |
| 5 | pushf |
| 6 | popf |
| 7 | inc |
| 8 | dec |
| 9 | add |
| 10 | sub |
| 11 | mul |
| 12 | div |
| 13 | mod |
| 14 | rem |
| 15 | not |
| 16 | xor |
| 17 | and |
| 18 | shl |
| 19 | shr |
| 20 | cmp |
| 21 | jmp |
| 22 | call |
| 23 | ret |
| 24 | je |
| 25 | jne |
| 26 | jg |
| 27 | jge |
| 28 | jl |
| 29 | jle |
| 30 | prn |

## Backdoor

- String at `0x4260`: `"Warning, you enter the backdoor (normal function, Don't patch)"`
- String at `0x4258`: `"/bin/sh"`
- The backdoor can be triggered via opcode=1 after manipulating function pointers

## How to Connect

Based on the CSV file, the service runs at: **`172.24.83.24`** (IP for "ctf" login)

```bash
# Connect via netcat (the binary reads from stdin)
nc 172.24.83.24 <PORT>

# Or run locally:
./easyvm
```

**Important:** The XOR key is time-based. The binary prints `"Begin connect: %d\n"` with the seed, so you can reconstruct the XOR table by using the same seed with `srand(seed)` and calling `rand()` 16 times.

## Exploitation Hints

1. Capture the time seed from `"Begin connect: %d\n"`
2. Regenerate XOR key table locally
3. XOR-encrypt your packets before sending
4. Login with valid credentials (format: `username:password`)
5. The backdoor at 0x18a0 can overwrite the XOR table - useful for known-plaintext attacks
6. Opcode 1 with proper session token calls a function pointer that can be manipulated to `/bin/sh`

## Key Addresses

| Address | Description |
|---------|-------------|
| 0x1270 | init_random_xor_key() |
| 0x18a0 | password_encoder() (backdoor) |
| 0x2060 | handle_login() |
| 0x2200 | process_packet() |
| 0x22b0 | connect() main loop |
| 0x2470 | main() |
| 0x6240 | XOR key table (16 x 4 bytes) |
| 0x60d0 | VM instruction string table |

## Connection Info (from easyvm.csv)

- **Target IP**: 172.24.83.24
- **Login name**: ctf
- **PEM key**: pvt-ctf-d3a3a2404382875310a0a2136635c756.pem
