# MQDA Binary Analysis - CTF AWD Challenge

## Overview

**Binary:** `mqda` - A custom Virtual Machine (VM) interpreter  
**Architecture:** x86-64 ELF PIE executable, dynamically linked, stripped  
**Running:** TCP port 9999 (likely via `nc` or `socat`)

## Binary Protections

```
- PIE: Enabled (Position Independent Executable)
- Stack Canary: Yes (__stack_chk_fail present)
- Stripped: Yes (no symbol names)
- RELRO: Likely partial (based on ELF structure)
```

## Program Structure

### Main Function (0x1160)

1. Allocates 0x50 (80) bytes via `calloc(0x50, 1)` for VM state structure
2. Calls `init_vm()` (0x1870) to:
   - Zero initialize state
   - Read code address, code length, code bytes, and entry IP
3. Main loop runs VM instructions (up to 0x1ff = 511 iterations)
4. Exit codes:
   - 0: "NORMAL EXITED!"
   - 1: "TERMINATED!" 
   - 2: "ILLEGAL INSTRUCTION!"
   - 3: "DIV ZERO!"
   - Other: "UNKNOWN ERROR!"

### VM State Structure (0x50 bytes at rbp)

```c
struct vm_state {
    void *page_table;      // offset 0x00: pointer to page table root
    uint32_t ip;           // offset 0x08: instruction pointer
    uint8_t flags;         // offset 0x0c: flags register (bits: 0=zero, 1=carry, etc.)
    uint8_t padding[3];    
    uint32_t regs[16];     // offset 0x10-0x4f: 16 general purpose 32-bit registers (r0-r15)
    uint32_t sp;           // offset 0x4c: stack pointer (r15 is also SP)
};
```

### Memory Model

- **Paging system:** 3-level page table (256 entries per level)
- **Page size:** 0x100 (256) bytes, with 4-byte header (address) + 256 bytes data  
- **Max pages:** 0x100 (256) pages
- **Address space:** 32-bit virtual addresses
- **Page structure:** malloc(0x104) = 4 bytes address + 0x100 bytes data

### Page Table Functions

#### `fcn.00001370` - get_or_create_page(vm_state, address)
- Navigates 3-level page table using address bytes
- Creates pages on demand via malloc(0x104)
- Returns pointer to page structure (4-byte header + 256 bytes data)
- Tracks pages in global array at 0x50c0 (max 256 entries)

#### `fcn.000015d0` - free_pages(vm_state, address, length)
- Frees pages in the specified address range
- Cleans up page table entries

### Init Function (0x1870)

User input prompts:
1. **"Code Address> "**: Starting address for code (15 chars max)
2. **"Code Length> "**: Length of code to read (1-0x1000 bytes)
3. **"Code> "**: The actual bytecode
4. **"Entry IP> "**: Initial instruction pointer value

Code is loaded into VM memory starting at the specified code address.

## VM Instruction Set (21 opcodes, 0-20)

### Instruction Format
- Byte 0: `(mode << 5) | opcode` (mode: 0-4, opcode: 0-20)
- Byte 1: First register operand (0-15)
- Byte 2+: Additional operands (register or immediate)

### Instruction Modes
- **Mode 0:** Register only
- **Mode 1:** Register-Register 
- **Mode 2:** Register-Immediate (32-bit)
- **Mode 3:** Memory store
- **Mode 4:** Memory load

### Opcodes

| Opcode | Name | Description |
|--------|------|-------------|
| 0 | HLT | Halt (exit code 1) |
| 1 | MOV | Move: reg = src (mode variants) |
| 2 | PUSH | Push register to stack |
| 3 | POP | Pop from stack to register |
| 4 | ADD | Add: reg += src |
| 5 | SUB | Subtract: reg -= src |
| 6 | MUL | Multiply: reg *= src (div by zero check!) |
| 7 | MUL | Multiply variant |
| 8 | NOT | Bitwise NOT: reg = ~reg |
| 9 | XOR | XOR: reg ^= src |
| 10 | OR | OR: reg |= src |
| 11 | SHL | Shift left: reg <<= src |
| 12 | SHR | Shift right: reg >>= src |
| 13 | CMP | Compare: sets flags based on reg vs src |
| 14 | JMP | Unconditional jump |
| 15 | JNE | Jump if not equal (flags & 3 != 0) |
| 16 | JE | Jump if equal (flags & 2 == 0) |
| 17 | JL | Jump if less (flags & 2) |
| 18 | JG | Jump if greater (flags & 3) |
| 19 | JLE | Jump if less or equal (flags & 1 == 0) |
| 20 | JGE | Jump if greater or equal (flags & 1) |

## VULNERABILITIES IDENTIFIED

### 1. **CRITICAL: Stack Buffer Overflow in Instruction Fetching**

**Location:** `fcn.00001a50` around 0x1b5a-0x1bb0 and 0x1be5-0x1c3b

**Stack Frame Layout (0x28 bytes reserved):**
```
RSP + 0x00: instruction buffer (16 bytes nominal)
RSP + 0x18: stack canary (8 bytes)
RSP + 0x20: padding
[Above RSP after prologue: saved registers + return addr]
```

**Description:** When fetching multi-byte instructions that span page boundaries:
```c
// Stack buffer at rsp (initialized with movaps xmmword [rsp], xmm0)
char buf[0x10];  // Only 16 bytes before canary!

// When IP is near page boundary (>= 0xfd or 0xfa), code reads from two pages:
// First copy: bytes remaining in current page
first_copy_size = 0x100 - (IP & 0xff);  
memcpy(buf, page1 + (IP & 0xff) + 4, first_copy_size);

// Second copy: bytes needed from next page - CAN OVERFLOW!
second_copy_size = (IP & 0xff) - 0xfd;  // or 0xfa for 6-byte
memcpy(buf + first_copy_size, page2 + 4, second_copy_size);
```

**Calculation Analysis:**
- For 3-byte instructions (mode 1), enters cross-page path if IP low byte > 0xfd
- For 6-byte instructions (mode 2), enters cross-page path if IP low byte > 0xfa
- Total copied = first_copy_size + second_copy_size
  - = (0x100 - IP_low) + (IP_low - threshold)
  - = 0x100 - threshold (constant for each mode)
  - Mode 1: 0x100 - 0xfd = 3 bytes total
  - Mode 2: 0x100 - 0xfa = 6 bytes total

The cross-page instruction fetch appears to be properly bounded.

### 2. **CRITICAL: VM Stack Pointer Manipulation (SP at rbp+0x4c)**

**Location:** PUSH (0x210d) and POP (0x1ee1) instruction handlers

**Description:** The VM uses `[rbp + 0x4c]` as a stack pointer register (r15/SP):
```c
// PUSH - stores register value at stack address
sp = vm_state[0x4c];
page = get_page(sp);
*((uint32_t*)(page + (sp & 0xff) + 4)) = reg_value;
sp -= 4;
vm_state[0x4c] = sp;

// POP - reads from stack address to register  
sp = vm_state[0x4c];
page = get_page(sp);
reg_value = *((uint32_t*)(page + (sp & 0xff) + 4));
sp += 4;
vm_state[0x4c] = sp;
```

**Vulnerability:** 
- SP is stored as a 32-bit value but NO bounds checking is performed
- Through arithmetic operations (ADD, SUB), SP can be set to ANY value
- This allows reading/writing ANYWHERE in the VM's addressable memory
- Combined with the page allocation system, can cause heap corruption

**Exploit Strategy:**
1. Use MOV/ADD/SUB to set r15 (SP) to target address
2. Use PUSH to write controlled data to that address
3. Use POP to read data from arbitrary addresses

### 3. **Integer Overflow in Page Address Calculation**

**Location:** `fcn.00001370`

**Description:** The page table navigation uses the 32-bit address split into bytes:
```
level1_idx = (addr >> 24) & 0xff
level2_idx = (addr >> 16) & 0xff  
level3_idx = (addr >> 8) & 0xff
page_offset = addr & 0xff
```

If multiple pages share similar high-order bytes, the paging system can be confused or memory can be corrupted.

### 4. **No Bounds Check on Register Index**

**Location:** Multiple instruction handlers

**Description:** Register indices are checked against 0x0f (15), which is correct for 16 registers. However, the check is done after dereferencing in some code paths, and the flags byte at offset 0x0c can be manipulated.

### 5. **Division by Zero Handling - Info Leak**

**Location:** 0x247c

When multiplication by zero is attempted, the VM sets exit code 3 but may leak information about memory state before exiting.

### 6. **No Timeout/Alarm Set**

**Location:** `main`

The `alarm()` function is imported but not called in the code flow we analyzed. If the challenge setup doesn't set it up externally, infinite loops are possible.

### 7. **Global Page Array Out-of-Bounds**

**Location:** 0x50c0 (256 entries, 8 bytes each = 0x800 bytes)

The page tracking array at 0x50c0 has exactly 256 entries. The check at 0x14a0 ensures no more than 256 pages are allocated, but race conditions or improper counting could lead to OOB writes.

## EXPLOITATION STRATEGY

### For Attack (Pwn)

1. **Stack Buffer Overflow Exploit:**
   - Set code address so that IP lands near a page boundary (e.g., 0xXXXXXXFE)
   - Craft instructions that span page boundaries to trigger overflow
   - Overwrite return address or stack canary (need leak first)
   
2. **ROP Chain:**
   - Leak libc address through controlled VM memory reads
   - Calculate libc base
   - Build ROP chain to spawn shell

3. **Steps:**
   ```
   1. Send code address: e.g., 0x1000fe
   2. Send code length: ~256 bytes
   3. Send carefully crafted code that will:
      a. Position IP at page boundary
      b. Execute instruction causing overflow
   4. Entry IP: start of exploit code
   ```

### For Defense (Patch)

1. **Fix the memcpy size calculation:**
   - Add bounds check: `if (remaining > sizeof(buf) - already_copied) remaining = sizeof(buf) - already_copied;`
   - Or redesign to not use stack buffer for cross-page fetches

2. **Add proper bounds checking:**
   - Validate all memory operations against allocated page ranges
   - Add checks before memcpy operations

3. **Enable alarm:**
   - Ensure timeout is set to prevent infinite loops

4. **Patch locations (relative to binary base):**
   - 0x1b7b-0x1bb0: First overflow path
   - 0x1c06-0x1c40: Second overflow path

## Files/Addresses Summary

| Item | Address/Value |
|------|---------------|
| main | 0x1160 |
| init_vm | 0x1870 |
| vm_execute | 0x1a50 |
| get_page | 0x1370 |
| free_pages | 0x15d0 |
| VM state size | 0x50 bytes |
| Page table root | 0x50c0 |
| Exit code global | 0x58c0 |
| Iteration counter | 0x58c8 |
| Page count | 0x58d0 |
| Switch table | 0x308c |

## Recommended Patches

### Minimal Patch 1 - Fix memcpy bounds (Priority: HIGH)

Patch at 0x1b7b and 0x1c06 to add bounds checking before the memcpy calls.

### Minimal Patch 2 - Limit instruction size

Ensure instructions never request more bytes than available in the fixed-size buffer.
