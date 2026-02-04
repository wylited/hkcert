# Patcherex Usage Report

A comprehensive guide to using the **patcherex** binary patching framework. Patcherex was originally developed for the DARPA Cyber Grand Challenge (CGC) and has been extended to support various architectures including x86, x86-64, ARM, AArch64, MIPS, and PowerPC.

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [Patch Types](#patch-types)
5. [Backends](#backends)
6. [Techniques](#techniques)
7. [Basic Usage Examples](#basic-usage-examples)
8. [Advanced Examples](#advanced-examples)
9. [Creating a Prefix Detour (Print "ciallo!!" After Each Call)](#creating-a-prefix-detour-print-ciallo-after-each-call)
10. [Architecture Support](#architecture-support)
11. [API Reference](#api-reference)
12. [Troubleshooting](#troubleshooting)

---

## Overview

Patcherex is a binary patching framework built on top of **angr** that allows you to:

- Insert code at specific addresses (detours/hooks)
- Add new code and data sections
- Replace functions
- Modify the entry point
- Apply various hardening techniques (shadow stack, CFI, etc.)

### Key Features

- **Multiple backends**: DetourBackend (reliable) and ReassemblerBackend (more powerful)
- **Architecture support**: i386, x86-64, ARM, AArch64, MIPS, PPC
- **Symbol resolution**: Reference patches by name using `{patch_name}` syntax
- **Automatic CFG generation**: Uses angr for control flow analysis
- **C code compilation**: Write patches in C code that gets compiled inline

---

## Installation

### System Dependencies

```bash
sudo apt-get install nasm clang
# Optional for AVR patching:
sudo apt-get install clang-10 gcc-avr binutils-avr avr-libc
```

### Python Installation

```bash
cd lasp/externals/patcherex
pip install -e .
```

### Dependencies (from setup.py)

- `angr` - Binary analysis framework
- `capstone` - Disassembly engine
- `keystone-engine` - Assembler engine
- `psutil` - Process utilities
- `pyelftools` - ELF file parsing
- `pyyaml` - YAML configuration
- `compilerex` - C compilation support

---

## Core Concepts

### 1. Patches

A **patch** is a single modification to a binary. Each patch has:
- A **name** (optional but recommended for referencing)
- **Dependencies** on other patches
- Specific parameters based on patch type

### 2. Backends

A **backend** is responsible for injecting patches into the binary:
- **DetourBackend**: Inserts jumps to detour code (more reliable)
- **ReassemblerBackend**: Disassembles and reassembles the binary (more powerful but less stable)

### 3. Techniques

A **technique** is a high-level component that analyzes a binary and returns a list of patches to apply (e.g., ShadowStack, CFI, Backdoor).

### 4. Symbol Resolution

Patches can reference each other using curly brace syntax:
```asm
call {my_function}      ; Calls the patch named "my_function"
mov eax, {my_data}      ; Loads address of patch named "my_data"
```

---

## Patch Types

### 1. InsertCodePatch

**Most commonly used patch.** Inserts code at a specific address that executes BEFORE the original instruction.

```python
from patcherex.patches import InsertCodePatch

code = '''
    pusha
    mov eax, 4          ; sys_write
    mov ebx, 1          ; stdout
    mov ecx, {message}  ; buffer
    mov edx, 8          ; length
    int 0x80
    popa
'''
patch = InsertCodePatch(0x08048457, code, name="my_hook")
```

**Parameters:**
- `addr` (int): Address where to insert the code
- `code` (str): Assembly code to insert
- `name` (str, optional): Patch name for referencing
- `priority` (int): Higher priority patches are applied first when multiple patches target the same address
- `stackable` (bool): If True, can be stacked with other patches at the same address

### 2. AddCodePatch

Adds a callable function/code block that other patches can reference.

```python
from patcherex.patches import AddCodePatch

code = '''
    ; eax = buffer, ebx = length
    pusha
    mov ecx, eax
    mov edx, ebx
    mov eax, 2          ; sys_transmit (CGC) or 4 (Linux write)
    mov ebx, 1          ; stdout
    int 0x80
    popa
    ret
'''
patch = AddCodePatch(code, name="print_function")
```

**Parameters:**
- `asm_code` (str): Assembly or C code
- `name` (str): Required for referencing
- `is_c` (bool): If True, code is C instead of assembly
- `optimization` (str): Compiler optimization level (e.g., "-Oz")
- `compiler_flags` (str): Additional compiler flags

### 3. AddRODataPatch

Adds read-only data (strings, constants).

```python
from patcherex.patches import AddRODataPatch

patch = AddRODataPatch(b"Hello World!\x00", name="hello_string")
```

### 4. AddRWDataPatch

Adds read-write (uninitialized) data.

```python
from patcherex.patches import AddRWDataPatch

patch = AddRWDataPatch(256, name="my_buffer")  # 256 bytes of zeroed memory
```

### 5. AddRWInitDataPatch

Adds read-write initialized data.

```python
from patcherex.patches import AddRWInitDataPatch

patch = AddRWInitDataPatch(b"\x00\x00\x00\x00", name="counter")
```

### 6. AddEntryPointPatch

Adds code that executes at program startup (before the original entry point).

```python
from patcherex.patches import AddEntryPointPatch

code = '''
    mov eax, 4
    mov ebx, 1
    mov ecx, {startup_msg}
    mov edx, 12
    int 0x80
'''
patch = AddEntryPointPatch(code, name="startup_code", priority=1)
```

**Parameters:**
- `asm_code` (str): Assembly code
- `priority` (int): Order of execution (higher = earlier)
- `after_restore` (bool): If True, runs after register restoration

### 7. InlinePatch

Replaces instruction(s) at a specific address in-place.

```python
from patcherex.patches import InlinePatch

# Replace instruction at 0x08048442 with new assembly
patch = InlinePatch(0x08048442, "LEA EDX, [EAX + 0xffffe4f3]", num_instr=1)
```

### 8. ReplaceFunctionPatch

Replaces an entire function with new C code.

```python
from patcherex.patches import ReplaceFunctionPatch

c_code = '''
int add(int a, int b) {
    return a + b;
}
'''
patch = ReplaceFunctionPatch(0x400536, 36, c_code, symbols={"printf": 0x400610})
```

**Parameters:**
- `addr` (int): Function start address
- `size` (int): Original function size in bytes
- `code` (str): New C code
- `symbols` (dict): External symbol addresses

### 9. RawMemPatch

Directly patches memory at a virtual address.

```python
from patcherex.patches import RawMemPatch

patch = RawMemPatch(0x080484f0, b"No")  # Replace 2 bytes at address
```

### 10. RawFilePatch

Directly patches the file at a file offset.

```python
from patcherex.patches import RawFilePatch

patch = RawFilePatch(0x4f0, b"No")  # Replace 2 bytes at file offset
```

### 11. RemoveInstructionPatch

NOPs out an instruction.

```python
from patcherex.patches import RemoveInstructionPatch

patch = RemoveInstructionPatch(0x08048449, 7)  # NOP 7 bytes at address
```

### 12. AddLabelPatch

Creates a named label for an existing address.

```python
from patcherex.patches import AddLabelPatch

patch = AddLabelPatch(0x080484f4, "my_label")
# Now you can use {my_label} in other patches
```

---

## Backends

### DetourBackend

The most reliable backend. Works by inserting jumps (detours) to redirect execution to your patch code.

```python
from patcherex.backends.detourbackend import DetourBackend

backend = DetourBackend("./target_binary")
backend.apply_patches(patches)
backend.save("./patched_binary")
```

**How it works:**
1. Analyzes the CFG to find safe detour points
2. Replaces instructions with a jump to new code
3. The new code executes your patch, then executes the original displaced instructions
4. Jumps back to continue normal execution

**Advantages:**
- More reliable (doesn't break binaries as often)
- Works with stripped binaries

**Limitations:**
- Produces larger binaries
- May fail if no suitable detour location exists

### ReassemblerBackend

More powerful but less stable. Disassembles and reassembles the entire binary.

```python
from patcherex.backends.reassembler_backend import ReassemblerBackend

backend = ReassemblerBackend("./target_binary")
backend.apply_patches(patches)
backend.save("./patched_binary")
```

**Advantages:**
- More flexible patching options
- Can produce smaller output

**Limitations:**
- More likely to break binaries
- Requires better binary analysis

---

## Techniques

Patcherex includes several built-in security techniques:

| Technique | Description |
|-----------|-------------|
| `ShadowStack` | Maintains a separate stack to protect return addresses |
| `StackRetEncryption` | Encrypts return addresses on the stack |
| `SimpleCFI` | Simple Control Flow Integrity |
| `IndirectCFI` | CFI for indirect calls/jumps |
| `TransmitProtection` | Protects transmit system calls |
| `ShiftStack` | Shifts the stack for protection |
| `NxStack` | Makes the stack non-executable |
| `Backdoor` | Adds a backdoor (for CTF purposes) |
| `Adversarial` | Adversarial patches |
| `Bitflip` | Bitflip protection |

### Using Techniques

```python
from patcherex.techniques.shadowstack import ShadowStack
from patcherex.backends.detourbackend import DetourBackend

backend = DetourBackend("./binary")
technique = ShadowStack("./binary", backend)
patches = technique.get_patches()
backend.apply_patches(patches)
backend.save("./patched")
```

---

## Basic Usage Examples

### Example 1: Simple "Hello World" Hook

```python
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import InsertCodePatch, AddRODataPatch

backend = DetourBackend("./target")
patches = []

# Add the string data
patches.append(AddRODataPatch(b"Hello World!\n\x00", name="hello_msg"))

# Insert code that prints "Hello World!" before instruction at 0x08048457
injected_code = '''
    pusha
    mov eax, 4          ; sys_write (Linux)
    mov ebx, 1          ; stdout
    mov ecx, {hello_msg}
    mov edx, 13         ; length
    int 0x80
    popa
'''
patches.append(InsertCodePatch(0x08048457, injected_code, name="hello_hook"))

backend.apply_patches(patches)
backend.save("./patched_target")
```

### Example 2: Entry Point Modification

```python
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import AddEntryPointPatch, AddCodePatch

backend = DetourBackend("./target")
patches = []

# Exit immediately with code 0x42
exit_code = '''
    mov eax, 1      ; sys_exit
    mov ebx, 0x42   ; exit code
    int 0x80
'''
patches.append(AddCodePatch(exit_code, name="exit_code"))

# Add entry point patch that calls our exit
entry_code = '''
    call {exit_code}
'''
patches.append(AddEntryPointPatch(entry_code))

backend.apply_patches(patches)
backend.save("./patched_target")
```

### Example 3: Function Hook with Shared Library

```python
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import InsertCodePatch, AddCodePatch, AddRODataPatch

backend = DetourBackend("./target")
patches = []

# Add format string
patches.append(AddRODataPatch(b"Function called!\n\x00", name="log_msg"))

# Add print function
print_func = '''
    pusha
    mov ecx, eax        ; buffer from eax
    xor edx, edx
    _len_loop:
        cmp BYTE [ecx + edx], 0
        je _len_done
        inc edx
        jmp _len_loop
    _len_done:
    mov eax, 4
    mov ebx, 1
    int 0x80
    popa
    ret
'''
patches.append(AddCodePatch(print_func, name="print_string"))

# Hook at function start
hook_code = '''
    pusha
    mov eax, {log_msg}
    call {print_string}
    popa
'''
patches.append(InsertCodePatch(0x08048500, hook_code, name="func_hook"))

backend.apply_patches(patches)
backend.save("./patched_target")
```

---

## Advanced Examples

### Example 4: C Code Patch

```python
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import AddCodePatch, InsertCodePatch
import patcherex.utils as utils

backend = DetourBackend("./target")
patches = []

# Add C function
c_code = '''
__attribute__((fastcall)) int multiply(int a, int b) {
    return a * b;
}
'''
patches.append(AddCodePatch(c_code, name="c_multiply", is_c=True, optimization="-Oz"))

# Call the C function from assembly
asm_wrapper = utils.get_nasm_c_wrapper_code("c_multiply", get_return=True)
hook_code = f'''
    mov ecx, 5      ; first arg
    mov edx, 10     ; second arg
    {asm_wrapper}
    ; result now in eax (should be 50)
'''
patches.append(InsertCodePatch(0x08048500, hook_code, name="call_c_func"))

backend.apply_patches(patches)
backend.save("./patched_target")
```

### Example 5: Multiple Hooks with Dependencies

```python
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import InsertCodePatch, AddRWDataPatch

backend = DetourBackend("./target")
patches = []

# Counter variable
patches.append(AddRWDataPatch(4, name="call_count"))

# Initialize counter at entry
init_code = '''
    mov DWORD [{call_count}], 0
'''
patches.append(AddEntryPointPatch(init_code, name="init_counter"))

# Increment counter at each function call
inc_code = '''
    inc DWORD [{call_count}]
'''
hook1 = InsertCodePatch(0x08048500, inc_code, name="hook1")
hook2 = InsertCodePatch(0x08048600, inc_code, name="hook2")

# Dependencies: both hooks depend on the init code
hook1.dependencies.append(patches[-1])  # depends on init_counter
hook2.dependencies.append(patches[-1])

patches.extend([hook1, hook2])

backend.apply_patches(patches)
backend.save("./patched_target")
```

---

## Creating a Prefix Detour (Print "ciallo!!" After Each Call)

This is a detailed example showing how to create a hook that prints `"ciallo!!"` after every `call` instruction in a function, or more practically, at specific points in the program.

### Method 1: Hook Specific Addresses (Recommended)

Since hooking ALL calls automatically is complex, the practical approach is to hook specific addresses where calls occur:

```python
#!/usr/bin/env python3
"""
Example: Print "ciallo!!" after each call instruction
This hooks specific call sites to print the message after the call returns.
"""

from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import (
    InsertCodePatch,
    AddCodePatch,
    AddRODataPatch,
)


def create_ciallo_patches(binary_path, call_addresses):
    """
    Create patches to print "ciallo!!" after each call at the specified addresses.
    
    Args:
        binary_path: Path to the target binary
        call_addresses: List of addresses AFTER the call instruction (return addresses)
    
    Returns:
        List of patches
    """
    patches = []
    
    # Add the "ciallo!!" string (with newline)
    patches.append(AddRODataPatch(b"ciallo!!\n\x00", name="ciallo_string"))
    
    # Add a print function that we can call from our hooks
    # For x86 32-bit Linux (using write syscall)
    print_function = '''
        ; Prints "ciallo!!" to stdout
        ; Preserves all registers
        pusha
        pushf
        
        mov eax, 4              ; sys_write
        mov ebx, 1              ; fd = stdout
        mov ecx, {ciallo_string} ; buffer
        mov edx, 9              ; length ("ciallo!!\n")
        int 0x80
        
        popf
        popa
        ret
    '''
    patches.append(AddCodePatch(print_function, name="print_ciallo"))
    
    # Create a hook for each call site
    for i, addr in enumerate(call_addresses):
        hook_code = '''
            call {print_ciallo}
        '''
        patches.append(InsertCodePatch(
            addr,
            hook_code,
            name=f"ciallo_hook_{i}",
            priority=100  # High priority to ensure it runs
        ))
    
    return patches


def patch_binary(input_path, output_path, call_addresses):
    """
    Apply the patches to the binary.
    """
    backend = DetourBackend(input_path)
    patches = create_ciallo_patches(input_path, call_addresses)
    backend.apply_patches(patches)
    backend.save(output_path)
    print(f"Patched binary saved to: {output_path}")


# Example usage
if __name__ == "__main__":
    # Suppose we have a binary with calls at these addresses:
    # The addresses should point to where execution continues AFTER the call
    # (i.e., the instruction following the call)
    
    # Example: If there's a "call printf" at 0x08048450 and the call is 5 bytes,
    # you would hook 0x08048455 (the address after the call)
    
    call_return_addresses = [
        0x08048460,  # After first call
        0x08048490,  # After second call
        0x080484C0,  # After third call
    ]
    
    patch_binary(
        "./target_binary",
        "./target_binary_ciallo",
        call_return_addresses
    )
```

### Method 2: Hook BEFORE Calls (Prefix Detour)

If you want to print "ciallo!!" BEFORE each call executes:

```python
#!/usr/bin/env python3
"""
Example: Print "ciallo!!" BEFORE specific call instructions
"""

from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import (
    InsertCodePatch,
    AddCodePatch,
    AddRODataPatch,
)


def create_prefix_ciallo_patches(binary_path, call_instruction_addresses):
    """
    Create patches to print "ciallo!!" BEFORE each call.
    
    Args:
        binary_path: Path to the target binary
        call_instruction_addresses: List of addresses OF the call instructions
    """
    patches = []
    
    # Add the message string
    patches.append(AddRODataPatch(b"ciallo!!\n\x00", name="ciallo_str"))
    
    # Print function for x86-32 Linux
    print_func = '''
        pusha
        pushf
        mov eax, 4              ; sys_write
        mov ebx, 1              ; stdout
        mov ecx, {ciallo_str}
        mov edx, 9
        int 0x80
        popf
        popa
        ret
    '''
    patches.append(AddCodePatch(print_func, name="do_print_ciallo"))
    
    # Hook each call instruction
    for i, call_addr in enumerate(call_instruction_addresses):
        # This code runs BEFORE the call instruction
        pre_call_hook = '''
            call {do_print_ciallo}
        '''
        patches.append(InsertCodePatch(
            call_addr,
            pre_call_hook,
            name=f"pre_call_ciallo_{i}"
        ))
    
    return patches


# Usage
if __name__ == "__main__":
    backend = DetourBackend("./my_binary")
    
    # Addresses OF the call instructions (not after)
    call_sites = [0x08048456, 0x08048478, 0x080484A0]
    
    patches = create_prefix_ciallo_patches("./my_binary", call_sites)
    backend.apply_patches(patches)
    backend.save("./my_binary_patched")
```

### Method 3: Complete Example with Automatic Call Discovery

For a more complete solution that automatically finds call instructions:

```python
#!/usr/bin/env python3
"""
Complete example: Automatically find all call instructions in a function
and hook them to print "ciallo!!"
"""

import angr
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import (
    InsertCodePatch,
    AddCodePatch,
    AddRODataPatch,
)


def find_call_instructions(binary_path, function_addr=None):
    """
    Find all call instruction addresses in a binary or specific function.
    
    Returns list of (call_addr, next_instruction_addr) tuples
    """
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    
    call_sites = []
    
    if function_addr:
        # Only analyze specific function
        func = cfg.functions.get(function_addr)
        if func:
            blocks = list(func.blocks)
        else:
            blocks = []
    else:
        # Analyze all functions
        blocks = []
        for func in cfg.functions.values():
            blocks.extend(func.blocks)
    
    for block in blocks:
        try:
            cap_block = proj.factory.block(block.addr)
            for insn in cap_block.capstone.insns:
                if insn.mnemonic == 'call':
                    next_addr = insn.address + insn.size
                    call_sites.append((insn.address, next_addr))
        except:
            continue
    
    return call_sites


def create_ciallo_after_all_calls(binary_path, function_addr=None):
    """
    Create patches to print "ciallo!!" after every call in the binary
    or a specific function.
    """
    patches = []
    
    # String data
    patches.append(AddRODataPatch(b"ciallo!!\n\x00", name="ciallo_msg"))
    
    # Print function (x86-32 Linux)
    print_asm = '''
        pusha
        pushf
        mov eax, 4
        mov ebx, 1
        mov ecx, {ciallo_msg}
        mov edx, 9
        int 0x80
        popf
        popa
        ret
    '''
    patches.append(AddCodePatch(print_asm, name="print_ciallo_func"))
    
    # Find all calls
    call_sites = find_call_instructions(binary_path, function_addr)
    print(f"Found {len(call_sites)} call sites")
    
    # Create hooks for addresses AFTER each call (so it prints when call returns)
    for i, (call_addr, return_addr) in enumerate(call_sites):
        hook = '''
            call {print_ciallo_func}
        '''
        patch = InsertCodePatch(
            return_addr,  # Hook at return address (after call)
            hook,
            name=f"ciallo_after_call_{i}_{hex(call_addr)}"
        )
        patches.append(patch)
        print(f"  Hooking after call at {hex(call_addr)} -> {hex(return_addr)}")
    
    return patches


def main():
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python ciallo_patcher.py <input_binary> <output_binary> [function_addr]")
        print("Example: python ciallo_patcher.py ./target ./target_ciallo 0x08048500")
        sys.exit(1)
    
    input_binary = sys.argv[1]
    output_binary = sys.argv[2]
    func_addr = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    
    print(f"Patching {input_binary}...")
    
    backend = DetourBackend(input_binary)
    patches = create_ciallo_after_all_calls(input_binary, func_addr)
    
    try:
        backend.apply_patches(patches)
        backend.save(output_binary)
        print(f"Successfully created: {output_binary}")
    except Exception as e:
        print(f"Error applying patches: {e}")
        # Some patches may fail; the backend will skip them
        backend.save(output_binary)
        print(f"Saved with partial patches: {output_binary}")


if __name__ == "__main__":
    main()
```

### Method 4: x86-64 Version

For 64-bit binaries, the syscall interface is different:

```python
#!/usr/bin/env python3
"""
x86-64 version of the ciallo printer
"""

from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import (
    InsertCodePatch,
    AddCodePatch,
    AddRODataPatch,
)


def create_ciallo_patches_x64(call_addresses):
    """Create patches for x86-64 binaries."""
    patches = []
    
    # Add string
    patches.append(AddRODataPatch(b"ciallo!!\n\x00", name="ciallo_str"))
    
    # Print function for x86-64 Linux
    # Note: x86-64 uses different syscall numbers and registers
    print_func_x64 = '''
        push rax
        push rdi
        push rsi
        push rdx
        push rcx
        push r11
        
        mov rax, 1              ; sys_write (x86-64)
        mov rdi, 1              ; stdout
        lea rsi, [{ciallo_str}] ; buffer (may need PIE handling)
        mov rdx, 9              ; length
        syscall
        
        pop r11
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        pop rax
        ret
    '''
    patches.append(AddCodePatch(print_func_x64, name="print_ciallo"))
    
    # Create hooks
    for i, addr in enumerate(call_addresses):
        hook = '''
            call {print_ciallo}
        '''
        patches.append(InsertCodePatch(addr, hook, name=f"ciallo_x64_{i}"))
    
    return patches


# For PIE binaries (Position Independent Executables):
def create_ciallo_patches_x64_pie(call_addresses):
    """Create patches for PIE x86-64 binaries."""
    patches = []
    
    patches.append(AddRODataPatch(b"ciallo!!\n\x00", name="ciallo_str"))
    
    # PIE-aware print function
    print_func_pie = '''
        push rax
        push rdi
        push rsi
        push rdx
        push rcx
        push r11
        
        ; Get runtime base address for PIE
        call {pie_thunk}
        lea rsi, [rax + {ciallo_str}]
        
        mov rax, 1              ; sys_write
        mov rdi, 1              ; stdout
        mov rdx, 9              ; length
        syscall
        
        pop r11
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        pop rax
        ret
    '''
    patches.append(AddCodePatch(print_func_pie, name="print_ciallo"))
    
    for i, addr in enumerate(call_addresses):
        hook = '''
            call {print_ciallo}
        '''
        patches.append(InsertCodePatch(addr, hook, name=f"ciallo_pie_{i}"))
    
    return patches
```

---

## Architecture Support

### Supported Architectures

| Architecture | Backend Class | Notes |
|--------------|---------------|-------|
| i386 (x86-32) | `DetourBackendi386` | Full support |
| x86-64 | `DetourBackendi386` | Full support |
| ARM | `DetourBackendArm` | Thumb mode support |
| AArch64 | `DetourBackendAarch64` | 64-bit ARM |
| MIPS | `DetourBackendMips` | Big/little endian |
| PowerPC | `DetourBackendPpc` | 32/64-bit |
| AVR | `DetourBackendAVR` | Microcontroller |

### Architecture Detection

The `DetourBackend` factory automatically detects the architecture:

```python
from patcherex.backends.detourbackend import DetourBackend

# Automatic architecture detection
backend = DetourBackend("./binary")  # Works for any supported arch
```

---

## API Reference

### DetourBackend

```python
class DetourBackend:
    def __init__(self, filename, 
                 data_fallback=None,
                 base_address=None, 
                 try_pdf_removal=True,
                 try_reuse_unused_space=False,
                 replace_note_segment=False,
                 try_without_cfg=False,
                 variant=None,
                 cfg=None):
        """
        Initialize the DetourBackend.
        
        Args:
            filename: Path to the binary to patch
            base_address: Override base address for PIE binaries
            replace_note_segment: Reuse NOTE segment for patches
            cfg: Pre-computed CFG (optional)
        """
    
    def apply_patches(self, patches):
        """Apply a list of patches to the binary."""
    
    def save(self, filename=None):
        """Save the patched binary to disk."""
    
    def get_final_content(self):
        """Get the patched binary as bytes."""
    
    def set_oep(self, new_oep):
        """Set the original entry point."""
    
    def get_oep(self):
        """Get the original entry point."""
```

### Important Name Map Symbols

The backend automatically creates these symbols:

| Symbol | Description |
|--------|-------------|
| `ADDED_CODE_START` | Start of added code segment |
| `ADDED_DATA_START` | Start of added data segment |
| `pie_thunk` | PIE base address helper (x86/x64) |

---

## Troubleshooting

### Common Errors

#### 1. DetourException: "No movable instructions found"

The basic block doesn't have enough movable instructions to insert a detour.

**Solution:** Try hooking at a different address, or use InlinePatch instead.

#### 2. DoubleDetourException

Trying to patch bytes that have already been patched.

**Solution:** Check for overlapping patches or use lower priority for one of them.

#### 3. MissingBlockException

Cannot find a basic block containing the target address.

**Solution:** Verify the address is valid code, not data.

#### 4. DuplicateLabelsException

Two patches have the same label name.

**Solution:** Give each patch a unique name.

### Debugging Tips

1. **Enable logging:**
```python
import logging
logging.getLogger("patcherex.backends.DetourBackend").setLevel("DEBUG")
```

2. **Check applied patches:**
```python
backend.apply_patches(patches)
print(f"Applied patches: {backend.added_patches}")
```

3. **Verify addresses with angr:**
```python
import angr
proj = angr.Project("./binary", auto_load_libs=False)
cfg = proj.analyses.CFGFast()
# Check if address is in a function
for func in cfg.functions.values():
    if addr in func.block_addrs:
        print(f"Address in function: {func.name}")
```

---

## Complete Working Example

Here's a fully working example that you can use as a template:

```python
#!/usr/bin/env python3
"""
Complete patcherex example: Add "ciallo!!" print after a specific function call.
"""

import sys
import os

# Add patcherex to path if needed
sys.path.insert(0, '/path/to/patcherex')

from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import (
    InsertCodePatch,
    AddCodePatch,
    AddRODataPatch,
    AddRWDataPatch,
)


def main():
    if len(sys.argv) != 4:
        print("Usage: python example.py <input> <output> <hook_address>")
        print("Example: python example.py ./prog ./prog_patched 0x08048456")
        return 1
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    hook_addr = int(sys.argv[3], 16)
    
    print(f"[*] Loading binary: {input_file}")
    backend = DetourBackend(input_file)
    
    patches = []
    
    # 1. Add the string to print
    patches.append(AddRODataPatch(b"ciallo!!\n\x00", name="ciallo_message"))
    
    # 2. Add a counter to track how many times we print
    patches.append(AddRWDataPatch(4, name="print_counter"))
    
    # 3. Add the print function
    print_function = '''
        pusha
        pushf
        
        ; Increment counter
        inc DWORD [{print_counter}]
        
        ; Print message
        mov eax, 4              ; sys_write
        mov ebx, 1              ; stdout  
        mov ecx, {ciallo_message}
        mov edx, 9              ; "ciallo!!\n"
        int 0x80
        
        popf
        popa
        ret
    '''
    patches.append(AddCodePatch(print_function, name="ciallo_printer"))
    
    # 4. Create the hook at the target address
    hook_code = '''
        call {ciallo_printer}
    '''
    patches.append(InsertCodePatch(hook_addr, hook_code, name="main_hook"))
    
    # Apply all patches
    print(f"[*] Applying {len(patches)} patches...")
    try:
        backend.apply_patches(patches)
        print(f"[+] Successfully applied patches")
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1
    
    # Save the result
    backend.save(output_file)
    os.chmod(output_file, 0o755)
    print(f"[+] Saved patched binary: {output_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## Conclusion

Patcherex is a powerful tool for binary patching. Key points to remember:

1. **Use `InsertCodePatch`** for most hooking needs
2. **Always preserve registers** (pusha/popa or push/pop individual registers)
3. **Use `{name}` syntax** to reference other patches
4. **DetourBackend** is more reliable than ReassemblerBackend
5. **Check for overlapping patches** when hooking multiple addresses
6. **Test your patches** thoroughly - binary patching can easily break things

For CTF and security research, this tool is invaluable for:
- Adding debugging/logging code
- Implementing security hardening
- Creating patches for vulnerable binaries
- Reverse engineering with instrumentation
