from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import *

# Don't use base_address - use ELF virtual addresses directly
# Ghidra address 0x100000 + offset -> ELF vaddr = offset
# So: Ghidra 0x103422 -> ELF 0x3422
#     Ghidra 0x1032e4 -> ELF 0x32e4

backend = DetourBackend("./easyvm.orig", base_address=0)
patches = []

patches.append(AddLabelPatch(0x3422, "call_exit"))
patches.append(InsertCodePatch(0x32e4,
'''
    mov RDX,qword [RCX + 0x8]
    cmp RAX, RDX
    jc {call_exit}
''', "check_operand_range"))

# Apply all patches
print(f"[*] Applying {len(patches)} patches...")
try:
    backend.apply_patches(patches)
    print(f"[+] Successfully applied patches")
except Exception as e:
    print(f"[-] Error: {e}")
    exit(-1)
backend.save('./easyvm.patched')