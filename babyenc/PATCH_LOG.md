# BabyEnc Patch Log

## Vulnerability Summary

### 1. Nonce Reuse in Stream Cipher (Critical) - MAIN EXPLOIT
- **Location**: `stream_xor` at 0x401ac0, nonce selection at 0x401744
- **Issue**: Only 2 nonces exist (toggled by `g_state+0x40`)
- **Flag encrypted with**: nonce 0 (`g_state+0x48`)
- **Toggle starts at**: 1 (so encrypt uses nonce 1 initially)
- **Exploit**: Decrypt note at even index to set toggle=even, then encrypt to get nonce 0 keystream
- **Status**: All teams VULNERABLE as of 2026-02-06 02:25

### 2. Memory Leak via Vault (Info Disclosure) - PATCHED BY US
- **Location**: main+0x4db (0x4017ab-0x4017c8)
- **Issue**: When encrypting a note, up to 48 bytes from end of note copied to `g_vault`
- **Exploit**: Combined with encrypted flag output, leaks key material

### 3. Key Overwrite via edit_note (Potential)
- **Location**: `edit_note` at 0x401f10, writes to `g_state` (0x405260)
- **Issue**: `edit_note` parses up to 0x80 hex bytes into `g_state`
- **Memory layout**:
  - `g_state`: 0x405260 (0x60 bytes)
  - `g_key`: 0x4052c0 (0x10 bytes) - at offset 0x60 from g_state
- **Exploit**: Can overwrite key to known value, but only affects future encryptions
- **Use case**: If nonce reuse is patched, this allows controlling the keystream

## Patch Applied

| File | Offset | Original | Patched | Description |
|------|--------|----------|---------|-------------|
| chall | 0x17a5 | `0f 84 45 fc ff ff` | `e9 46 fc ff ff 90` | `je` → `jmp` (skip vault copy) |

**Bytes modified**: 5 (within 30-byte limit)
**File size**: unchanged (21592 bytes)

### Patch Effect
Changed conditional jump to unconditional at 0x4017a5, causing vault copy code to be skipped entirely.

Before:
```asm
4017a2: test   %rax,%rax
4017a5: je     4013f0 <main+0x120>    ; only skip if vault NULL
4017ab: mov    0x8(%rbx),%rsi         ; vault copy begins
```

After:
```asm
4017a2: test   %rax,%rax
4017a5: jmp    4013f0 <main+0x120>    ; always skip
4017aa: nop
4017ab: mov    0x8(%rbx),%rsi         ; vault copy (now dead code)
```

## Recommended Additional Patches

### To patch nonce reuse (requires more bytes):
Option A: Randomize nonce on each encrypt (would need to modify fill_random call)
Option B: NOP out the decrypt toggle-set at 0x4016d5 (7 bytes)

## Deployment

```bash
scp -i auth.pem -s -P 22 src/chall_patched ctf@<server_ip>:/patch/patched
echo "v1" > /tmp/version && scp -i auth.pem -s -P 22 /tmp/version ctf@<server_ip>:/patch/version
```

## Scan Results (2026-02-06)

| Target | Nonce Reuse | Vault Leak |
|--------|-------------|------------|
| 172.28.32.32 | VULNERABLE | Unknown |
| 172.28.32.33 | VULNERABLE | Unknown |
| 172.28.32.34 | VULNERABLE | Unknown |
| 172.28.32.35 | VULNERABLE | Unknown |

## Date
2026-02-06
