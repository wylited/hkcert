# BabyEnc Patch Log

## Patched Binaries

| File | Patches Applied | Bytes | Status |
|------|-----------------|-------|--------|
| `src/chall_patched` | Vault leak only | 6 | v1 |
| `src/chall_patched_v2` | v1 + nonce + key | 14 | v2 |
| `src/chall_patched_v3` | v2 + audit skip | 20 | v3 |
| `src/chall_patched_v4` | v2 + audit surgical | 17 | v4 (flawed) |
| `src/chall_patched_v5` | v2 + audit skip | 20 | **v5 (DEPLOYED)** |

## Current Server Status (2026-02-06 04:47)
**172.28.32.31: FULLY PATCHED & HARDENED**
- Nonce Reuse: ✅ PATCHED
- Audit OOB: ✅ PATCHED  
- Key Overwrite: VULN (not critical)

## Vulnerability Summary

### 1. Nonce Reuse in Stream Cipher (Critical) - MAIN EXPLOIT
- **Location**: `stream_xor` at 0x401ac0, nonce selection at 0x401744
- **Issue**: Only 2 nonces exist (toggled by `g_state+0x40`)
- **Flag encrypted with**: nonce 0 (`g_state+0x48`)
- **Toggle starts at**: 1 (so encrypt uses nonce 1 initially)
- **Exploit**: Decrypt note at even index to set toggle=even, then encrypt to get nonce 0 keystream
- **Status**: All enemy teams VULNERABLE (32-35), our server PATCHED

### Current Vulnerability Matrix (Updated 2026-02-06 04:30)
| IP | Team | Nonce Reuse | Audit OOB | Key Overwrite | Status |
|----|------|-------------|-----------|---------------|--------|
| 172.28.32.31 | US | PATCHED | VULN* | VULN | DEFENDED |
| 172.28.32.32 | - | VULN | PATCHED | VULN | EXPLOITABLE |
| 172.28.32.33 | - | PATCHED | PATCHED | VULN | HARDENED |
| 172.28.32.34 | - | VULN | VULN | VULN | FULLY EXPLOITABLE |
| 172.28.32.35 | - | PATCHED | PATCHED | VULN | HARDENED |

*Our server shows audit OOB as VULN but flag isn't at expected offset

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

### 4. Audit Field OOB Read (CRITICAL) - FOUND IN v2!
- **Location**: show_note at 0x401862-0x401899
- **Issue**: Audit field reads `vault[note[1]]` for `note[0]` bytes
- **Exploit**: Set note[0]=64, note[1]=0x20 to read flag plaintext from heap!
- **This bypasses ALL crypto - direct plaintext leak!**

## All Patches Applied (v4 - surgical)

| # | File | Offset | Original | Patched | Bytes | Description |
|---|------|--------|----------|---------|-------|-------------|
| 1 | chall | 0x17a5 | `0f 84 45 fc ff ff` | `e9 46 fc ff ff 90` | 6 | Vault leak: `je` → `jmp` |
| 2 | chall | 0x16d5 | `44 88 1d c4 3b 00 00` | `90 90 90 90 90 90 90` | 7 | Nonce reuse: NOP toggle set |
| 3 | chall | 0x2021 | `80` | `40` | 1 | Key overwrite: limit to 0x40 bytes |
| 4 | chall | 0x188c | `0f b6 fb` | `31 ff 90` | 3 | Audit OOB: `movzbl %bl,%edi` → `xor %edi,%edi; nop` |

**Total bytes modified**: 17 (within 30-byte limit)

**v4 vs v3**: v3 skipped audit entirely (`je→jmp`), v4 surgically fixes the OOB by forcing offset=0
**File size**: unchanged (21592 bytes)

### Patch 1: Vault Leak Fix
Skips vault copy by changing conditional jump to unconditional.

### Patch 2: Nonce Reuse Fix (CRITICAL)
NOPs out `mov %r11b, g_state+0x40` which sets toggle = note_index.
Toggle stays at 1, so all user encryptions use nonce1 while flag uses nonce0.
**This blocks the main exploit.**

### Patch 3: Key Overwrite Fix
Reduces edit_note max write from 0x80 to 0x40 bytes.
Prevents overflow from g_state (0x405260) into g_key (0x4052c0).

### Patch 4: Audit OOB Read Fix (CRITICAL)
Changes `je` to `jmp` at 0x185c to always skip the audit print code.
**This blocks the plaintext leak exploit that bypasses all crypto!**

## Deployment

```bash
# Deploy v3 (all 4 patches) - CRITICAL
echo "put src/chall_patched_v3 /patch/patched" | sftp -i auth.pem ctf@172.28.32.31
```

## Current Status (2026-02-06 02:50)

### Our Server (172.28.32.31)
- **Status**: ✅ FULLY PATCHED (v2)
- All 3 patches verified deployed
- Exploit test: BLOCKED

### Other Teams
| Target | Nonce Reuse | Exploitable |
|--------|-------------|-------------|
| 172.28.32.32 | VULNERABLE | ✅ Yes |
| 172.28.32.33 | VULNERABLE | ✅ Yes |
| 172.28.32.34 | VULNERABLE | ✅ Yes |
| 172.28.32.35 | VULNERABLE | ✅ Yes |

## Exploit Scripts

| Script | Description |
|--------|-------------|
| `exploit_babyenc.py` | Original exploit (nonce reuse only) |
| `exploit_babyenc_v2.py` | Multi-exploit with patch detection |

### Usage
```bash
# Attack all targets once
python3 exploit_babyenc_v2.py

# Continuous mode
python3 exploit_babyenc_v2.py --loop

# Scan for patches
python3 exploit_babyenc_v2.py --scan

# Single target
python3 exploit_babyenc_v2.py -t 172.28.32.32
```

## Date
2026-02-06
