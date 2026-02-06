# EzNote Patch Log

## Patched Binaries

| File | Patches Applied | Bytes | Status |
|------|-----------------|-------|--------|
| `src/chall_patched` | Command injection blacklist | 2 | **v1 (DEPLOYED)** |

## Vulnerability Summary

### 1. Command Injection in Username (Critical) - MAIN EXPLOIT
- **Location**: `create_note_dir` at 0x4018f7, calls `system()` at 0x401969
- **Issue**: `USERNAME_BLACKLIST` at 0x402080 only blocks `"'.` but NOT `` ` `` or `$`
- **Command**: `mkdir -p "%s/%s/"` with username as second `%s`
- **Exploit**: Username like `` `cat /flag` `` or `$(cat /flag)` executes shell commands
- **Status**: PATCHED in v1

## Current Server Status (2026-02-06 06:46)
**172.28.31.31: PATCHED & VERIFIED**
- Command Injection: ✅ PATCHED (backticks and $() blocked)
- All v3 exploit methods: ✅ BLOCKED

### v3 Exploit Methods Tested:
1. `cmd_injection` (stderr redirect) - ✅ BLOCKED
2. `symlink` (arbitrary file read) - ✅ BLOCKED  
3. `dirleak` (flag in dirname) - ✅ BLOCKED
4. `mkdir_error` (long filename) - ✅ BLOCKED

## Patch Details

| # | File | Offset | Original | Patched | Bytes | Description |
|---|------|--------|----------|---------|-------|-------------|
| 1 | chall | 0x2083 | `00 00` | `60 24` | 2 | Add `` ` `` and `$` to USERNAME_BLACKLIST |

**Total bytes modified**: 2 (within 10-byte limit)
**File size**: unchanged (17376 bytes)

### Patch 1: Command Injection Fix (CRITICAL)
Extends the USERNAME_BLACKLIST string from `"'.` to `"'.\`$`.
- Original blacklist (0x402080): `22 27 2e 00` → `"'.`
- Patched blacklist (0x402080): `22 27 2e 60 24 00` → `"'.\`$`

This blocks:
- Backtick command substitution: `` `cmd` ``
- Dollar command substitution: `$(cmd)`

## Deployment

```bash
# Deploy v1 (command injection fix)
echo "put src/chall_patched /patch/patched" | sftp -i auth.pem ctf@172.28.32.31
# Then create version file to trigger patch
echo "v1" > /tmp/version && echo "put /tmp/version /patch/version" | sftp -i auth.pem ctf@172.28.32.31
```

## Current Vulnerability Matrix (Updated 2026-02-06 06:40)
| IP | Backtick | Dollar | Status |
|----|----------|--------|--------|
| 172.28.31.31 | PATCHED | PATCHED | **DEFENDED** |
| 172.28.31.32 | VULN | VULN | EXPLOITABLE |
| 172.28.31.33 | VULN | VULN | EXPLOITABLE |
| 172.28.31.34 | VULN | VULN | EXPLOITABLE |
| 172.28.31.35 | PATCHED | PATCHED | DEFENDED |

## Exploit Scripts

| Script | Description |
|--------|-------------|
| `eznote_exploit.py` | Original exploit (flawed - doesn't work) |
| `eznote_exploit_v2.py` | **Working exploit** - uses mkdir error for flag extraction |

### Usage
```bash
# Attack all targets once
python3 eznote_exploit.py

# Continuous mode
python3 eznote_exploit.py --loop

# Single target
python3 eznote_exploit.py 172.28.32.32
```

## Date
2026-02-06
