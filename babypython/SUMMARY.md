# BabyPython AWD Challenge - Summary

## Vulnerability Found
**Unicode Escape Path Traversal in `/download_attachment`**

The endpoint checks for `..` and `flag` in the raw request bytes:
```python
if b'..' in path or b'flag' in path:
    abort(400)
```

But JSON Unicode escapes (`\u002f\u0066\u006c\u0061\u0067` = `/flag`) bypass this check.

## Exploit
```bash
# Run against all targets
python3 exploit.py

# Run continuously
python3 exploit.py --loop

# Single target
python3 exploit.py -t 172.28.36.32
```

## Patch Applied
File: `/home/ctf/run_patched.py`

The patch adds WSGI middleware that:
1. Intercepts POST requests to `/download_attachment`
2. Decodes the JSON body
3. Checks the DECODED path for `..`, `/`, and `flag`
4. Blocks malicious requests with 403

## Files
- `exploit.py` - Main exploit script
- `src/run_patched.py` - Patched runner with WSGI middleware
- `src/security_patches.py` - Flask-level patches (alternative)
- `VULNS.md` - Full vulnerability documentation

## Results
| Target | Status |
|--------|--------|
| 172.28.36.31 (us) | PATCHED ✓ |
| 172.28.36.32 | VULNERABLE - flags captured |
| 172.28.36.33 | PATCHED by team |
| 172.28.36.34 | PATCHED by team |
| 172.28.36.35 | VULNERABLE - flags captured |

## Other Attack Vectors Tested (Not Working)
1. **ReportLab CVE-2023-33733** - `Word` class not available
2. **SSTI in web view** - Escaped/patched
3. **SSTI in PDF generation** - Content not rendered as template
4. **IDOR admin creation** - Works but admin panel doesn't show flag
5. **File upload via attachment** - No direct file read capability
