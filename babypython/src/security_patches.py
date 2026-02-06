"""
Security patches for babypython Flask app vulnerabilities.
Import this module and call apply_all_patches(app) after app initialization.

Vulnerabilities Patched:
1. IDOR - Insecure Direct Object Reference in admin endpoints
2. Path Traversal - in /download_attachment
3. SSTI - Server-Side Template Injection in post content
4. Mass Assignment - is_admin field in user creation/edit
"""
import os
import re
from functools import wraps
from flask import request, abort, jsonify, session
from flask_login import current_user

# === PATCH 1: IDOR Prevention (CRITICAL) ===
def require_admin(f):
    """Decorator to require admin access for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401, 'Authentication required')
        if not current_user.is_admin:
            abort(403, 'Admin access required')
        return f(*args, **kwargs)
    return decorated_function


def patch_admin_routes(app):
    """
    Patch admin routes to require proper authentication.
    Fixes IDOR in /admin/users, /admin/user/add, /admin/user/edit/<id>
    """
    admin_routes = [
        'user_list',      # /admin/users
        'user_add',       # /admin/user/add  
        'user_edit',      # /admin/user/edit/<id>
        'user_delete',    # /admin/user/delete/<id>
        'admin_panel',    # /admin/panel
    ]
    
    for route_name in admin_routes:
        if route_name in app.view_functions:
            original = app.view_functions[route_name]
            app.view_functions[route_name] = require_admin(original)
    
    print("[SECURITY] Admin routes patched with proper auth checks")


# === PATCH 2: Mass Assignment Prevention ===
ALLOWED_USER_FIELDS = {'username', 'password', 'avatar'}  # NOT is_admin!

def patch_user_edit(app):
    """
    Prevent mass assignment of is_admin field.
    """
    original_user_add = app.view_functions.get('user_add')
    original_user_edit = app.view_functions.get('user_edit')
    
    if original_user_add:
        @wraps(original_user_add)
        def secure_user_add():
            if request.method == 'POST':
                # Remove is_admin from form data
                if 'is_admin' in request.form:
                    # Create new ImmutableMultiDict without is_admin
                    from werkzeug.datastructures import ImmutableMultiDict
                    filtered = {k: v for k, v in request.form.items() if k != 'is_admin'}
                    request.form = ImmutableMultiDict(filtered)
            return original_user_add()
        app.view_functions['user_add'] = require_admin(secure_user_add)
    
    if original_user_edit:
        @wraps(original_user_edit)  
        def secure_user_edit(user_id):
            if request.method == 'POST':
                if 'is_admin' in request.form:
                    from werkzeug.datastructures import ImmutableMultiDict
                    filtered = {k: v for k, v in request.form.items() if k != 'is_admin'}
                    request.form = ImmutableMultiDict(filtered)
            return original_user_edit(user_id)
        app.view_functions['user_edit'] = require_admin(secure_user_edit)
    
    print("[SECURITY] Mass assignment protection enabled")


# === PATCH 3: Path Traversal Prevention ===
def sanitize_path(path, base_dir):
    """
    Prevent path traversal by ensuring resolved path stays within base_dir.
    Uses os.path.realpath to resolve ALL path tricks including unicode escapes.
    """
    if not path:
        return None
    
    # Normalize and resolve the full path FIRST
    # This handles unicode escapes, double encoding, etc.
    base_dir = os.path.realpath(base_dir)
    requested_path = os.path.realpath(os.path.join(base_dir, path))
    
    # Ensure the resolved path is within the base directory
    if not requested_path.startswith(base_dir + os.sep) and requested_path != base_dir:
        return None
    
    return requested_path


def patch_download_attachment(app):
    """
    Patch the download_attachment route to prevent path traversal.
    
    IMPORTANT: Check the RESOLVED path, not the raw input!
    Unicode escapes like \\u002e\\u002e will be decoded by JSON parser
    and then resolved by os.path.realpath.
    """
    original_view = app.view_functions.get('download_attachment')
    if not original_view:
        return
    
    @wraps(original_view)
    def secure_download_attachment():
        try:
            data = request.get_json()
            if not data or 'path' not in data:
                abort(400, 'Missing path parameter')
            
            requested_path = data.get('path', '')
            
            # SECURITY FIX: Use realpath-based check, not string matching!
            # This defeats unicode escape bypass (\u002e\u002e = ..)
            base_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), 'static', 'attachments'))
            full_path = os.path.realpath(os.path.join(base_dir, requested_path))
            
            # Check if resolved path is within allowed directory
            if not full_path.startswith(base_dir + os.sep) and full_path != base_dir:
                abort(403, 'Path traversal detected')
            
            if not os.path.isfile(full_path):
                abort(404, 'File not found')
            
            # Additional check: block if 'flag' appears in resolved path
            if 'flag' in full_path.lower():
                abort(403, 'Access denied')
                
        except Exception as e:
            abort(400, f'Invalid request: {str(e)}')
        
        return original_view()
    
    app.view_functions['download_attachment'] = secure_download_attachment
    print("[SECURITY] Path traversal protection enabled (unicode-safe)")


# === PATCH 4: SSTI Prevention ===
SSTI_PATTERNS = [
    r'\{\{.*\}\}',           # Jinja2 expressions
    r'\{%.*%\}',             # Jinja2 statements  
    r'__class__',
    r'__mro__',
    r'__subclasses__',
    r'__globals__',
    r'__builtins__',
    r'__import__',
    r'config\.',
    r'request\.',
    r'self\.',
    r'lipsum',
    r'cycler',
    r'joiner',
    r'namespace',
    r'url_for',
    r'get_flashed_messages',
]

def contains_ssti_payload(text):
    """Check if text contains potential SSTI payloads."""
    if not text:
        return False
    for pattern in SSTI_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def patch_post_creation(app):
    """
    Patch post creation/editing to sanitize content against SSTI.
    """
    for route_name in ['create', 'edit']:
        original_view = app.view_functions.get(route_name)
        if not original_view:
            continue
        
        if route_name == 'create':
            @wraps(original_view)
            def secure_create():
                if request.method == 'POST':
                    content = request.form.get('content', '')
                    title = request.form.get('title', '')
                    
                    if contains_ssti_payload(content) or contains_ssti_payload(title):
                        abort(400, 'Invalid content detected')
                
                return original_view()
            app.view_functions['create'] = secure_create
        else:
            @wraps(original_view)
            def secure_edit(post_id):
                if request.method == 'POST':
                    content = request.form.get('content', '')
                    title = request.form.get('title', '')
                    
                    if contains_ssti_payload(content) or contains_ssti_payload(title):
                        abort(400, 'Invalid content detected')
                
                return original_view(post_id)
            app.view_functions['edit'] = secure_edit
    
    print("[SECURITY] SSTI protection enabled")


# === PATCH 5: Disable Dangerous Endpoints ===
def patch_dangerous_endpoints(app):
    """
    Disable or restrict dangerous endpoints.
    """
    dangerous = ['edit_template', 'reinit']
    
    for endpoint in dangerous:
        if endpoint in app.view_functions:
            @wraps(app.view_functions[endpoint])
            def disabled():
                abort(403, 'This endpoint is disabled for security')
            app.view_functions[endpoint] = require_admin(disabled)
    
    print("[SECURITY] Dangerous endpoints restricted")


# === Apply All Patches ===
def apply_all_patches(app):
    """
    Apply all security patches to the Flask app.
    Call this after app initialization but before running.
    """
    patch_admin_routes(app)
    patch_user_edit(app)
    patch_download_attachment(app)
    patch_post_creation(app)
    patch_dangerous_endpoints(app)
    print("[SECURITY] All patches applied successfully")


# === Request-level validation middleware ===
def register_security_middleware(app):
    """
    Register before_request handler for additional security checks.
    """
    @app.before_request
    def security_check():
        # Block requests with suspicious path patterns
        for key, value in request.args.items():
            if isinstance(value, str) and '..' in value:
                abort(403, 'Invalid parameter')
        
        if request.method == 'POST' and request.is_json:
            data = request.get_json(silent=True) or {}
            for key, value in data.items():
                if isinstance(value, str) and '..' in value:
                    abort(403, 'Invalid parameter')
    
    print("[SECURITY] Security middleware registered")
