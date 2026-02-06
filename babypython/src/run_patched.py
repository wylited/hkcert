#!/usr/bin/env python3
"""
Patched runner for babypython - blocks path traversal with unicode bypass.
Also blocks SSTI in comments and other attack vectors.
"""
import sys
import os
import json
import re
from io import BytesIO
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BLOCKED_SSTI = ['__', 'config', 'request', 'lipsum', 'cycler', 'joiner', 'namespace', 
                'self.', 'url_for', 'get_flashed', 'mro', 'builtins', 'import', 
                'popen', 'system', 'eval', 'exec', 'open(', 'subprocess', 'Popen']

def is_ssti_attack(content):
    """Check if content contains SSTI payload"""
    if not content:
        return False
    lower = content.lower()
    if '{{' in content or '{%' in content:
        for blocked in BLOCKED_SSTI:
            if blocked.lower() in lower:
                return True
    return False

def is_path_attack(path):
    """Check if path is a traversal attack"""
    if not path:
        return False
    # Block .., absolute paths, and flag references
    return '..' in path or path.startswith('/') or 'flag' in path.lower() or 'proc' in path.lower()

class SecurityMiddleware:
    """WSGI middleware to block path traversal and SSTI attacks."""
    
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        path_info = environ.get('PATH_INFO', '')
        method = environ.get('REQUEST_METHOD', '')
        content_type = environ.get('CONTENT_TYPE', '')
        
        if method == 'POST':
            try:
                length = int(environ.get('CONTENT_LENGTH', 0))
                if length > 0:
                    body = environ['wsgi.input'].read(length)
                    environ['wsgi.input'] = BytesIO(body)
                    body_str = body.decode('utf-8', errors='ignore')
                    
                    # Block path traversal in download_attachment (any content type)
                    if 'download_attachment' in path_info:
                        if 'application/json' in content_type:
                            try:
                                data = json.loads(body_str)
                                req_path = data.get('path', '')
                                if is_path_attack(req_path):
                                    print(f"[BLOCKED] path_traversal: {req_path[:50]}")
                                    start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                                    return [b'Access denied']
                            except:
                                pass
                        else:
                            # Form data or other
                            for blocked in ['..', '/flag', 'flag', '/proc']:
                                if blocked in body_str.lower():
                                    print(f"[BLOCKED] path_form: {body_str[:50]}")
                                    start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                                    return [b'Access denied']
                    
                    # Block SSTI in comments and post content
                    if '/comment' in path_info or path_info in ['/create', '/edit']:
                        if is_ssti_attack(body_str):
                            print(f"[BLOCKED] ssti: {body_str[:50]}")
                            start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                            return [b'Access denied']
                    
            except Exception as e:
                print(f"[WARN] {e}")
        
        return self.app(environ, start_response)


def main():
    import importlib.util
    
    app_path = os.path.join(os.path.dirname(__file__), 'app.pyc')
    spec = importlib.util.spec_from_file_location("app", app_path)
    app_module = importlib.util.module_from_spec(spec)
    sys.modules['app'] = app_module
    spec.loader.exec_module(app_module)
    
    app = app_module.app
    app.wsgi_app = SecurityMiddleware(app.wsgi_app)
    print("[SECURITY] Patch enabled")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)


if __name__ == '__main__':
    main()
