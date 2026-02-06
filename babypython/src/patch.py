#!/usr/bin/env python3
"""
Simple security patch for babypython - blocks the unicode escape path traversal.
Deploy: Copy to server and import before app runs, OR use as WSGI middleware.
"""
import os
import sys

# Monkey-patch the download_attachment to block path traversal
def patch_flask_app():
    """
    This patches Flask's request handling to block path traversal attacks.
    Must be called AFTER the app is created but BEFORE it runs.
    """
    from flask import Flask, request, abort
    
    # Store original get_json
    original_get_json = request.__class__.get_json
    
    def secure_get_json(self, *args, **kwargs):
        data = original_get_json(self, *args, **kwargs)
        if data and isinstance(data, dict):
            path = data.get('path', '')
            if isinstance(path, str):
                # Check AFTER JSON decoding (defeats unicode escape)
                if '..' in path or path.startswith('/') or 'flag' in path.lower():
                    abort(403, 'Blocked: path traversal attempt')
        return data
    
    request.__class__.get_json = secure_get_json
    print("[PATCH] Path traversal protection enabled")


def create_patched_wsgi():
    """
    Create a WSGI middleware that blocks malicious requests.
    Use this if you can't modify the app directly.
    """
    import json
    
    class SecurityMiddleware:
        def __init__(self, app):
            self.app = app
        
        def __call__(self, environ, start_response):
            # Check POST requests with JSON
            if environ.get('REQUEST_METHOD') == 'POST':
                content_type = environ.get('CONTENT_TYPE', '')
                if 'application/json' in content_type:
                    try:
                        length = int(environ.get('CONTENT_LENGTH', 0))
                        if length > 0:
                            body = environ['wsgi.input'].read(length)
                            # Reset input stream
                            from io import BytesIO
                            environ['wsgi.input'] = BytesIO(body)
                            
                            # Check the decoded JSON
                            data = json.loads(body.decode('utf-8'))
                            path = data.get('path', '')
                            if isinstance(path, str):
                                if '..' in path or path.startswith('/') or 'flag' in path.lower():
                                    start_response('403 Forbidden', [('Content-Type', 'text/plain')])
                                    return [b'Blocked: path traversal attempt']
                    except:
                        pass
            
            return self.app(environ, start_response)
    
    return SecurityMiddleware


if __name__ == '__main__':
    print("Security patch module for babypython")
    print("Usage:")
    print("  1. Import and call patch_flask_app() after app creation")
    print("  2. Or wrap app with create_patched_wsgi()(app)")
