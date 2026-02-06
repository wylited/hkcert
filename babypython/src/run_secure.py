#!/usr/bin/env python3
"""
Secure wrapper to run the Flask app with security patches applied.
Usage: python run_secure.py
"""
import sys
import importlib.util

# Load the original app.pyc
spec = importlib.util.spec_from_file_location("app", "app.pyc")
app_module = importlib.util.module_from_spec(spec)
sys.modules["app"] = app_module
spec.loader.exec_module(app_module)

# Get the Flask app instance
app = app_module.app

# Apply security patches
from security_patches import apply_all_patches, register_security_middleware
apply_all_patches(app)
register_security_middleware(app)

if __name__ == "__main__":
    print("[SECURE] Starting patched application...")
    app.run(debug=False, host="0.0.0.0")
