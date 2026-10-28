"""
Configuration settings for Phishing Awareness Analyzer.
Hardens the Flask application and sets limits.
"""
import os
import secrets

class Config:
    # Use environment secret key if set; otherwise generate a cryptographically strong random key
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    # Enforce maximum payload size: 100 KB max to avoid memory exhaustion/DoS
    MAX_CONTENT_LENGTH = 100 * 1024
    
    # Static security configuration
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        ),
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=(), display-capture=()",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
    }
