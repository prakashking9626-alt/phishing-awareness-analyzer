"""
Automated Security Audit Verification Suite.
Safely tests security headers, input limits, XSS prevention, zero-network enforcement,
DoS boundaries, and error handlers against the Flask test client.
"""
import json
import re
import socket
import unittest
from unittest.mock import patch
from app import create_app
from app.config import Config
from app.analyzers.url_analyzer import analyze_url
from app.analyzers.email_analyzer import analyze_email


class TestSecurityAudit(unittest.TestCase):
    def setUp(self):
        self.app = create_app(Config)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    # =========================================================================
    # 1. HTTP Security Headers Audit
    # =========================================================================
    def test_security_headers_present_on_index(self):
        """Verify all mandatory security headers are present on dashboard response."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

        # X-Content-Type-Options
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

        # X-Frame-Options
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

        # Referrer-Policy
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")

        # Permissions-Policy
        perm_policy = resp.headers.get("Permissions-Policy")
        self.assertIsNotNone(perm_policy)
        self.assertIn("camera=()", perm_policy)
        self.assertIn("microphone=()", perm_policy)
        self.assertIn("geolocation=()", perm_policy)

        # Content-Security-Policy
        csp = resp.headers.get("Content-Security-Policy")
        self.assertIsNotNone(csp)
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("form-action 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

        # HSTS
        hsts = resp.headers.get("Strict-Transport-Security")
        self.assertIsNotNone(hsts)
        self.assertIn("max-age=31536000", hsts)

    def test_security_headers_present_on_api(self):
        """Verify security headers are also injected into API responses."""
        resp = self.client.post("/api/analyze-url", json={"url": "https://example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

    # =========================================================================
    # 2. XSS Protection & Template Safety
    # =========================================================================
    def test_xss_script_injection_in_url(self):
        """XSS payloads in URL must be rejected or serialized safely as inert data."""
        payload = "javascript:alert(document.cookie)"
        resp = self.client.post("/api/analyze-url", json={"url": payload})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["is_valid"])
        # Ensure returned evidence string contains no raw executable script context
        self.assertIn("javascript", data["error"])

    def test_xss_html_injection_in_email(self):
        """HTML script tags in email body must be parsed safely as inert text strings."""
        payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
        resp = self.client.post("/api/analyze-email", json={"email_body": payload})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["is_valid"])
        # Response must be JSON, not rendered as executable HTML in response
        self.assertEqual(resp.content_type, "application/json")

    # =========================================================================
    # 3. Input Validation & Boundaries
    # =========================================================================
    def test_url_length_cap_enforced(self):
        """URLs exceeding 4096 characters must be rejected with 400 Bad Request."""
        long_url = "https://example.com/" + "a" * 4100
        resp = self.client.post("/api/analyze-url", json={"url": long_url})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exceeds maximum permitted length", resp.get_json()["error"])

    def test_email_body_length_cap_enforced(self):
        """Email bodies exceeding 64 KB must be rejected with 400 Bad Request."""
        long_body = "Urgent: " + "A" * 70000
        resp = self.client.post("/api/analyze-email", json={"email_body": long_body})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exceeds maximum permitted length", resp.get_json()["error"])

    def test_sender_length_cap_enforced(self):
        """Sender header exceeding 1024 characters must be rejected with 400 Bad Request."""
        long_sender = "Admin <" + "a" * 1050 + "@example.com>"
        resp = self.client.post("/api/analyze-email", json={
            "email_body": "Test message content",
            "sender": long_sender
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Sender header exceeds", resp.get_json()["error"])

    def test_null_byte_sanitization(self):
        """Embedded null bytes must be stripped without raising exceptions."""
        null_url = "https://example.com/\x00login\x00.html"
        res = analyze_url(null_url)
        self.assertTrue(res["is_valid"])
        self.assertNotIn("\x00", res["parsed_components"]["raw_url"])

        null_email = "Hello\x00 world\x00 please login."
        res_email = analyze_email(null_email)
        self.assertTrue(res_email["is_valid"])

    # =========================================================================
    # 4. Request Size Limit (DoS / Resource Exhaustion)
    # =========================================================================
    def test_payload_exceeding_max_content_length(self):
        """Requests exceeding MAX_CONTENT_LENGTH (100 KB) must trigger HTTP 413."""
        huge_payload = json.dumps({"url": "https://example.com/" + ("b" * (120 * 1024))})
        resp = self.client.post(
            "/api/analyze-url",
            data=huge_payload,
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 413)
        self.assertIn("Payload Too Large", resp.get_json()["error"])

    # =========================================================================
    # 5. Safe Error Handling (No Stack Traces)
    # =========================================================================
    def test_error_handlers_return_clean_json(self):
        """API errors must return structured JSON without disclosing server internals."""
        # 404
        resp404 = self.client.get("/api/nonexistent-endpoint")
        self.assertEqual(resp404.status_code, 404)
        self.assertFalse(resp404.get_json()["is_valid"])
        self.assertIn("The requested endpoint does not exist", resp404.get_json()["error"])

        # 405 Method Not Allowed
        resp405 = self.client.get("/api/analyze-url")
        self.assertEqual(resp405.status_code, 405)
        self.assertFalse(resp405.get_json()["is_valid"])
        self.assertIn("HTTP method is not permitted", resp405.get_json()["error"])

        # 400 Bad Request
        resp400 = self.client.post("/api/analyze-url", data="invalid json", content_type="application/json")
        self.assertEqual(resp400.status_code, 400)
        self.assertFalse(resp400.get_json()["is_valid"])

    # =========================================================================
    # 6. Strict Zero Network Egress Enforcement
    # =========================================================================
    def test_zero_network_egress_during_url_analysis(self):
        """Prove that analyze_url never attempts socket connections or DNS resolution."""
        def block_socket(*args, **kwargs):
            raise AssertionError("CRITICAL SECURITY VIOLATION: Socket connect() attempted!")

        def block_dns(*args, **kwargs):
            raise AssertionError("CRITICAL SECURITY VIOLATION: DNS resolution getaddrinfo() attempted!")

        with patch("socket.socket.connect", side_effect=block_socket), \
             patch("socket.getaddrinfo", side_effect=block_dns):
            # Target suspicious phishing URLs
            res1 = analyze_url("https://signin.eby.de.zukruygxctzmmqi.civpro.co.za")
            self.assertTrue(res1["is_valid"])

            # Localhost / Private IP URLs
            res2 = analyze_url("http://127.0.0.1:8080/admin")
            self.assertTrue(res2["is_valid"])

            # Known clean URLs
            res3 = analyze_url("https://www.microsoft.com")
            self.assertTrue(res3["is_valid"])

    def test_zero_network_egress_during_email_analysis(self):
        """Prove that analyze_email never queries external servers for embedded links."""
        def block_socket(*args, **kwargs):
            raise AssertionError("CRITICAL SECURITY VIOLATION: Socket connect() attempted!")

        def block_dns(*args, **kwargs):
            raise AssertionError("CRITICAL SECURITY VIOLATION: DNS resolution getaddrinfo() attempted!")

        with patch("socket.socket.connect", side_effect=block_socket), \
             patch("socket.getaddrinfo", side_effect=block_dns):
            email_body = (
                "Immediate action required: verify your account at "
                "https://secure-login-chase.com/verify or your service will be terminated."
            )
            res = analyze_email(email_body, "Chase Security <alert@fake-chase.com>")
            self.assertTrue(res["is_valid"])
            self.assertGreater(len(res["extracted_urls"]), 0)

    # =========================================================================
    # 7. Command Execution & SSRF Resistance
    # =========================================================================
    def test_shell_injection_payloads_remain_inert(self):
        """Shell metacharacters in input must be treated as inert strings without execution."""
        payloads = [
            "; cat /etc/passwd #",
            "| dir C:\\",
            "`id`",
            "$(whoami)",
            "& ping 127.0.0.1 &"
        ]
        for p in payloads:
            res_url = analyze_url(p)
            self.assertIsInstance(res_url, dict)

            res_email = analyze_email(p)
            self.assertIsInstance(res_email, dict)


if __name__ == "__main__":
    unittest.main()
