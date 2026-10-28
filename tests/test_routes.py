"""
Integration tests for Flask application routes and API endpoints.
Verifies HTTP status codes, security headers, validation, and error handling.
"""
import unittest
import json
from app import create_app


class TestRoutes(unittest.TestCase):

    def setUp(self):
        """Create application test client."""
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_get_index(self):
        """GET / should return 200 and serve HTML dashboard with security headers."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Phishing Awareness Analyzer", response.data)
        
        # Verify Security Headers
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))

    def test_get_samples(self):
        """GET /api/samples should return 200 and sample payloads."""
        response = self.client.get("/api/samples")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("samples", data)
        self.assertIn("url_phishing", data["samples"])
        self.assertIn("url_legitimate", data["samples"])
        self.assertIn("email_phishing", data["samples"])
        self.assertIn("email_legitimate", data["samples"])

    def test_analyze_url_valid(self):
        """POST /api/analyze-url with valid URL returns 200 with score and indicators."""
        payload = {"url": "http://192.168.1.100/paypal.com/login-verify.php?id=9928"}
        response = self.client.post(
            "/api/analyze-url",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("is_valid"))
        self.assertIn("scoring", data)
        self.assertGreater(data["scoring"]["score"], 0)

    def test_analyze_url_empty_or_missing(self):
        """POST /api/analyze-url with empty or missing payload returns 400."""
        # Empty string
        res_empty = self.client.post(
            "/api/analyze-url",
            data=json.dumps({"url": ""}),
            content_type="application/json"
        )
        self.assertEqual(res_empty.status_code, 400)

        # Missing field
        res_missing = self.client.post(
            "/api/analyze-url",
            data=json.dumps({}),
            content_type="application/json"
        )
        self.assertEqual(res_missing.status_code, 400)

        # Non-JSON content type
        res_not_json = self.client.post(
            "/api/analyze-url",
            data="not-json",
            content_type="text/plain"
        )
        self.assertEqual(res_not_json.status_code, 400)

    def test_analyze_email_valid(self):
        """POST /api/analyze-email with valid body returns 200."""
        payload = {
            "email_body": "Dear Customer, please verify your account immediately at http://phish.net",
            "sender": "Security Desk <alert@fraud.com>"
        }
        response = self.client.post(
            "/api/analyze-email",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("is_valid"))
        self.assertIn("scoring", data)
        self.assertIn("extracted_urls", data)

    def test_analyze_email_empty_body(self):
        """POST /api/analyze-email with empty body returns 400."""
        response = self.client.post(
            "/api/analyze-email",
            data=json.dumps({"email_body": "   "}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)

    def test_not_found_endpoint(self):
        """Accessing a non-existent route should trigger 404 handler."""
        response = self.client.get("/api/non-existent-endpoint")
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIn("error", data)

    def test_method_not_allowed(self):
        """Using wrong method (GET on POST-only endpoint) should trigger 405 handler."""
        response = self.client.get("/api/analyze-url")
        self.assertEqual(response.status_code, 405)
        data = response.get_json()
        self.assertIn("error", data)

    def test_analyze_email_null_sender_regression(self):
        """Regression Test: Submitting email with sender=None (as sent by browser UI) must return 200 OK, not 500."""
        payload = {
            "email_body": "Dear user,\nYour account has been suspended. Please verify your password immediately within 24 hours:\nhttps://secure-login-portal.com/verify",
            "sender": None
        }
        response = self.client.post(
            "/api/analyze-email",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("is_valid"))
        self.assertEqual(data["scoring"]["tier"], "HIGH RISK")
        self.assertGreaterEqual(data["scoring"]["score"], 60)
        self.assertGreaterEqual(len(data.get("extracted_urls", [])), 1)

    def test_analyze_email_ordinary_workplace_clean(self):
        """Ordinary workplace communication without sender header must return 200 OK and LOW RISK tier."""
        payload = {
            "email_body": "Hi team,\nJust a reminder that our weekly project sync is scheduled for tomorrow at 10 AM.\nBest regards,\nAlex",
            "sender": None
        }
        response = self.client.post(
            "/api/analyze-email",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("is_valid"))
        self.assertEqual(data["scoring"]["tier"], "LOW RISK")
        self.assertEqual(data["scoring"]["score"], 0)


if __name__ == "__main__":
    unittest.main()
