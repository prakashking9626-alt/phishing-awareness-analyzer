"""
Unit tests for the Email Content Analyzer.
Verifies urgency cues, threat language, credential requests, embedded links, and sender spoofing.
"""
import unittest
from app.analyzers.email_analyzer import analyze_email, extract_sender_parts


class TestEmailAnalyzer(unittest.TestCase):

    def test_empty_email_body(self):
        """Empty or None email body should return is_valid=False with error."""
        res_none = analyze_email(None)
        self.assertFalse(res_none["is_valid"])
        self.assertIn("error", res_none)

        res_empty = analyze_email("    ")
        self.assertFalse(res_empty["is_valid"])

    def test_phishing_email_heuristics(self):
        """Phishing email with urgency, threats, credential demands must trigger matching indicators."""
        phish_text = (
            "Dear Customer,\n"
            "URGENT: Your account will be suspended within 24 hours due to a security violation.\n"
            "To avoid legal action and immediate termination, you must act immediately to confirm your password "
            "and submit your 2FA verification token.\n"
            "Click here: https://bit.ly/update-now"
        )
        res = analyze_email(phish_text)
        self.assertTrue(res["is_valid"])

        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("EMAIL_GENERIC_SALUTATION", indicator_ids)
        self.assertIn("EMAIL_URGENCY_PRESSURE", indicator_ids)
        self.assertIn("EMAIL_THREAT_EXTORTION", indicator_ids)
        self.assertIn("EMAIL_CREDENTIAL_SOLICITATION", indicator_ids)
        self.assertIn("EMAIL_EMBEDDED_SUSPICIOUS_URL", indicator_ids)

    def test_legitimate_email_heuristics(self):
        """Legitimate workplace communication should not trigger false positives."""
        legit_text = (
            "Good morning Alice,\n\n"
            "Attached is the project brief for next quarter's release. Please review the details "
            "whenever your schedule permits so we can discuss it at the next sync.\n\n"
            "Best regards,\n"
            "David Miller"
        )
        res = analyze_email(legit_text)
        self.assertTrue(res["is_valid"])
        indicator_ids = [ind["id"] for ind in res["indicators"]]

        # None of the severe phishing triggers should be present
        self.assertNotIn("EMAIL_URGENCY_PRESSURE", indicator_ids)
        self.assertNotIn("EMAIL_THREAT_EXTORTION", indicator_ids)
        self.assertNotIn("EMAIL_CREDENTIAL_SOLICITATION", indicator_ids)

    def test_sender_display_name_spoofing(self):
        """Sender claiming to be PayPal with mismatched domain should be flagged."""
        sender_header = "PayPal Support <security-alert@random-domain.xyz>"
        body = "Please review your monthly statement at your earliest convenience."
        res = analyze_email(body, sender_header=sender_header)
        self.assertTrue(res["is_valid"])

        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("EMAIL_SENDER_MISMATCH", indicator_ids)

    def test_sender_display_name_legitimate(self):
        """Sender with matching brand domain should NOT be flagged for mismatch."""
        sender_header = "PayPal Service <service@paypal.com>"
        body = "Here is your receipt for transaction #12345."
        res = analyze_email(body, sender_header=sender_header)
        self.assertTrue(res["is_valid"])

        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertNotIn("EMAIL_SENDER_MISMATCH", indicator_ids)

    def test_embedded_url_extraction(self):
        """Embedded URLs must be extracted and analyzed."""
        body = (
            "Please check the following resources:\n"
            "https://www.cybersecurity.ox.ac.uk/guidance/resources\n"
            "and also review http://192.168.1.1/admin"
        )
        res = analyze_email(body)
        self.assertTrue(res["is_valid"])
        self.assertEqual(len(res["extracted_urls"]), 2)

        # The IP address link should have flagged EMAIL_EMBEDDED_CRITICAL_URL
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("EMAIL_EMBEDDED_CRITICAL_URL", indicator_ids)

    def test_extract_sender_parts_helper(self):
        """Helper should parse display name, email, and domain properly."""
        disp, addr, dom = extract_sender_parts("Microsoft Team <support@microsoft.com>")
        self.assertEqual(disp, "Microsoft Team")
        self.assertEqual(addr, "support@microsoft.com")
        self.assertEqual(dom, "microsoft.com")

        disp2, addr2, dom2 = extract_sender_parts("plain@domain.org")
        self.assertEqual(disp2, "")
        self.assertEqual(addr2, "plain@domain.org")
        self.assertEqual(dom2, "domain.org")


if __name__ == "__main__":
    unittest.main()
