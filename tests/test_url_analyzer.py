"""
Unit tests for the URL Static Analyzer.
Verifies protocol handling, IP hosts, shorteners, typosquatting, and malformed inputs.
"""
import unittest
from app.analyzers.url_analyzer import analyze_url, is_ip_address, extract_registered_domain


class TestUrlAnalyzer(unittest.TestCase):

    def test_empty_or_none_url(self):
        """Empty or None input should return is_valid=False with an error message."""
        res_none = analyze_url(None)
        self.assertFalse(res_none["is_valid"])
        self.assertIn("error", res_none)

        res_empty = analyze_url("   ")
        self.assertFalse(res_empty["is_valid"])
        self.assertIn("error", res_empty)

    def test_valid_https_url(self):
        """Legitimate HTTPS URL should parse properly and detect HTTPS transport."""
        url = "https://www.cybersecurity.ox.ac.uk/guidance/resources"
        res = analyze_url(url)
        self.assertTrue(res["is_valid"])
        components = res["parsed_components"]
        self.assertEqual(components["scheme"], "https")
        self.assertEqual(components["registered_domain"], "ox.ac.uk")
        # Check that HTTPS indicator is present
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_HTTPS_PRESENT", indicator_ids)
        # Should NOT contain IP or typosquatting triggers
        self.assertNotIn("URL_IP_HOST", indicator_ids)
        self.assertNotIn("URL_TYPOSQUATTING", indicator_ids)

    def test_http_cleartext_url(self):
        """HTTP scheme should trigger cleartext transport indicator."""
        url = "http://example.org/about"
        res = analyze_url(url)
        self.assertTrue(res["is_valid"])
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_HTTP_CLEARTEXT", indicator_ids)

    def test_ip_address_host(self):
        """Raw IPv4 or IPv6 as host must trigger CRITICAL IP host indicator."""
        url_v4 = "http://192.168.1.100/login.php"
        res_v4 = analyze_url(url_v4)
        self.assertTrue(res_v4["is_valid"])
        indicator_ids = [ind["id"] for ind in res_v4["indicators"]]
        self.assertIn("URL_IP_HOST", indicator_ids)

        url_v6 = "http://[2001:db8::1]:8080/index.html"
        res_v6 = analyze_url(url_v6)
        self.assertTrue(res_v6["is_valid"])
        indicator_ids_v6 = [ind["id"] for ind in res_v6["indicators"]]
        self.assertIn("URL_IP_HOST", indicator_ids_v6)

    def test_userinfo_trick(self):
        """URLs utilizing @ symbol before host must trigger CRITICAL userinfo trick."""
        url = "https://legitimate-bank.com@malicious-phish.net/login"
        res = analyze_url(url)
        self.assertTrue(res["is_valid"])
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_USERINFO_TRICK", indicator_ids)

    def test_url_shorteners(self):
        """Known URL shorteners must be flagged with HIGH severity."""
        short_urls = [
            "https://bit.ly/secure-account",
            "https://tinyurl.com/it-verify-login-portal",
            "https://t.co/xyz123"
        ]
        for url in short_urls:
            res = analyze_url(url)
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertIn("URL_SHORTENER", indicator_ids)

    def test_excessive_subdomains(self):
        """URLs with excessive subdomain depth (> 3 levels) must be flagged."""
        deep_url = "https://login.portal.corp.account.verify.attacker.com/page"
        res = analyze_url(deep_url)
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_EXCESSIVE_SUBDOMAINS", indicator_ids)

    def test_subdomain_brand_impersonation(self):
        """Brand embedded in subdomains with an unrelated apex domain must be flagged."""
        spoofed_url = "https://paypal.com.account-verification.suspicious.net/login"
        res = analyze_url(spoofed_url)
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_SUBDOMAIN_BRAND_IMPERSONATION", indicator_ids)

    def test_path_brand_impersonation(self):
        """Brand domain embedded in path of IP or non-brand host must be flagged."""
        path_spoofed_url = "http://192.168.1.100/paypal.com/login-verify.php"
        res = analyze_url(path_spoofed_url)
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_PATH_BRAND_IMPERSONATION", indicator_ids)

    def test_punycode_idn(self):
        """Punycode xn-- hostnames must be flagged."""
        punycode_url = "https://xn--pypal-4ve.com/account"
        res = analyze_url(punycode_url)
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_IDN_PUNYCODE", indicator_ids)

    def test_typosquatting_and_compounds(self):
        """Common typosquats (paypa1, arnazon, micros0ft) must be flagged."""
        typos = [
            "https://paypa1.com/update",
            "https://arnazon.com/order",
            "https://micros0ft.com/office"
        ]
        for url in typos:
            res = analyze_url(url)
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertTrue(
                "URL_TYPOSQUATTING" in indicator_ids or "URL_BRAND_COMPOUND" in indicator_ids,
                f"Failed to detect typosquatting on {url}"
            )

    def test_non_standard_port(self):
        """Non-standard ports (e.g. 8080, 8443) must be flagged."""
        url = "https://example.com:8443/dashboard"
        res = analyze_url(url)
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_NON_STANDARD_PORT", indicator_ids)

    def test_malformed_non_numeric_port(self):
        """URLs with corrupted non-numeric port strings must be handled gracefully without crashing."""
        url = "http://example.com:\x0fGw/test"
        res = analyze_url(url)
        self.assertTrue(res["is_valid"])
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_NON_STANDARD_PORT", indicator_ids)

    def test_dangerous_schemes(self):
        """Dangerous non-web schemes (javascript:, data:, file:) must be rejected."""
        schemes = ["javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "file:///etc/passwd"]
        for s in schemes:
            res = analyze_url(s)
            self.assertFalse(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertIn("URL_DANGEROUS_SCHEME", indicator_ids)

    def test_percent_encoding(self):
        """Heavy percent-encoding must be flagged."""
        url = "http://example.com/%20%2F%40%25login"
        res = analyze_url(url)
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_SUSPICIOUS_ENCODING", indicator_ids)

    def test_deceptive_hostname_auth_compounds(self):
        """Hostnames compounding multiple deceptive auth/credential keywords must be flagged."""
        suspicious_urls = [
            "https://secure-login-portal.com",
            "https://login-verification-portal.com",
            "https://login.secure-bank-update.com",
            "https://login.live.com.user-verify.net",
            "https://account-verify-portal.net"
        ]
        for url in suspicious_urls:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            has_deceptive_trigger = any(
                ind in indicator_ids for ind in (
                    "URL_DECEPTIVE_HOSTNAME_LURE",
                    "URL_SUBDOMAIN_BRAND_IMPERSONATION",
                    "URL_BRAND_COMPOUND"
                )
            )
            self.assertTrue(
                has_deceptive_trigger,
                f"Expected deceptive hostname trigger on {url}, got: {indicator_ids}"
            )

    def test_legitimate_auth_portals_no_false_positives(self):
        """Legitimate brand login portals over HTTPS must not trigger false positive phishing flags."""
        legit_portals = [
            "https://login.microsoftonline.com",
            "https://accounts.google.com",
            "https://www.paypal.com/signin",
            "https://github.com/login",
            "https://appleid.apple.com"
        ]
        for url in legit_portals:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            # None of these should be flagged as deceptive lures, typosquats, or shorteners
            self.assertNotIn("URL_DECEPTIVE_HOSTNAME_LURE", indicator_ids)
            self.assertNotIn("URL_TYPOSQUATTING", indicator_ids)
            self.assertNotIn("URL_SUBDOMAIN_BRAND_IMPERSONATION", indicator_ids)
            self.assertNotIn("URL_SUSPICIOUS_KEYWORDS", indicator_ids)

    def test_high_risk_tld_with_auth_lure(self):
        """High-risk TLDs paired with credential keywords must be flagged."""
        tld_lure_urls = [
            "https://verify-account.xyz",
            "https://support-portal.top",
            "https://banking-update.work"
        ]
        for url in tld_lure_urls:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertTrue(
                any(ind in indicator_ids for ind in ("URL_HIGH_RISK_TLD_AUTH", "URL_DECEPTIVE_HOSTNAME_LURE")),
                f"Expected high-risk TLD lure trigger on {url}, got: {indicator_ids}"
            )

    def test_false_negative_deep_subdomain_phishing(self):
        """
        Regression Test: Confirmed Kaggle phishing URL with deep subdomains,
        embedded TLD masquerading, DGA random label, and typosquatted brand.
        Must evaluate to High Risk (>= 60) and never 'No Obvious Threat Detected'.
        """
        target_url = "https://signin.eby.de.zukruygxctzmmqi.civpro.co.za"
        res = analyze_url(target_url)
        self.assertTrue(res["is_valid"])
        components = res["parsed_components"]
        self.assertEqual(components["registered_domain"], "civpro.co.za")
        self.assertEqual(components["subdomains"], ["signin", "eby", "de", "zukruygxctzmmqi"])

        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_SUBDOMAIN_TLD_MASQUERADE", indicator_ids)
        self.assertIn("URL_RANDOM_SUBDOMAIN_LABEL", indicator_ids)
        self.assertIn("URL_DECEPTIVE_SUBDOMAIN_LURE", indicator_ids)
        self.assertIn("URL_TYPOSQUATTING", indicator_ids)

        from app.analyzers.scoring_engine import calculate_risk_score
        scoring = calculate_risk_score(res["indicators"])
        self.assertGreaterEqual(scoring["score"], 60)
        self.assertEqual(scoring["category"], "High Risk")

    def test_malware_executable_download(self):
        """Direct executable file downloads in URL path must trigger critical malware indicator."""
        malware_urls = [
            "http://example-malware-payload.com/billing_statement.pdf.exe",
            "https://suspicious-download.net/payload.scr?token=123",
            "http://updater.badsite.org/setup.apk"
        ]
        for url in malware_urls:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertIn("URL_MALWARE_EXECUTABLE_DOWNLOAD", indicator_ids)

    def test_defacement_compromise_indicator(self):
        """Defacement signatures and web shell markers in path must be flagged."""
        defaced_urls = [
            "http://vulnerable-site.com/administrator/components/com_media/deface.html",
            "http://compromised-blog.net/wp-content/plugins/root.html",
            "http://target.org/includes/c99.php"
        ]
        for url in defaced_urls:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertIn("URL_DEFACEMENT_COMPROMISE", indicator_ids)

    def test_legitimate_ebay_login_no_false_positive(self):
        """Legitimate eBay portals (including international ccTLDs like ebay.de) must score clean."""
        ebay_portals = [
            "https://signin.ebay.com",
            "https://signin.ebay.de",
            "https://signin.ebay.co.uk"
        ]
        for url in ebay_portals:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertNotIn("URL_TYPOSQUATTING", indicator_ids)
            self.assertNotIn("URL_SUBDOMAIN_BRAND_IMPERSONATION", indicator_ids)
            self.assertNotIn("URL_DECEPTIVE_HOSTNAME_LURE", indicator_ids)

    def test_bounded_typosquatting_no_benign_false_positives(self):
        """Benign words containing brand fragments (e.g. pineapple, snapple) must NOT trigger typosquatting."""
        benign_urls = [
            "https://www.pineapple.com",
            "https://snapple.com/products",
            "https://grapple.org/info"
        ]
        for url in benign_urls:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertNotIn("URL_TYPOSQUATTING", indicator_ids)

    def test_unencrypted_http_cleartext_auth_submission(self):
        """URLs requesting login credentials over cleartext HTTP must trigger URL_CLEARTEXT_AUTH_SUBMISSION."""
        cleartext_logins = [
            "http://example-portal.com/login.html",
            "http://emotivaodontologia.com.br/signin/",
            "http://untrusted-server.net/auth/logon.aspx"
        ]
        for url in cleartext_logins:
            res = analyze_url(url)
            self.assertTrue(res["is_valid"])
            indicator_ids = [ind["id"] for ind in res["indicators"]]
            self.assertIn("URL_CLEARTEXT_AUTH_SUBMISSION", indicator_ids)

    def test_expanded_brand_path_and_logon_lure(self):
        """Path brand impersonation with logon token on unrelated domain must be flagged."""
        url = "https://cartoworld.co.ke/smsm/chase/Logon.aspx/"
        res = analyze_url(url)
        self.assertTrue(res["is_valid"])
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_PATH_BRAND_IMPERSONATION", indicator_ids)

    def test_blizzard_battlenet_brand_impersonation(self):
        """Subdomains mimicking battle.net/blizzard on unrelated apex domains must be flagged."""
        url = "http://us.battle.net.login.en.tw-login.com/login/en/login.html"
        res = analyze_url(url)
        self.assertTrue(res["is_valid"])
        indicator_ids = [ind["id"] for ind in res["indicators"]]
        self.assertIn("URL_SUBDOMAIN_BRAND_IMPERSONATION", indicator_ids)


if __name__ == "__main__":
    unittest.main()
