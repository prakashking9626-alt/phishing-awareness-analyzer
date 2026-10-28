"""
Safe, Local Static Email Content Analyzer for Phishing Detection.
Evaluates email body text, embedded links, and sender header metadata using deterministic heuristics.
Strictly offline and in-memory: Zero network traffic and zero persistence.
"""
import re
from typing import Optional, List, Dict, Any
from app.analyzers.url_analyzer import analyze_url

# 1. Urgency & Coercive Pressure Phrases
URGENCY_PATTERNS = [
    r"\bact immediately\b",
    r"\bwithin 24 hours\b",
    r"\bwithin 12 hours\b",
    r"\bwithin 48 hours\b",
    r"\bimmediate(ly)? (action|response|attention|termination|verification)\b",
    r"\baction required immediately\b",
    r"\burgent attention required\b",
    r"\baccount (will be|has been) suspended\b",
    r"\baccount (is|has been) (locked|compromised|flagged|restricted)\b",
    r"\bpassword (will|is going to|about to) expire\b",
    r"\bexpire(s|d)? (today|tonight|soon|immediately|within)\b",
    r"\bunauthorized (login|access|activity|sign-in)\b",
    r"\bsuspicious (activity|sign-in|login)\b",
    r"\bsecurity (notice|alert|warning)\b",
    r"\bdeadline expiring\b",
    r"\bfailure to (respond|verify|update) will result\b",
    r"\btime is running out\b",
    r"\blimited time offer\b",
    r"\bdo not delay\b",
    r"\brespond promptly\b"
]

# 2. Threat Language & Extortion / Coercion
THREAT_PATTERNS = [
    r"\b(account|immediate|service|profile) (termination|closure|cancellation|deactivation)\b",
    r"\blegal action\b",
    r"\bpolice notification\b",
    r"\blaw enforcement\b",
    r"\bunpaid invoice(s)?\b",
    r"\bdebt collection\b",
    r"\bcourt summons\b",
    r"\barrest warrant\b",
    r"\bpermanent suspension\b",
    r"\baccess will be revoked\b",
    r"\bsecurity violation detected\b",
    r"\bcompromised account\b",
    r"\baccount locked\b",
    r"\bservice will be (interrupted|suspended|terminated)\b",
    r"\bunauthorized transaction\b"
]

# 3. Credential & Financial Solicitation
CREDENTIAL_FINANCIAL_PATTERNS = [
    r"\b(enter|confirm|verify|provide|update|submit) (your )?(password|passcode|pin|credentials)\b",
    r"\b(two-factor|2fa|mfa) (code|token|verification)\b",
    r"\b(credit|debit) card (number|details|expiration|cvv|cvc)\b",
    r"\bbank account (number|verification|details)\b",
    r"\bsocial security number\b|\bssn\b",
    r"\bgift card(s)? (purchase|payment|code)\b",
    r"\b(bitcoin|crypto|cryptocurrency|wallet) transfer\b",
    r"\bwire transfer\b",
    r"\bclick here to (login|verify|unlock|update|reactivate|restore|keep)\b",
    r"\bconfirm your (identity|password|details|account)\b",
    r"\bverify your (identity|account|credentials|email|information)\b",
    r"\breset your password\b"
]

# 4. Generic & Impersonal Salutations
GENERIC_SALUTATION_PATTERNS = [
    r"^(dear|hello|greetings|attention)\s+(customer|member|user|account holder|client|valued customer|undisclosed recipient|colleague)\b",
    r"^(dear|hello)\s+(sir/madam|sir or madam)\b",
    r"^undisclosed recipient(s)?\b"
]

# Known brands and their official sender domains for spoofing detection
BRAND_OFFICIAL_DOMAINS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "meta": ["meta.com", "facebook.com"],
    "linkedin": ["linkedin.com"]
}

# Regex to safely locate embedded HTTP/HTTPS URLs without executing them
URL_REGEX = re.compile(r"https?://[^\s<>\"'\)\],;]+", re.IGNORECASE)


def extract_sender_parts(sender_str: str) -> tuple[str, str, str]:
    """
    Parses display name and email address from typical formats like:
    'PayPal Security <support@attacker-domain.com>' or 'alert@domain.com'
    Returns (display_name, email_address, domain).
    """
    sender_str = sender_str.strip()
    match = re.search(r"^(.*?)\s*<([^>]+)>$", sender_str)
    if match:
        display_name = match.group(1).strip().strip("\"'")
        email_addr = match.group(2).strip().lower()
    else:
        display_name = ""
        email_addr = sender_str.lower()

    domain = email_addr.split("@")[-1] if "@" in email_addr else ""
    return display_name, email_addr, domain


def analyze_email(email_body: str, sender_header: Optional[str] = None) -> dict:
    """
    Performs deterministic, local static heuristic analysis on email body and optional sender.
    Includes embedded link extraction, psychological pressure detection, and display-name spoofing checks.
    """
    if not email_body or not isinstance(email_body, str) or not email_body.strip():
        return {
            "is_valid": False,
            "error": "Empty or invalid email body provided.",
            "indicators": [],
            "extracted_urls": [],
            "parsed_components": {}
        }

    body = email_body.replace("\x00", "").strip()
    clean_sender = sender_header.replace("\x00", "").strip() if (sender_header and isinstance(sender_header, str)) else None
    indicators: List[Dict[str, Any]] = []
    lines = [line.strip() for line in body.splitlines() if line.strip()]

    # Check 1: Generic & Impersonal Salutations
    generic_salutation_found = False
    for line in lines[:3]:  # Check initial lines
        for pattern in GENERIC_SALUTATION_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match and not generic_salutation_found:
                generic_salutation_found = True
                indicators.append({
                    "id": "EMAIL_GENERIC_SALUTATION",
                    "category": "Salutation & Personalization",
                    "severity": "LOW",
                    "title": "Generic Impersonal Salutation",
                    "description": "Email employs a generic greeting (e.g. 'Dear Customer') rather than addressing the recipient by full name. Mass phishing campaigns frequently use impersonal greetings to maximize recipient pool.",
                    "evidence": f"Greeting: \"{match.group(0)}\"",
                    "recommendation": "Legitimate service providers with whom you hold an account typically personalize notifications with your registered name."
                })
                break

    # Check 2: Urgency & Coercive Pressure
    urgency_matches = []
    for pattern in URGENCY_PATTERNS:
        found = re.findall(pattern, body, re.IGNORECASE)
        if found:
            for item in found:
                text_match = item if isinstance(item, str) else item[0]
                if text_match.lower() not in [m.lower() for m in urgency_matches]:
                    urgency_matches.append(text_match)

    if urgency_matches:
        indicators.append({
            "id": "EMAIL_URGENCY_PRESSURE",
            "category": "Psychological Manipulation",
            "severity": "MEDIUM",
            "title": f"Artificial Urgency & Time Pressure ({len(urgency_matches)} phrase(s))",
            "description": "Language imposes intense deadlines or rapid actions to induce cognitive panic and bypass cautious skepticism before clicking or providing credentials.",
            "evidence": f"Urgency indicators: \"{', '.join(urgency_matches[:3])}\"",
            "recommendation": "Pause and independently verify urgent demands through trusted off-platform channels. Legitimate organizations rarely demand 24-hour ultimatums via plain email."
        })

    # Check 3: Threat Language & Extortion
    threat_matches = []
    for pattern in THREAT_PATTERNS:
        found = re.findall(pattern, body, re.IGNORECASE)
        if found:
            for item in found:
                text_match = item if isinstance(item, str) else item[0]
                if text_match.lower() not in [m.lower() for m in threat_matches]:
                    threat_matches.append(text_match)

    if threat_matches:
        indicators.append({
            "id": "EMAIL_THREAT_EXTORTION",
            "category": "Psychological Manipulation",
            "severity": "HIGH",
            "title": f"Punitive Threat / Extortion Language ({len(threat_matches)} phrase(s))",
            "description": "Email threatens severe consequences such as immediate account termination, legal litigation, law enforcement action, or financial penalties.",
            "evidence": f"Threat triggers: \"{', '.join(threat_matches[:3])}\"",
            "recommendation": "Be skeptical of threatening emails. Contact the purported service directly via their official app or verified contact phone number."
        })

    # Check 4: Credential & Financial Solicitation
    credential_matches = []
    for pattern in CREDENTIAL_FINANCIAL_PATTERNS:
        found = re.findall(pattern, body, re.IGNORECASE)
        if found:
            for item in found:
                # Group or tuple handling
                text_match = item if isinstance(item, str) else (item[0] or pattern)
                if text_match.lower() not in [m.lower() for m in credential_matches]:
                    credential_matches.append(text_match)

    if credential_matches:
        indicators.append({
            "id": "EMAIL_CREDENTIAL_SOLICITATION",
            "category": "Credential Harvesting",
            "severity": "CRITICAL",
            "title": "Direct Credential or Financial Solicitation",
            "description": "Email requests passwords, PINs, 2FA verification codes, payment card numbers, or cryptocurrency transfers. Reputable institutions never request secrets or 2FA codes via email.",
            "evidence": f"Solicitation triggers: \"{', '.join(credential_matches[:3])}\"",
            "recommendation": "NEVER share passwords, one-time SMS/authenticator passcodes, or banking credentials via email or unsolicited web forms."
        })

    # Check 5: Sender Display Name Inconsistencies (Header Spoofing Heuristic)
    parsed_sender = {}
    if clean_sender:
        display_name, email_addr, domain = extract_sender_parts(clean_sender)
        parsed_sender = {
            "raw": clean_sender,
            "display_name": display_name,
            "email_address": email_addr,
            "domain": domain
        }

        # Check if display name mentions a brand that doesn't match domain
        display_lower = display_name.lower()
        for brand, legit_domains in BRAND_OFFICIAL_DOMAINS.items():
            if brand in display_lower:
                domain_matches = any(domain.endswith(ld) for ld in legit_domains)
                if not domain_matches:
                    indicators.append({
                        "id": "EMAIL_SENDER_MISMATCH",
                        "category": "Identity Impersonation",
                        "severity": "HIGH",
                        "title": f"Sender Display Name Spoofing ({brand.title()})",
                        "description": f"The display name claims to represent '{display_name}', but the underlying sender domain ('{domain or 'unspecified'}') does NOT match any authorized domain for {brand.title()}.",
                        "evidence": f"Display: \"{display_name}\" vs Actual Address: <{email_addr}>",
                        "recommendation": "Inspect the true email address inside angle brackets (<...>). Never trust display names alone."
                    })
                    break

    # Check 6: Embedded URL Extraction & Sub-Analysis
    raw_urls = URL_REGEX.findall(body)
    extracted_urls_results = []
    has_critical_embedded_url = False
    has_high_embedded_url = False

    for url in set(raw_urls):
        url_res = analyze_url(url)
        extracted_urls_results.append({
            "url": url,
            "is_valid": url_res["is_valid"],
            "indicators_count": len(url_res["indicators"]),
            "indicators": url_res["indicators"]
        })

        for ind in url_res["indicators"]:
            if ind["severity"] == "CRITICAL":
                has_critical_embedded_url = True
            elif ind["severity"] == "HIGH":
                has_high_embedded_url = True

    if raw_urls:
        if has_critical_embedded_url:
            indicators.append({
                "id": "EMAIL_EMBEDDED_CRITICAL_URL",
                "category": "Embedded Links",
                "severity": "CRITICAL",
                "title": f"High-Risk Embedded Link ({len(raw_urls)} total link(s) discovered)",
                "description": "An embedded URL inside the email exhibits critical malicious indicators (e.g. raw IP address host or deceptive userinfo trick).",
                "evidence": f"Found {len(raw_urls)} link(s); critical risks identified in embedded URL analysis",
                "recommendation": "Do not click any hyperlinks embedded inside this message."
            })
        elif has_high_embedded_url:
            indicators.append({
                "id": "EMAIL_EMBEDDED_SUSPICIOUS_URL",
                "category": "Embedded Links",
                "severity": "HIGH",
                "title": f"Suspicious Embedded Link ({len(raw_urls)} total link(s) discovered)",
                "description": "An embedded URL inside the email utilizes URL shorteners, typosquatted brand names, or deceptive subdomain structures.",
                "evidence": f"Found {len(raw_urls)} link(s); high-severity indicators detected",
                "recommendation": "Inspect destination URLs thoroughly before clicking. Prefer navigating via browser bookmarks."
            })
        else:
            indicators.append({
                "id": "EMAIL_EMBEDDED_LINKS_PRESENT",
                "category": "Embedded Links",
                "severity": "INFORMATIONAL",
                "title": f"Embedded Hyperlinks Detected ({len(raw_urls)} link(s))",
                "description": f"Email contains {len(raw_urls)} external web link(s).",
                "evidence": f"Found: {', '.join(raw_urls[:2])}{'...' if len(raw_urls) > 2 else ''}",
                "recommendation": "Always verify link targets before entering credentials or executing downloads."
            })

    # Educational Advisory Note
    advisory_notice = (
        "Advisory Notice: Static text heuristics evaluate lexical, psychological, and formatting cues. "
        "They cannot inspect cryptographic email authentication signatures (SPF, DKIM, DMARC) or mail server relay records. "
        "Classification is purely advisory for security awareness."
    )

    return {
        "is_valid": True,
        "indicators": indicators,
        "extracted_urls": extracted_urls_results,
        "parsed_components": {
            "body_length_chars": len(body),
            "line_count": len(lines),
            "url_count": len(raw_urls),
            "sender": parsed_sender
        },
        "advisory_notice": advisory_notice
    }
