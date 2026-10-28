"""
Safe, Local Static URL Analyzer for Phishing Detection.
Strictly offline and deterministic: No DNS, socket, or network traffic generated.
"""
import ipaddress
import math
import re
from urllib.parse import urlparse, unquote

# Set of common URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "rebrand.ly",
    "buff.ly", "cutt.ly", "goo.gl", "shorturl.at", "tiny.cc", "clck.ru",
    "rotf.lol", "bc.vc", "rb.gy", "v.gd"
}

# Sensitive authentication & financial keywords
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "verify", "verification", "account", "update", "banking",
    "secure", "confirm", "confirmation", "credential", "signin", "wallet",
    "authenticate", "authentication", "password", "security", "validation",
    "suspended", "unlock", "billing", "recover", "logon", "sign-in",
    "log-in", "webscr", "ebayisapi", "cpanel", "webmail", "passcode", "otp"
]

# High-profile brand targets for typosquatting & subdomain impersonation
MONITORED_BRANDS = {
    "paypal": ["paypal.com", "paypal-community.com"],
    "google": ["google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "youtube.com"],
    "microsoft": [
        "microsoft.com", "live.com", "office.com", "office365.com",
        "microsoftonline.com", "azure.com", "windowsazure.com", "msft.net",
        "sharepoint.com", "outlook.com"
    ],
    "apple": ["apple.com", "icloud.com", "itunes.com"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": [
        "amazon.com", "amazonaws.com", "primevideo.com", "amazon.co.uk",
        "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca",
        "amazon.co.jp", "amazon.in"
    ],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com"],
    "chase": ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
    "wellsfargo": ["wellsfargo.com", "wf.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "bofa": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com", "citigroup.com"],
    "citi": ["citi.com", "citibank.com", "citigroup.com"],
    "yahoo": ["yahoo.com", "ymail.com", "yahoo.net", "yahoo.co.uk", "yahoo.de", "yahoo.fr"],
    "gmail": ["gmail.com", "google.com"],
    "outlook": ["outlook.com", "microsoft.com", "live.com"],
    "onedrive": ["onedrive.com", "live.com", "microsoft.com"],
    "ebay": ["ebay.com", "ebay.de", "ebay.co.uk", "ebay.fr", "ebay.it", "ebay.es", "ebay.ca", "ebay.com.au"],
    "battle.net": ["battle.net", "blizzard.com"],
    "blizzard": ["blizzard.com", "battle.net"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "walmart": ["walmart.com"],
    "lloyds": ["lloydsbank.com", "lloydstsb.com"],
    "westpac": ["westpac.com.au", "westpac.co.nz"],
    "hsbc": ["hsbc.com", "hsbc.co.uk"],
    "barclays": ["barclays.co.uk", "barclays.com"],
    "santander": ["santander.com", "santander.co.uk"],
    "github": ["github.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"]
}

# Sensitive tokens often abused in deceptive hostnames
AUTH_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "secure",
    "security", "portal", "banking", "auth", "authenticate", "credential",
    "update", "confirm", "confirmation", "wallet", "recover", "unlock",
    "alert", "billing", "support", "validation", "suspended", "protection",
    "protect", "card", "service", "customer", "client", "password",
    "online", "web", "pay", "payment", "fund", "transfer", "bonus", "claim",
    "logon", "sign-in", "log-in", "webscr", "ebayisapi", "cpanel", "webmail",
    "admin", "passcode", "otp"
}

# Known high-risk or commonly abused TLDs in disposable phishing campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "work", "click", "buzz", "club", "cam", "rest",
    "loan", "gq", "cf", "tk", "ml", "ga", "fit", "surf", "live", "support",
    "tech", "site", "space", "icu", "bid"
}

# Known typosquatting character substitutions
TYPOSQUAT_PATTERNS = [
    (r"(?:^|[-_.0-9])paypa[l1i](?:$|[-_.0-9])", "paypal"),
    (r"(?:^|[-_.0-9])p+a+y+p+a+[l1i]{2,}(?:$|[-_.0-9])", "paypal"),
    (r"(?:^|[-_.0-9])arnazon(?:$|[-_.0-9])", "amazon"),
    (r"(?:^|[-_.0-9])a+m{2,}a+z+o+n+(?:$|[-_.0-9])", "amazon"),
    (r"(?:^|[-_.0-9])micros[0o]ft(?:$|[-_.0-9])", "microsoft"),
    (r"(?:^|[-_.0-9])g[0o]{2}g[l1i]e(?:$|[-_.0-9])", "google"),
    (r"(?:^|[-_.0-9])g+[0o]{3,}g+[l1i]+e+(?:$|[-_.0-9])", "google"),
    (r"(?:^|[-_.0-9])app[l1i]e(?:$|[-_.0-9])", "apple"),
    (r"(?:^|[-_.0-9])a+p{3,}l+e+(?:$|[-_.0-9])", "apple"),
    (r"(?:^|[-_.0-9])netf[l1i]x(?:$|[-_.0-9])", "netflix"),
    (r"(?:^|[-_.0-9])faceb[0o]{2}k(?:$|[-_.0-9])", "facebook"),
    (r"(?:^|[-_.0-9])we[l1i]{2}sfarg[0o](?:$|[-_.0-9])", "wellsfargo"),
    (r"(?:^|[-_.0-9])c[1i]t[1i]bank(?:$|[-_.0-9])", "citibank"),
    (r"(?:^|[-_.])(?:eb[a@]?[y]|eb[e3]y|ebuy|0bay)(?:$|[-_.])", "ebay")
]

# Free and disposable web hosting providers frequently abused for credential phishing
DISPOSABLE_HOSTING_DOMAINS = {
    "000webhostapp.com", "beget.tech", "swtest.ru", "weebly.com",
    "wixsite.com", "firebaseapp.com", "web.app", "pages.dev",
    "glitch.me", "netlify.app", "surge.sh", "pastehtml.com"
}

# Common TLDs evaluated for subdomain masquerading / tunneling
EMBEDDED_TLD_CANDIDATES = {
    "com", "net", "org", "de", "uk", "ru", "cn", "fr", "it", "ca",
    "au", "jp", "br", "za", "ch", "se", "nl", "es", "info", "biz"
}

# Dangerous executable / dropper file extensions characteristic of malware delivery
MALWARE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".apk",
    ".msi", ".dll", ".bin", ".iso", ".hta", ".wsf", ".pif"
}

# Web defacement and web shell intrusion markers
DEFACEMENT_INDICATORS = [
    "/deface", "/hacked", "/root.html", "/bypassed", "/c99.php",
    "/r57.php", "/wso.php", "/shell.php"
]

DANGEROUS_SCHEMES = {"javascript", "data", "file", "ftp", "blob", "vbscript"}


def is_ip_address(host: str) -> bool:
    """Check if host string is a valid IPv4 or IPv6 address."""
    clean_host = host.strip("[]")  # Strip IPv6 enclosing brackets if present
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def is_legitimate_brand_domain(brand: str, reg_domain: str) -> bool:
    """Check if the given registered domain is genuinely affiliated with the brand."""
    legit_domains = MONITORED_BRANDS.get(brand, [])
    return reg_domain in legit_domains or any(reg_domain.endswith("." + ld) for ld in legit_domains)


def is_any_known_brand_domain(reg_domain: str) -> bool:
    """Check if the registered domain belongs to any monitored legitimate brand."""
    return any(is_legitimate_brand_domain(brand, reg_domain) for brand in MONITORED_BRANDS)


def extract_registered_domain(host: str) -> str:
    """
    Extract registered domain (domain + TLD) heuristically without external PSL dependency.
    Handles standard double TLDs (e.g. .co.uk, .com.au, .ac.uk, .gov.uk) and normal TLDs.
    """
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    
    double_tlds = {"co.uk", "com.au", "co.nz", "co.za", "com.br", "ac.uk", "gov.uk", "org.uk"}
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in double_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"
    
    return f"{parts[-2]}.{parts[-1]}"


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return - sum(p * math.log2(p) for p in prob)


def max_consonant_cluster(s: str) -> int:
    """Calculate the maximum consecutive non-vowel run (consonants and digits) in an alphanumeric string."""
    vowels = set("aeiouy")
    max_run = 0
    curr = 0
    for ch in s.lower():
        if ch.isalnum() and ch not in vowels:
            curr += 1
            if curr > max_run:
                max_run = curr
        else:
            curr = 0
    return max_run


def is_random_or_dga_label(label: str, subdomain_depth: int = 1) -> bool:
    """
    Detect algorithmically generated (DGA) or random gibberish labels.
    Requires sufficient length (>= 10 chars) and either extreme non-vowel clustering (>=6)
    or high Shannon entropy in multi-level subdomain structures (depth >= 2).
    """
    if len(label) < 10:
        return False
    non_vowels = max_consonant_cluster(label)
    # Extreme non-vowel sequences characteristic of DGA / random generation
    if non_vowels >= 6:
        return True
    # In multi-level subdomain hierarchies (e.g. signin.eby.de.<dga>.civpro.co.za),
    # DGA tokens feature non-vowel clusters >= 5 or elevated entropy >= 3.35
    if subdomain_depth >= 2:
        if non_vowels >= 5 or (shannon_entropy(label) >= 3.35 and "-" not in label):
            return True
    return False


def detect_subdomain_tld_masquerade(subdomain_labels: list[str]) -> tuple[bool, str | None]:
    """
    Detect if any subdomain label acts as an embedded TLD (e.g. eby.de or paypal.com inside subdomains).
    """
    for idx, label in enumerate(subdomain_labels):
        if label.lower() in EMBEDDED_TLD_CANDIDATES and idx > 0:
            simulated_domain = f"{subdomain_labels[idx-1]}.{label}"
            return True, simulated_domain
    return False, None


def analyze_url(raw_url: str) -> dict:
    """
    Performs deterministic, local static heuristic analysis on a submitted URL.
    Returns validation status, list of detected indicators, and parsed components.
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "is_valid": False,
            "error": "Empty or invalid URL provided.",
            "indicators": [],
            "parsed_components": {}
        }

    cleaned_url = raw_url.replace("\x00", "").strip()
    indicators = []

    # Check for dangerous scheme prefix directly (e.g. javascript:, data:, file:)
    scheme_match = re.match(r"^([a-zA-Z0-9+.-]+):", cleaned_url)
    if scheme_match:
        detected_scheme = scheme_match.group(1).lower()
        if detected_scheme in DANGEROUS_SCHEMES:
            indicators.append({
                "id": "URL_DANGEROUS_SCHEME",
                "category": "Protocol & Scheme",
                "severity": "CRITICAL",
                "title": f"Dangerous Scheme Detected ({detected_scheme}:)",
                "description": f"URL uses the dangerous '{detected_scheme}:' protocol handler which can execute client-side scripts, load local files, or inject data payloads.",
                "evidence": f"Scheme: {detected_scheme}",
                "recommendation": "Never open non-web protocol links from unverified sources."
            })
            return {
                "is_valid": False,
                "error": f"Unsupported or dangerous URL scheme: {detected_scheme}:",
                "indicators": indicators,
                "parsed_components": {"raw_url": cleaned_url, "scheme": detected_scheme}
            }

    # Normalize protocol if omitted
    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned_url))
    url_to_parse = cleaned_url if has_explicit_scheme else f"http://{cleaned_url}"

    try:
        parsed = urlparse(url_to_parse)
    except Exception as e:
        return {
            "is_valid": False,
            "error": f"URL parsing error: {str(e)}",
            "indicators": [{
                "id": "URL_MALFORMED",
                "category": "Format Analysis",
                "severity": "HIGH",
                "title": "Malformed URL Structure",
                "description": "The URL cannot be parsed into standard RFC 3986 components.",
                "evidence": str(e),
                "recommendation": "Avoid interacting with corrupt or malformed links."
            }],
            "parsed_components": {"raw_url": cleaned_url}
        }

    try:
        host = (parsed.hostname or "").lower()
    except (ValueError, AttributeError):
        host = (parsed.netloc.split(":")[0] if parsed.netloc else "").lower()

    try:
        port = parsed.port
    except ValueError:
        port = None
        indicators.append({
            "id": "URL_NON_STANDARD_PORT",
            "category": "Network & Architecture",
            "severity": "HIGH",
            "title": "Malformed or Non-Numeric Port in Authority",
            "description": "The URL specifies a corrupted or non-numeric port component in the network authority segment.",
            "evidence": "Invalid port string in authority",
            "recommendation": "Avoid interacting with links containing corrupted or non-standard port structures."
        })

    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    if not host:
        return {
            "is_valid": False,
            "error": "URL does not contain a valid host.",
            "indicators": [{
                "id": "URL_NO_HOST",
                "category": "Format Analysis",
                "severity": "HIGH",
                "title": "Missing or Invalid Host",
                "description": "No valid destination hostname could be extracted from the URL.",
                "evidence": cleaned_url,
                "recommendation": "Do not navigate to URLs lacking a valid domain or address."
            }],
            "parsed_components": {"raw_url": cleaned_url, "scheme": scheme}
        }

    # RULE 1: Scheme / Protocol Validation
    if has_explicit_scheme:
        if scheme not in ("http", "https"):
            indicators.append({
                "id": "URL_INVALID_SCHEME",
                "category": "Protocol & Scheme",
                "severity": "HIGH",
                "title": f"Non-Standard Web Scheme ({scheme})",
                "description": f"URL uses scheme '{scheme}' instead of standard HTTP or HTTPS.",
                "evidence": f"Scheme: {scheme}",
                "recommendation": "Verify whether this protocol is expected before opening."
            })
        elif scheme == "http":
            indicators.append({
                "id": "URL_HTTP_CLEARTEXT",
                "category": "Transport Security",
                "severity": "MEDIUM",
                "title": "Unencrypted HTTP Protocol",
                "description": "HTTP transmits data in cleartext. Note that while HTTPS encrypts transit, it does NOT guarantee the site is benign.",
                "evidence": "Protocol: http://",
                "recommendation": "Never enter credentials or sensitive information over cleartext HTTP connections."
            })
        elif scheme == "https":
            indicators.append({
                "id": "URL_HTTPS_PRESENT",
                "category": "Transport Security",
                "severity": "INFORMATIONAL",
                "title": "Encrypted HTTPS Transport",
                "description": "Connection uses HTTPS transport encryption. Note that modern phishing sites frequently acquire free TLS certificates; HTTPS alone does NOT verify site trustworthiness.",
                "evidence": "Protocol: https://",
                "recommendation": "Inspect domain spelling and legitimacy regardless of HTTPS padlock."
            })

    # RULE 2: Raw IP-Address Host
    if is_ip_address(host):
        indicators.append({
            "id": "URL_IP_HOST",
            "category": "Host & Domain",
            "severity": "CRITICAL",
            "title": "Raw IP Address Host",
            "description": "URL uses a raw IP address instead of a registered domain name. Threat actors frequently use IP addresses to bypass domain reputation blocklists and certificate authority controls.",
            "evidence": f"Host IP: {host}",
            "recommendation": "Do not interact with raw IP destinations requesting credentials or personal data."
        })

    # RULE 3: Userinfo Trickery (@ symbol in authority)
    netloc_authority = parsed.netloc or ""
    if "@" in netloc_authority:
        indicators.append({
            "id": "URL_USERINFO_TRICK",
            "category": "Host & Domain",
            "severity": "CRITICAL",
            "title": "UserInfo Redirection Trick (@ Symbol)",
            "description": "URL contains an '@' symbol in the authority segment. Standard browsers interpret everything preceding '@' as authentication userinfo and redirect the user to the host after '@'.",
            "evidence": f"Detected '@' in URL authority",
            "recommendation": "Treat any URL containing an '@' in the address portion as highly deceptive."
        })

    # RULE 4: URL Shortener Detection
    registered_domain = extract_registered_domain(host)
    if host in SHORTENER_DOMAINS or registered_domain in SHORTENER_DOMAINS:
        indicators.append({
            "id": "URL_SHORTENER",
            "category": "Evasion & Obfuscation",
            "severity": "HIGH",
            "title": "Known URL Shortener Service",
            "description": "URL shortening service detected. Shorteners obscure the true destination hostname, frequently hiding credential phishing pages and malicious redirects.",
            "evidence": f"Shortener domain: {host}",
            "recommendation": "Do not click shortened links in emails or messages without expanding and verifying the true target destination."
        })

    # RULE 4B: Disposable / Abused Free Web Hosting with Lure Subdomains
    if registered_domain in DISPOSABLE_HOSTING_DOMAINS:
        has_hosting_lure = any(kw in host for kw in AUTH_KEYWORDS) or registered_domain == "pastehtml.com"
        if has_hosting_lure:
            indicators.append({
                "id": "URL_DISPOSABLE_HOSTING_LURE",
                "category": "Evasion & Obfuscation",
                "severity": "HIGH",
                "title": f"Disposable Free Hosting Lure ({registered_domain})",
                "description": f"Destination utilizes disposable free hosting provider '{registered_domain}' with authentication/phishing lure indicators. Attackers frequently deploy ephemeral credential harvesters on free hosting platforms.",
                "evidence": f"Free hosting provider '{registered_domain}' hosting '{host}'",
                "recommendation": "Never provide credentials or sensitive data on free/disposable web hosting subdomains."
            })

    # RULE 5: Subdomain Depth Anomalies & Misleading Structures
    host_labels = [label for label in host.split(".") if label]
    reg_labels = [label for label in registered_domain.split(".") if label]
    subdomain_labels = host_labels[:-len(reg_labels)] if len(host_labels) > len(reg_labels) else []
    if len(subdomain_labels) > 3:
        indicators.append({
            "id": "URL_EXCESSIVE_SUBDOMAINS",
            "category": "Domain Structure",
            "severity": "MEDIUM",
            "title": f"Excessive Subdomain Depth ({len(subdomain_labels)} levels)",
            "description": "Domain contains unusually deep subdomain nesting, often structured to camouflage fraudulent hostnames or push the true apex domain off visible mobile address bars.",
            "evidence": f"Subdomain structure: {'.'.join(subdomain_labels)}",
            "recommendation": "Examine the rightmost portion of the domain to identify the true apex domain."
        })

    # Subdomain TLD Masquerading (e.g. signin.eby.de... or account.paypal.com...)
    has_masquerade, sim_domain = detect_subdomain_tld_masquerade(subdomain_labels)
    if has_masquerade:
        indicators.append({
            "id": "URL_SUBDOMAIN_TLD_MASQUERADE",
            "category": "Deceptive Naming",
            "severity": "HIGH",
            "title": f"Subdomain TLD Masquerade ({sim_domain})",
            "description": f"Subdomain hierarchy simulates a full domain/TLD structure ('{sim_domain}') inside the prefix of unrelated apex domain '{registered_domain}'. Attackers use embedded TLD labels to spoof familiar domains.",
            "evidence": f"Simulated destination '{sim_domain}' nested under '{registered_domain}'",
            "recommendation": "Inspect the domain right-to-left. Subdomain prefixes do not represent the hosting authority."
        })

    # Random / High-Entropy / DGA Subdomain Label Detection
    random_labels = [lbl for lbl in subdomain_labels if is_random_or_dga_label(lbl, len(subdomain_labels))]
    if random_labels:
        top_random = random_labels[0]
        indicators.append({
            "id": "URL_RANDOM_SUBDOMAIN_LABEL",
            "category": "Evasion & Obfuscation",
            "severity": "HIGH",
            "title": f"Random / High-Entropy Subdomain Label ({top_random})",
            "description": f"Subdomain contains pseudo-random / DGA-like string '{top_random}' (entropy {shannon_entropy(top_random):.2f}, {len(top_random)} chars). Random alphanumeric tokens in subdomains are frequently deployed in disposable phishing infrastructure.",
            "evidence": f"Pseudo-random label '{top_random}' in subdomain hierarchy",
            "recommendation": "Exercise caution. High-entropy subdomain strings are characteristic of automated phishing campaigns."
        })

    # Deceptive Authentication Keyword on Multi-Level Subdomains (Unaffiliated Domain)
    is_clean_brand = is_any_known_brand_domain(registered_domain)
    if not is_clean_brand:
        sub_auth_matches = [kw for kw in AUTH_KEYWORDS if any(kw in lbl.lower() for lbl in subdomain_labels)]
        # Flag when auth keywords appear in deep subdomains (>= 3 levels) or compound with masquerading/random labels
        if sub_auth_matches and (len(subdomain_labels) >= 3 or ((has_masquerade or bool(random_labels)) and len(subdomain_labels) >= 2)):
            indicators.append({
                "id": "URL_DECEPTIVE_SUBDOMAIN_LURE",
                "category": "Deceptive Naming",
                "severity": "HIGH",
                "title": f"Deceptive Subdomain Authentication Lure ({', '.join(sorted(sub_auth_matches)[:2])})",
                "description": f"Subdomain contains authentication keyword(s) ({', '.join(sorted(sub_auth_matches))}) structured across {len(subdomain_labels)} subdomain levels under an unaffiliated registered domain '{registered_domain}'.",
                "evidence": f"Auth lure in subdomains: '{'.'.join(subdomain_labels)}' on '{registered_domain}'",
                "recommendation": "Do not enter login credentials. Unaffiliated multi-level subdomains are commonly used to craft fake portal addresses."
            })

    # Check for brand impersonation in subdomains (e.g. paypal.com.account-verification.suspicious.net)
    subdomain_str = ".".join(subdomain_labels)
    for brand, legit_domains in MONITORED_BRANDS.items():
        if not is_legitimate_brand_domain(brand, registered_domain):
            # Check if subdomain embeds brand name or genuine domain name
            brand_in_sub = (brand in subdomain_str) or any(ld in subdomain_str for ld in legit_domains)
            if brand_in_sub:
                indicators.append({
                    "id": "URL_SUBDOMAIN_BRAND_IMPERSONATION",
                    "category": "Deceptive Naming",
                    "severity": "HIGH",
                    "title": f"Subdomain Brand Impersonation ({brand.capitalize()})",
                    "description": f"Domain embeds brand identifier '{brand}' into its subdomains while registered under unrelated apex domain '{registered_domain}'.",
                    "evidence": f"Subdomain '{subdomain_str}' mimics {brand} on host '{host}'",
                    "recommendation": f"Verify whether the destination matches the official {brand.capitalize()} website."
                })
                break

            # Check path segments for brand impersonation (e.g. /paypal.com/, /apple/signin.php)
            path_lower = path.lower()
            has_brand_domain_in_path = any(ld in path_lower for ld in legit_domains)
            has_brand_lure_in_path = False
            if not has_brand_domain_in_path and re.search(rf"/(?:{brand})(?:[-_.]|$|/)", path_lower):
                has_brand_lure_in_path = any(kw in path_lower for kw in AUTH_KEYWORDS)

            if has_brand_domain_in_path or has_brand_lure_in_path:
                if not any(ind["id"].endswith("BRAND_IMPERSONATION") for ind in indicators):
                    matched_target = next((ld for ld in legit_domains if ld in path_lower), brand)
                    indicators.append({
                        "id": "URL_PATH_BRAND_IMPERSONATION",
                        "category": "Deceptive Naming",
                        "severity": "HIGH",
                        "title": f"Path Brand Impersonation ({brand.capitalize()})",
                        "description": f"URL embeds official brand identifier or domain '{matched_target}' inside its path segment to masquerade as {brand.capitalize()} while hosted on an unrelated destination ({host}).",
                        "evidence": f"Path '{path}' embeds brand '{matched_target}' on host '{host}'",
                        "recommendation": f"Inspect the actual host/domain. Path segments do not represent the hosting authority."
                    })
                    break

    # RULE 6: Punycode & IDN Homograph Heuristics
    if "xn--" in host:
        indicators.append({
            "id": "URL_IDN_PUNYCODE",
            "category": "Evasion & Obfuscation",
            "severity": "MEDIUM",
            "title": "Punycode / Internationalized Domain (IDN)",
            "description": "Host utilizes Punycode ('xn--' prefix). Attackers exploit Internationalized Domain Names to execute homograph attacks, spoofing familiar ASCII characters with visually identical Cyrillic or Greek glyphs.",
            "evidence": f"Punycode host: {host}",
            "recommendation": "Inspect the resolved Unicode characters to confirm the domain is not impersonating another site."
        })

    # RULE 7: Typosquatting & Lookalike Heuristics
    # A: Regex substitution patterns on host
    for pattern, brand in TYPOSQUAT_PATTERNS:
        if re.search(pattern, host, re.IGNORECASE):
            # Check if apex domain is actually the genuine brand
            if not is_legitimate_brand_domain(brand, registered_domain):
                indicators.append({
                    "id": "URL_TYPOSQUATTING",
                    "category": "Deceptive Naming",
                    "severity": "HIGH",
                    "title": f"Typosquatting Lookalike Domain ({brand.capitalize()})",
                    "description": f"Hostname exhibits common character substitutions or misspellings resembling '{brand}'. Phishers register typosquatted domains to trick hurried users.",
                    "evidence": f"Suspicious host pattern on '{host}' mimicking {brand}",
                    "recommendation": "Carefully re-read the domain spelling character by character."
                })
                break

    # B: Hyphenated brand compounds (e.g. secure-login-apple.com, paypal-update.net)
    is_known_clean_brand = is_any_known_brand_domain(registered_domain)
    if not is_known_clean_brand:
        for brand in MONITORED_BRANDS.keys():
            # If brand is in host and combined with hyphen or keywords
            if brand in host:
                if re.search(rf"(^|[-_.])({brand})[-_.]|[-_.]{brand}($|[-_.])", host):
                    # Check if already flagged for typosquatting or subdomain brand impersonation
                    if not any(ind["id"] in ("URL_TYPOSQUATTING", "URL_SUBDOMAIN_BRAND_IMPERSONATION") for ind in indicators):
                        indicators.append({
                            "id": "URL_BRAND_COMPOUND",
                            "category": "Deceptive Naming",
                            "severity": "HIGH",
                            "title": f"Suspicious Brand Compound Domain ({brand.capitalize()})",
                            "description": f"Domain pairs recognizable trademark '{brand}' with secondary words or hyphens on an unaffiliated domain name.",
                            "evidence": f"Apex domain '{registered_domain}' contains brand token '{brand}'",
                            "recommendation": f"Navigate directly to {brand.capitalize()}'s official website using a saved bookmark."
                        })
                    break

    # RULE 8A: Deceptive Hostname / Authentication Keyword Compounding
    # Flag when multiple authentication / security lures compound on an unaffiliated hostname
    if not is_known_clean_brand:
        reg_tokens = [t for t in re.split(r"[-_.]", registered_domain.lower()) if t]
        matched_reg_kw = set()
        for token in reg_tokens:
            for kw in AUTH_KEYWORDS:
                if kw in token:
                    matched_reg_kw.add(kw)

        host_tokens = [t for t in re.split(r"[-_.]", host.lower()) if t]
        matched_host_kw = set()
        for token in host_tokens:
            for kw in AUTH_KEYWORDS:
                if kw in token:
                    matched_host_kw.add(kw)

        tld = host_labels[-1] if host_labels else ""
        if len(matched_reg_kw) >= 2:
            indicators.append({
                "id": "URL_DECEPTIVE_HOSTNAME_LURE",
                "category": "Deceptive Naming",
                "severity": "HIGH",
                "title": f"Deceptive Authentication Hostname ({', '.join(sorted(matched_reg_kw)[:3])})",
                "description": f"Registered domain name compounds multiple credential or security lure keywords ({', '.join(sorted(matched_reg_kw))}), a pattern characteristic of fraudulent harvesting portals.",
                "evidence": f"Deceptive registered domain tokens in '{registered_domain}'",
                "recommendation": "Do not enter credentials. Fraudulent domains frequently string together terms like 'secure', 'login', 'portal', and 'verify'."
            })
        elif len(matched_host_kw) >= 2 and len(subdomain_labels) > 0 and not any(ind["id"] in ("URL_SUBDOMAIN_BRAND_IMPERSONATION", "URL_BRAND_COMPOUND") for ind in indicators):
            indicators.append({
                "id": "URL_DECEPTIVE_HOSTNAME_LURE",
                "category": "Deceptive Naming",
                "severity": "HIGH",
                "title": f"Compounded Hostname Authentication Lures ({', '.join(sorted(matched_host_kw)[:3])})",
                "description": f"Hostname combines multiple security/login keyword tokens ({', '.join(sorted(host_kw_matches if 'host_kw_matches' in dir() else matched_host_kw))}) across subdomains and host.",
                "evidence": f"Host '{host}' strings together auth lures across domain structure",
                "recommendation": "Confirm whether this domain is an authorized corporate login portal."
            })
        elif len(matched_host_kw) >= 1 and tld in HIGH_RISK_TLDS and not any(ind["id"].startswith("URL_DECEPTIVE") for ind in indicators):
            indicators.append({
                "id": "URL_HIGH_RISK_TLD_AUTH",
                "category": "Deceptive Naming",
                "severity": "HIGH",
                "title": f"Suspicious TLD with Login Lure (.{tld})",
                "description": f"Domain couples high-risk TLD '.{tld}' with sensitive keyword tokens ({', '.join(sorted(matched_host_kw))}), commonly deployed for short-lived phishing campaigns.",
                "evidence": f"TLD '.{tld}' paired with tokens {', '.join(sorted(matched_host_kw))}",
                "recommendation": "Exercise extreme caution with free or disposable TLDs hosting authentication forms."
            })

    # RULE 8B: Sensitive / High-Risk Keywords in Path or Query
    # Do not treat a login keyword alone as proof of phishing if on a verified brand domain over HTTPS
    if not (is_known_clean_brand and scheme == "https"):
        full_path_and_query = f"{path}?{query}".lower()
        matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if re.search(rf"\b{kw}\b|[-_/]{kw}[-_/.]", full_path_and_query)]
        if matched_keywords:
            indicators.append({
                "id": "URL_SUSPICIOUS_KEYWORDS",
                "category": "Credential & Phishing Tokens",
                "severity": "MEDIUM",
                "title": f"Sensitive Authentication Keywords in Path ({', '.join(matched_keywords[:3])})",
                "description": f"URL path or query string contains sensitive keywords ({', '.join(matched_keywords)}) typical of credential harvesting and account verification scams.",
                "evidence": f"Matched tokens: {', '.join(matched_keywords)} in path/query",
                "recommendation": "Never provide login credentials or personal data after clicking an unsolicited link."
            })

            # RULE 8C: Unencrypted Cleartext Authentication Portal (CWE-319)
            STRICT_AUTH_SET = {
                "login", "signin", "logon", "sign-in", "log-in",
                "webscr", "authenticate", "credential", "password", "ebayisapi"
            }
            if has_explicit_scheme and scheme == "http" and any(re.search(rf"/(?:{kw})(?:[._/?&=-]|$)", full_path_and_query) for kw in STRICT_AUTH_SET):
                indicators.append({
                    "id": "URL_CLEARTEXT_AUTH_SUBMISSION",
                    "category": "Credential & Phishing Tokens",
                    "severity": "HIGH",
                    "title": "Unencrypted Cleartext Authentication Portal (HTTP)",
                    "description": "URL explicitly specifies unencrypted HTTP transport while targeting authentication or credential submission. Transmitting credentials in cleartext violates basic confidentiality (CWE-319) and is heavily abused by harvesting portals.",
                    "evidence": f"Cleartext http:// coupled with authentication resource in '{path}'",
                    "recommendation": "Never submit passwords or sensitive credentials over unencrypted HTTP connections."
                })

    # RULE 9: Heavy URL Percent-Encoding
    percent_encoded_tokens = re.findall(r"%[0-9a-fA-F]{2}", cleaned_url)
    if len(percent_encoded_tokens) >= 3 or ("%" in host):
        indicators.append({
            "id": "URL_SUSPICIOUS_ENCODING",
            "category": "Evasion & Obfuscation",
            "severity": "MEDIUM",
            "title": f"Suspicious URL Percent-Encoding ({len(percent_encoded_tokens)} instances)",
            "description": "Heavy percent-encoding detected. Attackers use excessive hexadecimal encoding to obfuscate target hostnames, evade keyword scanners, and confuse users.",
            "evidence": f"Encoded occurrences: {', '.join(percent_encoded_tokens[:4])}",
            "recommendation": "Review decoded URL parameters to ensure they do not mask malicious payloads."
        })

    # RULE 10: Non-Standard Web Ports
    if port is not None:
        standard_ports = {80, 443}
        if port not in standard_ports:
            indicators.append({
                "id": "URL_NON_STANDARD_PORT",
                "category": "Network & Architecture",
                "severity": "MEDIUM",
                "title": f"Non-Standard Port ({port})",
                "description": f"URL explicitly specifies port {port}. Standard legitimate public web portals operate on default ports 80 (HTTP) or 443 (HTTPS). Non-standard ports may bypass enterprise egress filtering.",
                "evidence": f"Custom port: :{port}",
                "recommendation": "Verify whether accessing this unusual service port is authorized by your network security policy."
            })

    # RULE 11: Direct Executable / Malware Payload Delivery
    path_lower = path.lower()
    full_pq = f"{path}?{query}".lower()
    matched_ext = next((ext for ext in MALWARE_EXTENSIONS if path_lower.endswith(ext) or (ext + "?") in full_pq or (ext + "#") in full_pq), None)
    if matched_ext:
        indicators.append({
            "id": "URL_MALWARE_EXECUTABLE_DOWNLOAD",
            "category": "Malware & Exploitation",
            "severity": "CRITICAL",
            "title": f"Direct Executable / Malware Dropper ({matched_ext})",
            "description": f"URL path terminates in executable or script extension '{matched_ext}'. Direct downloads of executable payloads over the web are characteristic of malware distribution and dropper links.",
            "evidence": f"File extension '{matched_ext}' in resource path",
            "recommendation": "Do not download or execute files from this link. Block payload at gateway perimeter."
        })

    # RULE 12: Web Defacement & Intrusion Shell Markers
    matched_deface = next((m for m in DEFACEMENT_INDICATORS if m in path_lower), None)
    if matched_deface or re.search(r"\.\./|\.\.\\", path):
        indicators.append({
            "id": "URL_DEFACEMENT_COMPROMISE",
            "category": "Malware & Exploitation",
            "severity": "CRITICAL",
            "title": "Web Defacement / Malicious Script Indicator",
            "description": "URL path contains signatures characteristic of website defacement, web shell insertion, or path traversal attacks.",
            "evidence": f"Intrusion marker '{matched_deface if matched_deface else 'path-traversal'}' in path",
            "recommendation": "Site exhibits evidence of security compromise or defacement. Do not browse or interact."
        })

    return {
        "is_valid": True,
        "indicators": indicators,
        "parsed_components": {
            "raw_url": cleaned_url,
            "scheme": scheme,
            "host": host,
            "registered_domain": registered_domain,
            "port": port,
            "path": path,
            "query": query,
            "subdomains": subdomain_labels
        }
    }
