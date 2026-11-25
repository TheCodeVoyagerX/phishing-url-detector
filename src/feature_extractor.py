"""
Feature Extraction Engine for Phishing URL Detection
Extracts lexical, structural, statistical, and security-heuristic features from URLs.
"""

import math
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# Well-known URL shortening domains
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "su.pr", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "qr.ae", "v.gd", "clck.ru", "rb.gy"
}

# Suspicious / high-abuse top-level domains frequently observed in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "fit", "surf", "gq", "tk", "ml", "cf",
    "ga", "buzz", "rest", "bar", "live", "icu", "cam", "quest", "agency", "monster",
    "tokyo", "download", "racing", "kim", "party", "science", "cricket", "faith"
}

# High-profile brands frequently targeted by phishing campaigns
TARGETED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "twitter", "binance", "coinbase", "metamask", "chase", "wellsfargo",
    "bankofamerica", "steam", "roblox", "discord", "telegram", "whatsapp", "ebay",
    "citibank", "spotify", "linkedin", "dropbox", "ledger", "trezor", "stellar"
]

# Suspicious keywords commonly seen in credential harvesting & phishing paths/subdomains
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "banking", "secure",
    "security", "account", "wallet", "crypto", "confirm", "confirmation",
    "password", "validation", "authenticate", "billing", "invoice", "support",
    "recovery", "claim", "airdrop", "reward", "free", "gift", "bonus", "alert",
    "suspend", "unlock", "re-activate", "portal", "authorise", "authorize"
]

# IPv4 regex pattern
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def normalize_url(url: str) -> str:
    """Normalizes URL by stripping whitespace and ensuring scheme exists for parsing."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def parse_domain_parts(hostname: str) -> Tuple[str, str, str]:
    """
    Splits hostname into (subdomain, main_domain, tld).
    Works with both standard domains and IP addresses.
    """
    if not hostname:
        return "", "", ""
    
    # Strip port if present
    hostname = hostname.split(":")[0].lower()
    
    # If hostname is IP address
    if IPV4_PATTERN.match(hostname):
        return "", hostname, ""
    
    parts = hostname.split(".")
    if len(parts) <= 1:
        return "", hostname, ""
    elif len(parts) == 2:
        return "", parts[0], parts[1]
    else:
        # e.g., ['sub2', 'sub1', 'domain', 'com'] or ['co', 'uk']
        # Simple heuristic for ccTLDs like .co.uk, .com.au
        if len(parts) >= 3 and parts[-1] in {"uk", "au", "br", "in", "nz", "za"} and parts[-2] in {"co", "com", "org", "gov", "net", "edu"}:
            tld = f"{parts[-2]}.{parts[-1]}"
            main_domain = parts[-3]
            subdomain = ".".join(parts[:-3])
        else:
            tld = parts[-1]
            main_domain = parts[-2]
            subdomain = ".".join(parts[:-2])
        return subdomain, main_domain, tld


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts all numerical and boolean features from a raw URL.
    Returns a dictionary of feature_name -> numerical_value.
    """
    norm_url = normalize_url(raw_url)
    parsed = urlparse(norm_url)
    
    hostname = (parsed.netloc or "").split(":")[0].lower()
    path = parsed.path or ""
    query = parsed.query or ""
    raw_lower = raw_url.lower()
    
    subdomain, main_domain, tld = parse_domain_parts(hostname)
    
    # 1. Length features
    url_length = len(raw_url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    
    # 2. Character counts in URL
    num_dots = raw_url.count(".")
    num_dots_hostname = hostname.count(".")
    num_hyphens = raw_url.count("-")
    num_hyphens_hostname = hostname.count("-")
    num_underscores = raw_url.count("_")
    num_slashes = raw_url.count("/")
    num_question_marks = raw_url.count("?")
    num_equal_signs = raw_url.count("=")
    num_at_symbols = raw_url.count("@")
    num_ampersands = raw_url.count("&")
    num_exclamations = raw_url.count("!")
    num_tilde = raw_url.count("~")
    num_percent = raw_url.count("%")
    
    # 3. Digit and Letter metrics
    num_digits = sum(c.isdigit() for c in raw_url)
    num_letters = sum(c.isalpha() for c in raw_url)
    num_digits_hostname = sum(c.isdigit() for c in hostname)
    
    digit_letter_ratio = round(num_digits / (num_letters + 1e-5), 4)
    hostname_digit_ratio = round(num_digits_hostname / (len(hostname) + 1e-5), 4)
    
    # 4. Host & Structure Checks
    is_ip = 1 if IPV4_PATTERN.match(hostname) else 0
    is_shortened = 1 if hostname in KNOWN_SHORTENERS else 0
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    subdomain_count = len(subdomain_parts)
    is_https = 1 if parsed.scheme == "https" else 0
    has_port = 1 if parsed.port and parsed.port not in (80, 443) else 0
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    punycode = 1 if "xn--" in hostname else 0
    
    # 5. Content & Brand Spoofing Checks
    # Brand appearing in subdomain or path while NOT being the main domain
    brand_in_subdomain_or_path = 0
    for brand in TARGETED_BRANDS:
        if (brand in subdomain or brand in path) and brand != main_domain:
            brand_in_subdomain_or_path = 1
            break
            
    # Suspicious keywords
    keywords_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in raw_lower)
    
    # Double slash in path (redirect tricks)
    has_double_slash_path = 1 if "//" in path else 0
    
    # Shannon Entropy
    entropy_url = calculate_entropy(raw_url)
    entropy_hostname = calculate_entropy(hostname)
    
    # Consecutive character repetition check
    max_consecutive_repeat = 1
    current_repeat = 1
    for i in range(1, len(raw_url)):
        if raw_url[i] == raw_url[i - 1]:
            current_repeat += 1
            max_consecutive_repeat = max(max_consecutive_repeat, current_repeat)
        else:
            current_repeat = 1

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "num_dots": num_dots,
        "num_dots_hostname": num_dots_hostname,
        "num_hyphens": num_hyphens,
        "num_hyphens_hostname": num_hyphens_hostname,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_question_marks": num_question_marks,
        "num_equal_signs": num_equal_signs,
        "num_at_symbols": num_at_symbols,
        "num_ampersands": num_ampersands,
        "num_exclamations": num_exclamations,
        "num_tilde": num_tilde,
        "num_percent": num_percent,
        "num_digits": num_digits,
        "num_digits_hostname": num_digits_hostname,
        "digit_letter_ratio": digit_letter_ratio,
        "hostname_digit_ratio": hostname_digit_ratio,
        "is_ip": is_ip,
        "is_shortened": is_shortened,
        "subdomain_count": subdomain_count,
        "is_https": is_https,
        "has_port": has_port,
        "suspicious_tld": suspicious_tld,
        "punycode": punycode,
        "brand_spoofing": brand_in_subdomain_or_path,
        "suspicious_keywords_count": keywords_count,
        "has_double_slash_path": has_double_slash_path,
        "entropy_url": entropy_url,
        "entropy_hostname": entropy_hostname,
        "max_consecutive_repeat": max_consecutive_repeat,
    }


def analyze_threat_indicators(raw_url: str) -> List[Dict[str, Any]]:
    """
    Returns a human-readable list of security indicators with severity level,
    explanation, and status (SAFE, WARNING, DANGER).
    """
    features = extract_features(raw_url)
    norm_url = normalize_url(raw_url)
    parsed = urlparse(norm_url)
    hostname = (parsed.netloc or "").split(":")[0].lower()
    subdomain, main_domain, tld = parse_domain_parts(hostname)
    
    indicators = []
    
    # 1. IP Hostname Check
    if features["is_ip"] == 1:
        indicators.append({
            "name": "Direct IP Address Hostname",
            "status": "DANGER",
            "severity": "High",
            "description": f"URL uses raw IP address ({hostname}) instead of a trusted domain name. Typical of illicit hostings.",
        })
    else:
        indicators.append({
            "name": "Domain Hostname Validation",
            "status": "SAFE",
            "severity": "Low",
            "description": f"Valid domain structure detected ({hostname}).",
        })

    # 2. Brand Spoofing Check
    if features["brand_spoofing"] == 1:
        matched_brand = next((b for b in TARGETED_BRANDS if (b in subdomain or b in (parsed.path or "").lower()) and b != main_domain), "Target Brand")
        indicators.append({
            "name": "Target Brand Spoofing Detected",
            "status": "DANGER",
            "severity": "Critical",
            "description": f"Brand name '{matched_brand}' appears in subdomain/path while the actual domain is '{main_domain}'. Deceptive credential-stealing tactic.",
        })

    # 3. URL Shortener Check
    if features["is_shortened"] == 1:
        indicators.append({
            "name": "URL Shortener Detected",
            "status": "WARNING",
            "severity": "Medium",
            "description": f"Uses shortening service ({hostname}), masking the true final destination.",
        })

    # 4. HTTPS Security
    if features["is_https"] == 1:
        indicators.append({
            "name": "HTTPS Encryption Protocol",
            "status": "SAFE",
            "severity": "Low",
            "description": "Secure HTTPS communication protocol is in use.",
        })
    else:
        indicators.append({
            "name": "Unencrypted HTTP Protocol",
            "status": "WARNING",
            "severity": "Medium",
            "description": "Plaintext HTTP connection; vulnerable to eavesdropping and interception.",
        })

    # 5. Suspicious TLD
    if features["suspicious_tld"] == 1:
        indicators.append({
            "name": f"High-Abuse Top-Level Domain (.{tld})",
            "status": "WARNING",
            "severity": "Medium",
            "description": f"The top-level domain '.{tld}' has a statistically elevated association with spam and phishing.",
        })

    # 6. Embedded '@' symbol
    if features["num_at_symbols"] > 0:
        indicators.append({
            "name": "Embedded '@' Symbol in URL",
            "status": "DANGER",
            "severity": "High",
            "description": "Contains '@' symbol, which ignores preceding characters in browsers to spoof user perception.",
        })

    # 7. Subdomain Depth
    if features["subdomain_count"] >= 3:
        indicators.append({
            "name": "Excessive Subdomain Nesting",
            "status": "WARNING",
            "severity": "Medium",
            "description": f"{features['subdomain_count']} subdomains detected. Phishing sites frequently chain subdomains.",
        })

    # 8. Suspicious Keywords
    if features["suspicious_keywords_count"] >= 2:
        found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in raw_url.lower()]
        indicators.append({
            "name": "Multiple Sensitive Action Keywords",
            "status": "WARNING",
            "severity": "Medium",
            "description": f"Contains security/credential terms: {', '.join(found_kw[:4])}.",
        })

    # 9. Shannon Entropy
    if features["entropy_hostname"] > 3.8:
        indicators.append({
            "name": "Elevated Hostname Entropy",
            "status": "WARNING",
            "severity": "Medium",
            "description": f"Hostname entropy ({features['entropy_hostname']:.2f}) indicates potential algorithmically generated domain (DGA).",
        })

    # 10. URL Length
    if features["url_length"] > 75:
        indicators.append({
            "name": "Abnormally Long URL",
            "status": "WARNING",
            "severity": "Low",
            "description": f"URL length ({features['url_length']} chars) exceeds standard conventions, often used to conceal payloads.",
        })

    return indicators
