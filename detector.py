"""
Phishing URL Detector - Core Detection Engine
Author: Senior Python Developer & Cybersecurity Engineer
Description: Offline, rule-based phishing URL analysis using lexical and structural heuristics.
             Does NOT make network requests to target websites.
"""

import ipaddress
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# Well-known URL shortening services
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "su.pr", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "qr.ae", "v.gd", "clck.ru", "rb.gy"
}

# Suspicious / high-abuse top-level domains frequently abused by phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "fit", "surf", "gq", "tk", "ml",
    "cf", "ga", "buzz", "rest", "bar", "live", "icu", "cam", "quest",
    "monster", "tokyo", "download", "racing", "kim", "party", "science",
    "cricket", "faith", "club", "cfd", "online"
}

# Suspicious keywords frequently found in phishing paths, queries, and deceptive subdomains
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "banking", "secure",
    "security", "account", "wallet", "crypto", "confirm", "confirmation",
    "password", "validation", "authenticate", "billing", "invoice", "support",
    "recovery", "claim", "airdrop", "reward", "free", "bonus", "alert",
    "suspend", "suspended", "unlock", "re-activate", "authorise", "authorize",
    "auth", "logon", "access"
]


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validates user input to ensure it is a non-empty, parseable URL.
    Returns (is_valid, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "Input cannot be empty. Please enter a URL to inspect."

    cleaned_url = url.strip()
    if not cleaned_url:
        return False, "URL cannot consist only of whitespace characters."

    # URLs cannot contain internal spaces
    if " " in cleaned_url:
        return False, "Invalid URL: URLs cannot contain spaces."

    # Prepend scheme if missing for parsing check
    test_url = cleaned_url if cleaned_url.startswith(("http://", "https://")) else "http://" + cleaned_url

    try:
        parsed = urlparse(test_url)
        # Netloc or host must exist
        if not parsed.netloc:
            return False, "Invalid URL structure: Unable to extract domain or host name."
            
        # Check for illegal characters according to standard URI specifications
        illegal_chars = {'\r', '\n', '\t', '<', '>', '"', '\\', '^', '`', '{', '|', '}'}
        if any(c in parsed.netloc for c in illegal_chars):
            return False, "Invalid URL: Domain contains forbidden characters."
    except Exception as e:
        return False, f"URL parsing error: {str(e)}"

    return True, ""


def is_ip_address(hostname: str) -> bool:
    """
    Checks if hostname is an IPv4 or IPv6 address.
    Uses Python standard library `ipaddress`.
    """
    if not hostname:
        return False
    # Strip port if present
    host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_subdomains(hostname: str) -> List[str]:
    """
    Extracts subdomain tokens from hostname.
    Handles standard ccTLDs (e.g., .co.uk, .com.au) properly.
    """
    if not hostname:
        return []
        
    host = hostname.split(":")[0].lower()
    if is_ip_address(host):
        return []

    parts = host.split(".")
    if len(parts) <= 2:
        return []

    # Check for two-part country TLDs (e.g. .co.uk, .com.br)
    cctlds = {"uk", "au", "br", "in", "nz", "za", "ca", "mx", "sg"}
    second_levels = {"co", "com", "org", "gov", "net", "edu", "ac"}
    if len(parts) >= 3 and parts[-1] in cctlds and parts[-2] in second_levels:
        # e.g., ['sub2', 'sub1', 'domain', 'co', 'uk'] -> subdomains are parts[:-3]
        return parts[:-3]
    else:
        # e.g., ['sub2', 'sub1', 'domain', 'com'] -> subdomains are parts[:-2]
        return parts[:-2]


def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive offline rule-based phishing analysis on a given URL.
    Returns detailed scoring, risk level, and breakdown of all 8 core rules.
    """
    # 1. Validation check
    is_valid, error_msg = validate_url(raw_url)
    if not is_valid:
        return {
            "is_valid": False,
            "error_message": error_msg,
            "raw_url": raw_url,
            "risk_score": 0,
            "risk_level": "INVALID",
            "indicators": [],
            "analysis_summary": error_msg
        }

    raw_url = raw_url.strip()
    # Normalize scheme for parsing
    normalized_url = raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url
    parsed = urlparse(normalized_url)

    # Use parsed.hostname if available (correctly extracts host when userinfo@ is present)
    hostname = (parsed.hostname or parsed.netloc.split("@")[-1] or "").split(":")[0].lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = raw_url.lower()

    indicators: List[Dict[str, Any]] = []
    total_score = 0

    # -------------------------------------------------------------
    # RULE 1: URL Length Detection
    # -------------------------------------------------------------
    url_length = len(raw_url)
    if url_length > 75:
        rule1_triggered = True
        rule1_points = 15
        rule1_details = f"URL length is abnormally long ({url_length} characters). Phishing sites use long URLs to conceal fake tokens and deceive users."
    elif url_length > 54:
        rule1_triggered = True
        rule1_points = 8
        rule1_details = f"URL length is moderately long ({url_length} characters)."
    else:
        rule1_triggered = False
        rule1_points = 0
        rule1_details = f"Standard concise URL length ({url_length} characters)."

    total_score += rule1_points
    indicators.append({
        "rule_id": 1,
        "name": "URL Length Detection",
        "triggered": rule1_triggered,
        "score": rule1_points,
        "max_score": 15,
        "details": rule1_details
    })

    # -------------------------------------------------------------
    # RULE 2: HTTPS Protocol Detection
    # -------------------------------------------------------------
    has_https = parsed.scheme.lower() == "https"
    if not has_https:
        rule2_triggered = True
        rule2_points = 15
        rule2_details = "Insecure HTTP protocol detected. Legitimate modern services use encrypted HTTPS communication."
    else:
        rule2_triggered = False
        rule2_points = 0
        rule2_details = "Secure HTTPS protocol detected."

    total_score += rule2_points
    indicators.append({
        "rule_id": 2,
        "name": "HTTPS Protocol Detection",
        "triggered": rule2_triggered,
        "score": rule2_points,
        "max_score": 15,
        "details": rule2_details
    })

    # -------------------------------------------------------------
    # RULE 3: IP Address-Based URL Detection
    # -------------------------------------------------------------
    has_ip = is_ip_address(hostname)
    if has_ip:
        rule3_triggered = True
        rule3_points = 30
        rule3_details = f"Raw IP address ({hostname}) used instead of a registered domain. Attackers use direct IPs to evade domain name registration and DNS blacklists."
    else:
        rule3_triggered = False
        rule3_points = 0
        rule3_details = f"Hostname uses a registered domain name format ({hostname})."

    total_score += rule3_points
    indicators.append({
        "rule_id": 3,
        "name": "IP Address-Based URL Detection",
        "triggered": rule3_triggered,
        "score": rule3_points,
        "max_score": 30,
        "details": rule3_details
    })

    # -------------------------------------------------------------
    # RULE 4: Suspicious Keyword Detection
    # -------------------------------------------------------------
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if len(matched_keywords) >= 2:
        rule4_triggered = True
        rule4_points = 20
        rule4_details = f"Multiple sensitive action keywords detected ({', '.join(matched_keywords[:4])}). Commonly used in credential-harvesting attacks."
    elif len(matched_keywords) == 1:
        rule4_triggered = True
        rule4_points = 10
        rule4_details = f"Sensitive keyword detected: '{matched_keywords[0]}'."
    else:
        rule4_triggered = False
        rule4_points = 0
        rule4_details = "No suspicious action keywords found in URL string."

    total_score += rule4_points
    indicators.append({
        "rule_id": 4,
        "name": "Suspicious Keyword Detection",
        "triggered": rule4_triggered,
        "score": rule4_points,
        "max_score": 20,
        "details": rule4_details
    })

    # -------------------------------------------------------------
    # RULE 5: URL Shortening Service Detection
    # -------------------------------------------------------------
    is_shortened = hostname in KNOWN_SHORTENERS
    if is_shortened:
        rule5_triggered = True
        rule5_points = 15
        rule5_details = f"Known URL shortening domain detected ({hostname}). Shorteners hide the true destination URL from the user."
    else:
        rule5_triggered = False
        rule5_points = 0
        rule5_details = "URL does not appear to use a standard URL shortener service."

    total_score += rule5_points
    indicators.append({
        "rule_id": 5,
        "name": "URL Shortening Service Detection",
        "triggered": rule5_triggered,
        "score": rule5_points,
        "max_score": 15,
        "details": rule5_details
    })

    # -------------------------------------------------------------
    # RULE 6: Excessive Subdomain Detection
    # -------------------------------------------------------------
    subdomain_list = extract_subdomains(hostname)
    subdomain_count = len(subdomain_list)
    if subdomain_count >= 3:
        rule6_triggered = True
        rule6_points = 15
        rule6_details = f"Excessive subdomains detected ({subdomain_count} levels: {'.'.join(subdomain_list)}). Attackers chain subdomains to mimic trusted brand names."
    elif subdomain_count == 2:
        rule6_triggered = True
        rule6_points = 8
        rule6_details = f"Multiple subdomains detected ({subdomain_count} levels: {'.'.join(subdomain_list)})."
    else:
        rule6_triggered = False
        rule6_points = 0
        rule6_details = f"Normal subdomain structure ({subdomain_count} subdomain levels)."

    total_score += rule6_points
    indicators.append({
        "rule_id": 6,
        "name": "Excessive Subdomain Detection",
        "triggered": rule6_triggered,
        "score": rule6_points,
        "max_score": 15,
        "details": rule6_details
    })

    # -------------------------------------------------------------
    # RULE 7: Special Character Detection (@, -, // in path)
    # -------------------------------------------------------------
    has_at_symbol = "@" in raw_url
    hyphen_count_domain = hostname.count("-")
    has_double_slash_path = "//" in path

    special_char_issues = []
    rule7_score = 0

    if has_at_symbol:
        rule7_score += 20
        special_char_issues.append("'@' symbol found (used to trick browsers into ignoring leading credentials)")
    if hyphen_count_domain >= 2:
        rule7_score += 10
        special_char_issues.append(f"{hyphen_count_domain} hyphens in domain name (often used to simulate brand names)")
    if has_double_slash_path:
        rule7_score += 10
        special_char_issues.append("'//' found inside URL path (can trigger unexpected redirection)")

    rule7_points = min(rule7_score, 30)
    rule7_triggered = len(special_char_issues) > 0

    if rule7_triggered:
        rule7_details = f"Special character anomalies detected: {'; '.join(special_char_issues)}."
    else:
        rule7_details = "No deceptive special characters (@, excessive hyphens, or path redirects) detected."

    total_score += rule7_points
    indicators.append({
        "rule_id": 7,
        "name": "Special Character Detection (@, -, //)",
        "triggered": rule7_triggered,
        "score": rule7_points,
        "max_score": 30,
        "details": rule7_details
    })

    # -------------------------------------------------------------
    # RULE 8: Suspicious Domain Pattern Detection
    # -------------------------------------------------------------
    tld = hostname.split(".")[-1] if "." in hostname and not has_ip else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    has_punycode = "xn--" in hostname
    has_hex_encoding = "%" in raw_url

    pattern_issues = []
    rule8_score = 0

    if is_suspicious_tld:
        rule8_score += 15
        pattern_issues.append(f"High-abuse top-level domain (.{tld}) with frequent spam/phishing association")
    if has_punycode:
        rule8_score += 10
        pattern_issues.append("Punycode / IDN homograph pattern ('xn--') detected")
    if has_hex_encoding:
        rule8_score += 5
        pattern_issues.append("Hex/URL percentage encoding (%xx) detected")

    rule8_points = min(rule8_score, 25)
    rule8_triggered = len(pattern_issues) > 0

    if rule8_triggered:
        rule8_details = f"Suspicious domain patterns detected: {'; '.join(pattern_issues)}."
    else:
        rule8_details = f"Standard domain naming pattern with recognized TLD (.{tld if tld else 'standard'})."

    total_score += rule8_points
    indicators.append({
        "rule_id": 8,
        "name": "Suspicious Domain Pattern Detection",
        "triggered": rule8_triggered,
        "score": rule8_points,
        "max_score": 25,
        "details": rule8_details
    })

    # -------------------------------------------------------------
    # Calculate Final Risk Level
    # -------------------------------------------------------------
    # Cap total score at 100
    final_score = min(total_score, 100)

    if final_score < 30:
        risk_level = "LOW RISK"
        risk_color = "#22c55e"  # Cyber Green
        badge_emoji = "🟢"
        analysis_summary = (
            "No major suspicious indicators detected. The URL follows standard conventions with a valid structure. "
            "However, always stay vigilant and verify the domain name spelling before entering credentials."
        )
    elif final_score < 65:
        risk_level = "MEDIUM RISK"
        risk_color = "#f59e0b"  # Amber / Warning Yellow
        badge_emoji = "🟡"
        analysis_summary = (
            "Some suspicious characteristics detected. This URL has traits such as missing HTTPS, sensitive keywords, "
            "or unusual length. Proceed with caution and do not submit passwords or financial information."
        )
    else:
        risk_level = "HIGH RISK"
        risk_color = "#ef4444"  # Red / Threat Crimson
        badge_emoji = "🔴"
        analysis_summary = (
            "Multiple suspicious indicators detected! This URL exhibits significant phishing patterns such as direct IP hosting, "
            "deceptive special characters, abusive TLDs, or multiple credential-harvesting keywords. Avoid visiting this link."
        )

    # Discretionary advisory reminder
    disclaimer = (
        "Educational Notice: This tool uses heuristic rule-based detection for academic and awareness purposes. "
        "Do not claim or assume that a URL is 100% safe or malicious based only on these rules."
    )

    return {
        "is_valid": True,
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "hostname": hostname,
        "path": path,
        "query": query,
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "badge_emoji": badge_emoji,
        "indicators": indicators,
        "analysis_summary": analysis_summary,
        "disclaimer": disclaimer,
        "triggered_count": sum(1 for ind in indicators if ind["triggered"]),
        "total_rules": len(indicators)
    }
