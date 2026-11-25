"""
Automated Test Suite for Phishing URL Detector
Covers all test scenarios specified in the project requirements:
1. Legitimate URLs
2. Suspicious URLs
3. URLs containing IP addresses
4. URLs containing suspicious keywords
5. URLs using HTTP and HTTPS
6. Invalid URLs
7. Empty input
"""

import pytest
from detector import analyze_url, is_ip_address, validate_url, extract_subdomains


class TestURLValidation:
    """Tests input validation logic."""

    def test_empty_string(self):
        is_valid, msg = validate_url("")
        assert is_valid is False
        assert "empty" in msg.lower()

    def test_whitespace_only(self):
        is_valid, msg = validate_url("    ")
        assert is_valid is False
        assert "whitespace" in msg.lower() or "empty" in msg.lower()

    def test_url_with_spaces(self):
        is_valid, msg = validate_url("https://google .com/search")
        assert is_valid is False
        assert "spaces" in msg.lower()

    def test_valid_urls(self):
        assert validate_url("https://www.google.com")[0] is True
        assert validate_url("http://192.168.1.1/login")[0] is True
        assert validate_url("wikipedia.org/wiki/Python")[0] is True
        # URL with @ symbol in userinfo should pass parsing validation
        assert validate_url("http://google.com@evil-site.com/auth")[0] is True


class TestIPDetection:
    """Tests IP address identification."""

    def test_ipv4_detection(self):
        assert is_ip_address("192.168.1.1") is True
        assert is_ip_address("10.0.0.1:8080") is True
        assert is_ip_address("45.134.22.91") is True

    def test_domain_not_ip(self):
        assert is_ip_address("google.com") is False
        assert is_ip_address("paypal.verification.com") is False
        assert is_ip_address("amazon123.org") is False


class TestSubdomainExtraction:
    """Tests subdomain token parsing."""

    def test_single_subdomain(self):
        subs = extract_subdomains("mail.google.com")
        assert subs == ["mail"]

    def test_excessive_subdomains(self):
        subs = extract_subdomains("secure.login.verify.paypal.com")
        # Domain is paypal.com, subdomains are secure, login, verify
        assert len(subs) == 3
        assert subs == ["secure", "login", "verify"]

    def test_cctld_subdomains(self):
        subs = extract_subdomains("news.bbc.co.uk")
        assert subs == ["news"]


class TestRuleBasedDetectorScenarios:
    """Tests complete rule-based analysis across all required scenarios."""

    def test_scenario_empty_input(self):
        res = analyze_url("")
        assert res["is_valid"] is False
        assert res["risk_level"] == "INVALID"

    def test_scenario_invalid_url(self):
        res = analyze_url("not a valid url with spaces")
        assert res["is_valid"] is False
        assert res["risk_level"] == "INVALID"

    def test_scenario_legitimate_url_https(self):
        url = "https://www.wikipedia.org/wiki/Computer_science"
        res = analyze_url(url)
        assert res["is_valid"] is True
        assert res["risk_level"] == "LOW RISK"
        assert res["risk_score"] < 30
        assert res["badge_emoji"] == "🟢"

    def test_scenario_http_vs_https(self):
        # Plain HTTP adds 15 points
        res_http = analyze_url("http://example.com")
        res_https = analyze_url("https://example.com")
        assert res_http["risk_score"] > res_https["risk_score"]
        rule2_http = next(i for i in res_http["indicators"] if i["rule_id"] == 2)
        assert rule2_http["triggered"] is True

    def test_scenario_ip_address_url(self):
        url = "http://192.168.1.100/banking/login.php"
        res = analyze_url(url)
        assert res["is_valid"] is True
        rule3 = next(i for i in res["indicators"] if i["rule_id"] == 3)
        assert rule3["triggered"] is True
        assert rule3["score"] == 30
        assert res["risk_level"] == "HIGH RISK"

    def test_scenario_suspicious_keywords(self):
        url = "http://account-support-service.com/login-verification-password-reset"
        res = analyze_url(url)
        rule4 = next(i for i in res["indicators"] if i["rule_id"] == 4)
        assert rule4["triggered"] is True
        assert rule4["score"] >= 10

    def test_scenario_shortened_url(self):
        url = "http://bit.ly/secure-login-3921"
        res = analyze_url(url)
        rule5 = next(i for i in res["indicators"] if i["rule_id"] == 5)
        assert rule5["triggered"] is True
        assert rule5["score"] == 15

    def test_scenario_special_characters(self):
        # '@' symbol credential injection trick
        url = "http://google.com@malicious-attacker-host.top/auth.php"
        res = analyze_url(url)
        assert res["is_valid"] is True
        rule7 = next(i for i in res["indicators"] if i["rule_id"] == 7)
        assert rule7["triggered"] is True
        assert res["risk_level"] == "HIGH RISK"

    def test_scenario_high_risk_composite_phishing(self):
        url = "http://paypal.verification-account-security-update.xyz/login.php"
        res = analyze_url(url)
        assert res["is_valid"] is True
        assert res["risk_level"] == "HIGH RISK"
        assert res["risk_score"] >= 65
        assert res["badge_emoji"] == "🔴"


if __name__ == "__main__":
    pytest.main(["-v", "test_detector.py"])
