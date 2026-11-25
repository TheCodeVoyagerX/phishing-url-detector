"""
Automated Test Suite for Phishing URL Detector
Tests feature extraction, synthetic generation, inference engine, and risk boundaries.
"""

import pytest
from src.feature_extractor import (
    calculate_entropy,
    extract_features,
    normalize_url,
    parse_domain_parts,
    analyze_threat_indicators,
)
from src.dataset_generator import generate_synthetic_samples
from src.predictor import PhishingDetector


def test_calculate_entropy():
    # Empty string should have 0 entropy
    assert calculate_entropy("") == 0.0
    # Homogeneous string has 0 entropy
    assert calculate_entropy("aaaaaaa") == 0.0
    # Randomized string should have higher entropy
    low_ent = calculate_entropy("google.com")
    high_ent = calculate_entropy("a8f9d0c2e3b1a4z7x6v5")
    assert high_ent > low_ent


def test_normalize_url():
    assert normalize_url("google.com").startswith("http://")
    assert normalize_url("https://secure.chase.com") == "https://secure.chase.com"


def test_parse_domain_parts():
    sub, main, tld = parse_domain_parts("login.paypal.com")
    assert sub == "login"
    assert main == "paypal"
    assert tld == "com"

    sub_uk, main_uk, tld_uk = parse_domain_parts("news.bbc.co.uk")
    assert main_uk == "bbc"
    assert tld_uk == "co.uk"


def test_extract_features_safe_url():
    url = "https://www.google.com/search?q=machine+learning"
    feats = extract_features(url)
    assert feats["is_ip"] == 0
    assert feats["is_https"] == 1
    assert feats["is_shortened"] == 0
    assert feats["brand_spoofing"] == 0
    assert feats["url_length"] > 10


def test_extract_features_phishing_url():
    # Brand spoofing inside deceptive domain
    url = "http://paypal.account-verify.xyz/login.php"
    feats = extract_features(url)
    assert feats["suspicious_tld"] == 1
    assert feats["brand_spoofing"] == 1
    assert feats["suspicious_keywords_count"] >= 1


def test_extract_features_ip_address():
    url = "http://192.168.1.50/banking/signin.html"
    feats = extract_features(url)
    assert feats["is_ip"] == 1
    assert feats["is_https"] == 0


def test_threat_indicators():
    url = "http://185.220.101.5/paypal/signin.html"
    indicators = analyze_threat_indicators(url)
    statuses = [i["status"] for i in indicators]
    assert "DANGER" in statuses


def test_synthetic_dataset_generation():
    df = generate_synthetic_samples(n_legit=50, n_phish=50)
    assert len(df) >= 100
    assert "url" in df.columns
    assert "label" in df.columns
    assert set(df["label"].unique()).issubset({0, 1})


def test_detector_inference():
    detector = PhishingDetector()
    
    # Test safe URL
    safe_res = detector.predict("https://www.wikipedia.org/")
    assert safe_res["is_phishing"] is False
    assert safe_res["risk_score"] < 50
    assert 0 <= safe_res["risk_score"] <= 100

    # Test blatant phishing URL
    phish_res = detector.predict("http://paypal.com.verification-center-update.xyz/login.php?token=fake")
    assert phish_res["is_phishing"] is True
    assert phish_res["risk_score"] >= 60
    assert 0 <= phish_res["risk_score"] <= 100
