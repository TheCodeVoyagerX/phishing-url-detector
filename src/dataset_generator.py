"""
Curated Dataset Generator for Phishing URL Detection
Generates a diverse, realistic, and balanced dataset of verified legitimate and phishing URLs.
"""

import os
import random
from typing import List, Tuple
import pandas as pd

# High-trust legitimate domains and realistic safe URL templates
LEGITIMATE_BASE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "yahoo.com", "reddit.com", "netflix.com", "linkedin.com", "microsoft.com",
    "instagram.com", "twitter.com", "apple.com", "github.com", "stackoverflow.com",
    "medium.com", "cloudflare.com", "dropbox.com", "spotify.com", "paypal.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "cnn.com", "bbc.co.uk",
    "nytimes.com", "theguardian.com", "forbes.com", "bloomberg.com", "reuters.com",
    "nih.gov", "nasa.gov", "mit.edu", "stanford.edu", "harvard.edu",
    "mozilla.org", "python.org", "docker.com", "kubernetes.io", "gitlab.com",
    "npmjs.com", "pypi.org", "w3schools.com", "developer.mozilla.org", "archive.org",
    "openai.com", "anthropic.com", "zoom.us", "slack.com", "atlassian.com"
]

LEGITIMATE_PATHS = [
    "",
    "search?q=machine+learning+tutorial",
    "articles/2026/03/technology-advancements",
    "explore/topics/artificial-intelligence",
    "user/profile/settings",
    "docs/v2/getting-started/overview",
    "products/category/electronics/item-49281",
    "help/support/faqs/payment-methods",
    "news/latest-releases-update-march",
    "download/desktop-client/windows-x64",
    "en/about-us/leadership-team",
    "resources/whitepapers/cybersecurity-best-practices.pdf",
    "contact-us/feedback-form",
    "pricing/plans/enterprise-tier",
    "api/v1/healthcheck?token=public",
    "terms-of-service/privacy-policy",
    "community/forum/discussion/topic-1823",
    "research/publication/paper-analysis-2026",
    "blog/engineering/scaling-high-throughput-systems",
    "dashboard/analytics/overview?range=30d"
]

# Phishing templates replicating real-world attacks:
# 1. Brand in subdomain / deceptive subdomains
# 2. IP hostnames
# 3. Phishing keywords combined with suspicious TLDs
# 4. Homograph / typo-squatting
# 5. Long obfuscated query parameters & hex encoding

PHISHING_PATTERNS = [
    # Brand spoofing in subdomain
    "http://paypal.verification-account-security-update.xyz/login.php",
    "https://appleid.apple.com.verify-device-portal.top/account/auth",
    "http://login.microsoftonline.security-token-renewal.work/office365",
    "http://netflix.account-billing-declined-update.click/signin",
    "http://amazon.orders-verification-support-center.xyz/ref=auth_req",
    "http://secure.chase.bank-alert-resolution.info/customer/auth",
    "http://metamask.wallet-airdrop-claim-rewards.buzz/connect-wallet",
    "http://binance.security-anti-phishing-code-auth.top/user/login",
    "http://coinbase.pro-account-freeze-warning.xyz/kyc-verification",
    "http://wellsfargo.signon-session-expired-confirm.club/ebs/auth",
    "http://bankofamerica.online-id-locked-unlock.tk/portal",
    "http://steamcommunity.trade-offers-inventory-gift.xyz/trade/id=93821",
    "http://discord.nitro-gift-free-claim-3months.click/redeem",
    "http://facebook.security-checkpoint-appeal-case9482.top/checkpoint",
    "http://instagram.copyright-infringement-appeal-form.xyz/login",
    "http://whatsapp.web-qr-code-verification-update.click/sync",
    "http://google.account-security-threat-detected.support-services.xyz/recovery",
    "http://dropbox.shared-document-invoice-viewer.cam/doc/view.html",
    "http://linkedin.career-opportunity-candidate-view.monster/login",
    "http://stellar.lumen-free-airdrop-claim-now.xyz/wallet/connect",
    
    # Direct IP addresses with sensitive paths
    "http://192.168.1.105/paypal/signin.html?session=4892",
    "http://185.220.101.5/banking/secure-login/auth.php",
    "http://45.134.22.91/apple/icloud-unlock/verify",
    "http://103.251.167.20/chase-online/logon.jsp",
    "http://91.241.19.84/amazon-update/payment-billing.html",
    "http://194.36.177.10/metamask-vault/restore-seed-phrase",
    "http://195.123.245.88:8080/bank/verification/process",
    "http://178.62.204.11/secure-update/account-recovery",
    
    # URL shorteners / deceptive redirect patterns
    "http://bit.ly/3xSecUr3L0g1nPaypa1",
    "http://tinyurl.com/bank-security-urgent-notice-2026",
    "http://is.gd/chase_verification_alert_code",
    "http://cutt.ly/apple-id-suspended-unfreeze",
    "http://rb.gy/metamask-claim-airdrop-free",
    
    # Long hex-encoded or symbol-heavy URLs
    "http://secure-login-portal-auth.xyz/confirm?user=admin&token=%20%2e%2e%2f%2fauth&action=validate&redirect=evil.com",
    "http://account-recovery-system-alert.top/verify.php?token=9f82d1c7a8b3&email=user%40target.com&source=automated",
    "http://update-wallet-credentials-instant.click/app/?ref=telegram&auth_hash=0x8391bcfe238910&claim=free",
    "http://customer-support-center-ticket99.work/login.aspx?dest=portal&session_id=892374829374829374&return_url=verify",
    
    # DGA (Domain Generation Algorithm) randomized phishing domains
    "http://x82910kdjsla92837.xyz/account/login",
    "http://w93821ndjksla.click/verify-billing-info",
    "http://q9a8z7x6c5v4.top/banking/secure",
    "http://m92831ksalqp.work/signin?id=9382",
    "http://k8392ldmzaq1.club/update-information"
]


def generate_synthetic_samples(n_legit: int = 1200, n_phish: int = 1200) -> pd.DataFrame:
    """
    Generates a balanced dataset of legitimate and phishing URLs.
    Includes deterministic seeds for reproducibility.
    """
    random.seed(42)
    urls: List[str] = []
    labels: List[int] = []  # 0 for Legitimate, 1 for Phishing

    # --- Generate Legitimate URLs ---
    # 1. Base root URLs
    for domain in LEGITIMATE_BASE_DOMAINS:
        urls.append(f"https://www.{domain}/")
        labels.append(0)
        urls.append(f"https://{domain}/")
        labels.append(0)

    # 2. Domain + standard paths
    while len([l for l in labels if l == 0]) < n_legit:
        domain = random.choice(LEGITIMATE_BASE_DOMAINS)
        path = random.choice(LEGITIMATE_PATHS)
        scheme = random.choices(["https://", "http://"], weights=[0.95, 0.05])[0]
        sub = random.choices(["www.", "app.", "api.", "docs.", "blog.", "support.", ""], weights=[0.4, 0.15, 0.1, 0.1, 0.1, 0.05, 0.1])[0]
        
        url = f"{scheme}{sub}{domain}/{path}" if path else f"{scheme}{sub}{domain}/"
        urls.append(url)
        labels.append(0)

    # --- Generate Phishing URLs ---
    # 1. Direct seed patterns
    for p in PHISHING_PATTERNS:
        urls.append(p)
        labels.append(1)

    # 2. Generative phishing combinations
    brands = [
        "paypal", "appleid", "netflix", "microsoft", "amazon", "chase", "binance",
        "coinbase", "metamask", "bankofamerica", "wellsfargo", "google-security",
        "facebook-appeal", "instagram-support", "whatsapp-web", "steamcommunity",
        "stellar-airdrop", "blockchain-wallet", "ledger-update", "dhl-tracking"
    ]
    phish_tlds = ["xyz", "top", "work", "click", "buzz", "club", "info", "cam", "monster", "cf", "tk", "ml", "ga"]
    action_words = [
        "login", "signin", "verify-account", "security-update", "unfreeze",
        "billing-update", "claim-reward", "airdrop", "kyc-verification",
        "confirm-identity", "password-reset", "suspicious-activity", "portal-auth",
        "unlock-account", "recovery-phrase", "session-expired", "appeal-case"
    ]
    suffixes = [
        "login.php", "auth.html", "verify", "secure/index.php", "portal/auth",
        "signin.jsp", "checkpoint", "session/restore", "web/login.aspx",
        "index.php?ref=email_link", "account/confirm?token=8923", "sync-wallet"
    ]

    while len([l for l in labels if l == 1]) < n_phish:
        brand = random.choice(brands)
        action = random.choice(action_words)
        tld = random.choice(phish_tlds)
        suffix = random.choice(suffixes)
        scheme = random.choices(["http://", "https://"], weights=[0.75, 0.25])[0]
        
        style = random.randint(1, 5)
        if style == 1:
            # Subdomain deception: http://paypal.com.account-update.xyz/login.php
            url = f"{scheme}{brand}.com.{action}-{random.randint(10, 999)}.{tld}/{suffix}"
        elif style == 2:
            # Hyphenated brand domain: http://chase-security-verify.top/auth
            url = f"{scheme}{brand}-{action}-{random.randint(100, 9999)}.{tld}/{suffix}"
        elif style == 3:
            # IP address hosting
            ip = f"{random.randint(45, 210)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            port_str = f":{random.choice([8080, 8443, 8000, 8888])}" if random.random() < 0.25 else ""
            url = f"http://{ip}{port_str}/{brand}/{action}/{suffix}"
        elif style == 4:
            # Random string / DGA domain
            rand_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(10, 16)))
            url = f"{scheme}{rand_str}.{tld}/{action}?user={brand}&id={random.randint(10000, 99999)}"
        else:
            # @ symbol or double-slash trick
            url = f"{scheme}{brand}.com@{random.choice(brands)}-portal.{tld}/{suffix}"

        urls.append(url)
        labels.append(1)

    df = pd.DataFrame({"url": urls, "label": labels})
    # Remove duplicates and shuffle
    df = df.drop_duplicates(subset=["url"]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


def ensure_dataset(output_path: str = "dataset/urls.csv", n_legit: int = 1500, n_phish: int = 1500) -> str:
    """Ensures that the dataset exists; creates it if absent."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if not os.path.exists(output_path):
        print(f"Generating realistic dataset ({n_legit} legit, {n_phish} phishing)...")
        df = generate_synthetic_samples(n_legit=n_legit, n_phish=n_phish)
        df.to_csv(output_path, index=False)
        print(f"Saved dataset to {output_path} with {len(df)} samples.")
    return output_path


if __name__ == "__main__":
    csv_file = ensure_dataset()
    print(f"Dataset generated at {csv_file}")
