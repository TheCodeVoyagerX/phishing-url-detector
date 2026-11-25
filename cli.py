"""
Command Line Interface (CLI) for Phishing URL Detector
Scan single URLs or batch process URL lists directly from your terminal.
"""

import argparse
import sys
from typing import List
from src.predictor import PhishingDetector


def format_cli_output(result: dict) -> str:
    color_map = {
        "Safe": "\033[92m",               # Green
        "Low Risk / Caution": "\033[93m",  # Yellow
        "Suspicious": "\033[33m",          # Orange/Brown
        "Critical Phishing Threat": "\033[91m",  # Red
    }
    reset = "\033[0m"
    bold = "\033[1m"
    col = color_map.get(result["risk_level"], "\033[97m")

    out = []
    out.append(f"\n{bold}============================================================{reset}")
    out.append(f"{bold}🛡️  PHISHING URL INSPECTOR REPORT{reset}")
    out.append(f"{bold}============================================================{reset}")
    out.append(f"Target URL:       {bold}{result['url']}{reset}")
    out.append(f"Verdict:          {col}{bold}{result['prediction'].upper()}{reset}")
    out.append(f"Risk Level:       {col}{bold}{result['risk_level']}{reset}")
    out.append(f"Risk Score:       {col}{bold}{result['risk_score']}/100{reset} (Confidence: {result['confidence_pct']}%)")
    out.append(f"Engine Model:     {result['model_used']}")
    out.append(f"Summary:          {result['verdict_summary']}")
    out.append(f"Action:           {bold}{result['action_advice']}{reset}")
    
    out.append(f"\n{bold}--- Threat Indicators Breakdown ---{reset}")
    for ind in result["threat_indicators"]:
        tag = "[PASS]" if ind["status"] == "SAFE" else "[WARN]" if ind["status"] == "WARNING" else "[ALERT]"
        ind_col = "\033[92m" if ind["status"] == "SAFE" else "\033[93m" if ind["status"] == "WARNING" else "\033[91m"
        out.append(f" {ind_col}{tag:<7}{reset} {ind['name']} ({ind['severity']}): {ind['description']}")

    out.append(f"{bold}============================================================{reset}\n")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(
        description="Phishing URL Detector - AI & Heuristic Powered Security Scanner"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Single URL scan
    scan_parser = subparsers.add_parser("scan", help="Scan a single URL")
    scan_parser.add_argument("url", type=str, help="The URL to scan for phishing traits")

    # Batch scan
    batch_parser = subparsers.add_parser("batch", help="Scan multiple URLs from a file")
    batch_parser.add_argument("file", type=str, help="Path to text or CSV file containing URLs")
    batch_parser.add_argument("--output", "-o", type=str, default="scan_results.csv", help="Output CSV path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    print("Loading AI Phishing Detection Engine...")
    detector = PhishingDetector()

    if args.command == "scan":
        result = detector.predict(args.url)
        print(format_cli_output(result))
    elif args.command == "batch":
        with open(args.file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"Scanning {len(lines)} URLs...")
        df_res = detector.predict_batch(lines)
        df_res.to_csv(args.output, index=False)
        print(f"Completed! Saved results to {args.output}")
        print(df_res[["URL", "Verdict", "Risk Score", "Risk Level"]])


if __name__ == "__main__":
    main()
