#!/usr/bin/env python3

"""
Sentinel
--------
A lightweight HTTP security header analyzer.

Author: Shajjat Hassan
Purpose: Educational web security analysis
"""

import argparse
import sys
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Helps control which resources a browser is allowed to load.",
        "weight": 25,
    },
    "Strict-Transport-Security": {
        "description": "Forces browsers to use HTTPS for future requests.",
        "weight": 20,
    },
    "X-Content-Type-Options": {
        "description": "Helps prevent MIME-type sniffing.",
        "weight": 15,
    },
    "X-Frame-Options": {
        "description": "Helps reduce clickjacking risks.",
        "weight": 15,
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information browsers send.",
        "weight": 10,
    },
    "Permissions-Policy": {
        "description": "Controls access to selected browser features.",
        "weight": 10,
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Helps isolate browsing contexts from cross-origin documents.",
        "weight": 5,
    },
}


BANNER = r"""
   _____            _   _            _
  / ____|          | | (_)          | |
 | (___   ___ _ __ | |_ _ _ __   ___| |
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  ____) |  __/ | | | |_| | | | |  __/ |
 |_____/ \___|_| |_|\__|_|_| |_|\___|_|

        HTTP SECURITY HEADER ANALYZER
"""


def normalize_url(target):
    """Add HTTPS if the user does not provide a scheme."""

    target = target.strip()

    if not target:
        raise ValueError("Target URL cannot be empty.")

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)

    if not parsed.netloc:
        raise ValueError("Invalid URL.")

    return target


def analyze_headers(response):
    """Check the target response against the security header list."""

    results = []

    for header, metadata in SECURITY_HEADERS.items():
        value = response.headers.get(header)

        results.append(
            {
                "header": header,
                "present": value is not None,
                "value": value,
                "description": metadata["description"],
                "weight": metadata["weight"],
            }
        )

    return results


def calculate_score(results):
    """Calculate a simple weighted security-header score."""

    total = sum(item["weight"] for item in results)
    earned = sum(item["weight"] for item in results if item["present"])

    if total == 0:
        return 0

    return round((earned / total) * 100)


def print_result(item):
    """Print one security-header result."""

    if item["present"]:
        print(f"  \033[92m[+] {item['header']}\033[0m")
    else:
        print(f"  \033[91m[-] {item['header']}\033[0m")

    print(f"      {item['description']}")

    if item["present"]:
        print(f"      Value: {item['value']}")

    print()


def score_label(score):
    """Return a simple label for the calculated score."""

    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Needs Improvement"

    return "Weak"


def analyze(target, timeout):
    """Fetch and analyze the target."""

    url = normalize_url(target)

    headers = {
        "User-Agent": "Sentinel-Security-Header-Analyzer/1.0"
    }

    print(BANNER)
    print(f"Target : {url}")
    print("-" * 60)

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.exceptions.SSLError:
        print("\033[91m[!] TLS/SSL certificate verification failed.\033[0m")
        sys.exit(1)

    except requests.exceptions.Timeout:
        print("\033[91m[!] Request timed out.\033[0m")
        sys.exit(1)

    except requests.exceptions.RequestException as error:
        print(f"\033[91m[!] Request failed: {error}\033[0m")
        sys.exit(1)

    print(f"Status : {response.status_code}")
    print(f"Final  : {response.url}")
    print()

    print("SECURITY HEADERS")
    print("=" * 60)

    results = analyze_headers(response)

    for result in results:
        print_result(result)

    score = calculate_score(results)

    print("=" * 60)
    print(f"Security Score : {score}/100")
    print(f"Assessment     : {score_label(score)}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze common HTTP security headers."
    )

    parser.add_argument(
        "target",
        help="Target website URL, e.g. https://example.com",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        print("Timeout must be greater than zero.")
        sys.exit(1)

    analyze(args.target, args.timeout)


if __name__ == "__main__":
    main()
