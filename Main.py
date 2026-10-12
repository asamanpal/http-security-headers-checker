
import argparse
import sys
from urllib.parse import urlparse

import requests

HEADERS = {
    "Content-Security-Policy": "Helps mitigate content injection.",
    "Strict-Transport-Security": "Encourages HTTPS connections.",
    "X-Content-Type-Options": "Helps prevent MIME sniffing.",
    "X-Frame-Options": "Helps control framing and clickjacking.",
    "Referrer-Policy": "Controls referrer information.",
    "Permissions-Policy": "Restricts selected browser features.",
}


def check_url(value):
    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    return value


def scan(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "HeaderChecker/1.0"},
        )
    except requests.RequestException as error:
        print(f"Request failed: {error}")
        return 1

    print(f"\nURL: {response.url}")
    print(f"HTTP Status: {response.status_code}")
    print("\nSECURITY HEADER REPORT")
    print("=" * 45)

    present = 0

    for header, description in HEADERS.items():
        value = response.headers.get(header)

        if value:
            present += 1
            print(f"[PRESENT] {header}: {value}")
        else:
            print(f"[MISSING] {header}")

        print(f"  Info: {description}\n")

    print("=" * 45)
    print(f"Headers present: {present}/{len(HEADERS)}")
    print("Missing headers need review, not automatic vulnerability claims.")

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Inspect HTTP security headers."
    )
    parser.add_argument("url", help="Website URL to inspect")
    args = parser.parse_args()

    try:
        url = check_url(args.url)
    except ValueError as error:
        parser.error(str(error))

    return scan(url)


if __name__ == "__main__":
    sys.exit(main())
  
