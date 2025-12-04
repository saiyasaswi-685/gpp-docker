#!/usr/bin/env python3
"""
Request encrypted seed from instructor API and save to encrypted_seed.txt

Usage:
    python app/request_seed.py --student-id YOUR_ID \
        --github-repo-url https://github.com/alekhya178/gpp-docker \
        --api-url https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import requests
except Exception as e:
    print("The 'requests' library is required. Install with: pip install requests")
    raise

def read_public_key_as_single_line(pem_path: Path) -> str:
    """
    Read a PEM file and return the PEM as a normal Python string
    containing real newline characters. JSON encoding will escape
    those newlines automatically when sent in the request.
    """
    raw = pem_path.read_text()
    # Normalize CRLF -> LF so the server receives consistent line endings
    normalized = raw.replace("\r\n", "\n")
    return normalized

def request_seed(student_id: str, github_repo_url: str, api_url: str, public_pem_path: Path, timeout: int = 15):
    public_key_text = read_public_key_as_single_line(public_pem_path)

    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_text
    }

    headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(api_url, json=payload, headers=headers, timeout=timeout)
    except Exception as e:
        print("Network / request error:", e)
        sys.exit(1)

    if resp.status_code != 200:
        print(f"Error: Received HTTP {resp.status_code}")
        print("Response body:", resp.text)
        sys.exit(1)

    try:
        data = resp.json()
    except Exception as e:
        print("Error parsing JSON response:", e)
        print("Raw response:", resp.text)
        sys.exit(1)

    if data.get("status") != "success" or "encrypted_seed" not in data:
        print("API returned error or unexpected payload:")
        print(json.dumps(data, indent=2))
        sys.exit(1)

    encrypted_seed = data["encrypted_seed"]

    # Save to file (plain text). DO NOT commit this file to git.
    out_path = Path("encrypted_seed.txt")
    out_path.write_text(encrypted_seed)
    print(f"Encrypted seed saved to {out_path.resolve()}")
    print("=== encrypted_seed (first 80 chars) ===")
    print(encrypted_seed[:80] + ("..." if len(encrypted_seed) > 80 else ""))

    return encrypted_seed

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--student-id", required=True)
    p.add_argument("--github-repo-url", required=True)
    p.add_argument("--api-url", required=True)
    p.add_argument("--public-pem", default="student_public.pem",
                   help="Path to your student public key PEM (default: student_public.pem)")
    args = p.parse_args()

    public_path = Path(args.public_pem)
    if not public_path.exists():
        print("Public key file not found:", public_path)
        sys.exit(1)

    request_seed(
        student_id=args.student_id,
        github_repo_url=args.github_repo_url,
        api_url=args.api_url,
        public_pem_path=public_path
    )
