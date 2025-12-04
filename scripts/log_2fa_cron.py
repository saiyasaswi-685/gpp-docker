#!/usr/bin/env python3
"""
Cron script to log 2FA codes every minute.

Writes lines to stdout which cron redirects to /cron/last_code.txt
Format: "YYYY-MM-DD HH:MM:SS - 2FA Code: 123456"
"""

from datetime import datetime, timezone
from pathlib import Path
import sys

# import TOTP generator
from app.totp_utils import generate_totp_code

SEED_PATHS = [Path("/data/seed.txt"), Path("data/seed.txt")]

def read_seed():
    for p in SEED_PATHS:
        if p.exists():
            return p.read_text().strip()
    return None

def main():
    try:
        seed = read_seed()
        if not seed:
            print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - 2FA Code: <seed not found>")
            return

        code = generate_totp_code(seed)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} - 2FA Code: {code}")

    except Exception as e:
        print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - 2FA Code: <error: {e}>")

if __name__ == "__main__":
    main()
