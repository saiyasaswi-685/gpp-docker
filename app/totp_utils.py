# app/totp_utils.py
"""
TOTP generation & verification (instructor-required settings).

Usage examples (from repo root):
  python -c "from app.totp_utils import generate_totp_code; print(generate_totp_code(open('data/seed.txt').read().strip()))"
  python -c "from app.totp_utils import verify_totp_code; print(verify_totp_code(open('data/seed.txt').read().strip(), '<CODE>'))"

Requirements:
  pip install pyotp
"""

import base64
import pyotp

def _hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-char hex string -> base32 string (no padding).
    """
    if not isinstance(hex_seed, str):
        raise TypeError("hex_seed must be a string")
    hex_seed = hex_seed.strip().lower()
    if len(hex_seed) != 64:
        raise ValueError("hex_seed must be 64 hex characters")
    # Validate hex characters
    try:
        seed_bytes = bytes.fromhex(hex_seed)
    except Exception:
        raise ValueError("hex_seed contains non-hex characters")
    # base32 encode and remove '=' padding (pyotp accepts no padding)
    b32 = base64.b32encode(seed_bytes).decode("utf-8").rstrip("=")
    return b32

def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code from a 64-character hex seed.
    Algorithm: SHA-1, Period: 30s, Digits: 6 (defaults used by pyotp.TOTP)
    Returns the 6-digit string.
    """
    b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)  # SHA1 default
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code with +/- valid_window periods.
    valid_window=1 => accepts codes within ±30 seconds.
    Returns True if valid, False otherwise.
    """
    b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    # totp.verify(code, valid_window=...) accepts int window
    # pyotp verify: valid_window means number of steps of skew to allow.
    try:
        return bool(totp.verify(code, valid_window=valid_window))
    except Exception:
        return False
