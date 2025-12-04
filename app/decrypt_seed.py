#!/usr/bin/env python3
"""
Decrypt an encrypted seed (base64) using RSA OAEP(SHA-256) and store it
at /data/seed.txt (as required by the assignment).

Usage (example):
    python app/decrypt_seed.py --private-pem student_private.pem --encrypted-file encrypted_seed.txt
"""

from pathlib import Path
import argparse
import base64
import sys

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def load_private_key(pem_path: Path):
    """
    Load a PEM-encoded RSA private key from file (unencrypted).
    """
    data = pem_path.read_bytes()
    # No password expected (assignment says keys are unencrypted)
    private_key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Loaded key is not an RSA private key.")
    return private_key

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP with SHA-256.

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext (string)
        private_key: RSAPrivateKey object (from cryptography)

    Returns:
        Decrypted hex seed (64-character lowercase hex string)

    Raises:
        ValueError on invalid format or decryption failure.
    """
    # 1. Base64 decode
    try:
        ct = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encrypted seed: {e}")

    # 2. RSA/OAEP decrypt with SHA-256 and MGF1(SHA-256)
    try:
        plaintext_bytes = private_key.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")

    # 3. Decode bytes to UTF-8 string
    try:
        seed = plaintext_bytes.decode("utf-8").strip()
    except Exception as e:
        raise ValueError(f"Decrypted plaintext is not valid UTF-8: {e}")

    # 4. Validate: must be 64-character hex string (allow uppercase by normalizing)
    if len(seed) != 64:
        raise ValueError(f"Invalid seed length: expected 64 characters, got {len(seed)}")

    seed_lower = seed.lower()
    hex_chars = set("0123456789abcdef")
    if any(c not in hex_chars for c in seed_lower):
        raise ValueError("Invalid seed content: must be hexadecimal [0-9a-f] only")

    # Return normalized lowercase hex seed
    return seed_lower

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--private-pem", default="student_private.pem",
                   help="Path to your student private PEM file (default: student_private.pem)")
    p.add_argument("--encrypted-file", default="encrypted_seed.txt",
                   help="Path to the encrypted_seed.txt (default: encrypted_seed.txt)")
    p.add_argument("--out-path", default="/data/seed.txt",
                   help="Output path for the decrypted seed inside the container (default: /data/seed.txt)")
    args = p.parse_args()

    priv_path = Path(args.private_pem)
    enc_path = Path(args.encrypted_file)
    out_path = Path(args.out_path)

    if not priv_path.exists():
        print(f"Private key not found: {priv_path}", file=sys.stderr)
        sys.exit(1)
    if not enc_path.exists():
        print(f"Encrypted seed file not found: {enc_path}", file=sys.stderr)
        sys.exit(1)

    try:
        private_key = load_private_key(priv_path)
    except Exception as e:
        print(f"Failed to load private key: {e}", file=sys.stderr)
        sys.exit(1)

    encrypted_b64 = enc_path.read_text().strip()

    try:
        seed_hex = decrypt_seed(encrypted_b64, private_key)
    except Exception as e:
        print(f"Decryption/validation error: {e}", file=sys.stderr)
        sys.exit(1)

    # Ensure parent directory exists (container should have /data/ but create if not)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(seed_hex)
    except Exception as e:
        print(f"Failed to write seed to {out_path}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Decrypted seed saved to {out_path} (64 hex chars).")
    print(seed_hex)

if __name__ == "__main__":
    main()
