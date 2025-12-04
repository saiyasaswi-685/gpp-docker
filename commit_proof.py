# commit_proof.py
# Usage:
#   python3 commit_proof.py            # uses `git log -1 --format=%H`
#   python3 commit_proof.py <commit>   # use provided 40-char commit hash

import sys
import subprocess
import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

def get_commit_hash_from_git():
    p = subprocess.run(["git", "log", "-1", "--format=%H"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise SystemExit(f"Error running git: {p.stderr.strip()}")
    h = p.stdout.strip()
    if len(h) != 40:
        raise SystemExit(f"Git returned non-40-char hash: '{h}'")
    return h

def load_private_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())

def load_public_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_public_key(data, backend=default_backend())

def sign_message(message: str, private_key) -> bytes:
    """
    Sign ASCII commit-hash string using RSA-PSS with SHA-256, MGF1(SHA-256) and max salt length.
    Returns signature bytes.
    """
    m_bytes = message.encode("utf-8")   # IMPORTANT: sign the ASCII/UTF-8 bytes of the hex string
    sig = private_key.sign(
        m_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA/OAEP with SHA-256 (MGF1 SHA-256).
    Returns ciphertext bytes.
    """
    ct = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ct

def main():
    # commit hash argument or from git
    if len(sys.argv) >= 2:
        commit = sys.argv[1].strip()
        if len(commit) != 40:
            raise SystemExit("Provided commit hash must be 40 hex characters.")
    else:
        commit = get_commit_hash_from_git()

    # files (adjust paths if necessary)
    student_priv = Path("student_private.pem")
    instr_pub = Path("instructor_public.pem")

    if not student_priv.exists():
        raise SystemExit("student_private.pem not found in current directory.")
    if not instr_pub.exists():
        raise SystemExit("instructor_public.pem not found in current directory.")

    # load keys
    priv = load_private_key(student_priv)
    pub = load_public_key(instr_pub)

    # sign commit (ASCII)
    signature = sign_message(commit, priv)

    # encrypt signature with instructor public key
    encrypted = encrypt_with_public_key(signature, pub)

    # base64 encode encrypted signature (single-line)
    b64 = base64.b64encode(encrypted).decode("ascii")

    # output
    print("Commit Hash:", commit)
    print("Encrypted Signature (base64):")
    print(b64)

if __name__ == "__main__":
    main()
