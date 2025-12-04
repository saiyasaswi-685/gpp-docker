# app/api.py
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from pathlib import Path
import time
import base64
import traceback

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# reuse your totp utils
from .totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

# File locations (use same as assignment)
SEED_PATH = Path("/data/seed.txt")      # path inside container
LOCAL_SEED_PATH = Path("data/seed.txt") # useful for local testing on Windows
PRIVATE_KEY_PATH = Path("student_private.pem")


# Request models
class EncryptedSeedRequest(BaseModel):
    encrypted_seed: str

class VerifyRequest(BaseModel):
    code: str | None = None


def _load_private_key(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Private key file not found: {path}")
    data = path.read_bytes()
    private_key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Loaded key is not an RSA private key.")
    return private_key


def _write_seed(seed_hex: str, target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(seed_hex)


# Use decrypt logic consistent with your decrypt_seed.py
def _decrypt_with_private(encrypted_seed_b64: str, private_key):
    try:
        ct = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError("Encrypted seed is not valid base64") from e

    try:
        plaintext_bytes = private_key.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise ValueError("RSA decryption failed") from e

    try:
        seed = plaintext_bytes.decode("utf-8").strip()
    except Exception as e:
        raise ValueError("Decrypted plaintext is not valid UTF-8") from e

    # validate 64-char hex
    if len(seed) != 64:
        raise ValueError("Decrypted seed length invalid")
    seed_lower = seed.lower()
    if any(c not in "0123456789abcdef" for c in seed_lower):
        raise ValueError("Decrypted seed contains non-hex characters")
    return seed_lower


# Helper to decide where to persist seed (container vs local)
def _target_seed_path() -> Path:
    # If running in container, /data/ exists; otherwise use local data/
    if Path("/data").exists():
        return SEED_PATH
    else:
        return LOCAL_SEED_PATH


@app.post("/decrypt-seed")
async def post_decrypt_seed(req: EncryptedSeedRequest):
    """
    Decrypt the provided base64 encrypted_seed using the student's private key,
    validate it is a 64-char hex seed, save to /data/seed.txt and return {"status":"ok"}.
    """
    try:
        priv = _load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        # Private key missing -> internal server error for this API
        raise HTTPException(status_code=500, detail={"error": f"Private key not found: {e}"})

    try:
        seed_hex = _decrypt_with_private(req.encrypted_seed, priv)
    except Exception as e:
        # Decryption or validation failed
        # return 500 with the specified error message
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    try:
        target = _target_seed_path()
        _write_seed(seed_hex, target)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "Failed to write seed"})

    return {"status": "ok"}


@app.get("/generate-2fa")
async def get_generate_2fa():
    """
    Generate the current TOTP code from the stored seed and return:
    { "code": "123456", "valid_for": 30 }
    or 500 if the seed is not present.
    """
    target = _target_seed_path()
    if not target.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    seed_hex = target.read_text().strip()
    # generate TOTP
    try:
        code = generate_totp_code(seed_hex)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "Failed to generate TOTP"})

    # calculate remaining seconds in current period
    period = 30
    now = int(time.time())
    rem = period - (now % period)
    # If rem==30 that means start of period, but usually show 30 -> keep it in range 1..30
    if rem == 0:
        rem = period

    return {"code": code, "valid_for": rem}


@app.post("/verify-2fa")
async def post_verify_2fa(req: VerifyRequest):
    """
    Verify a posted code:
    - 400 if code missing
    - 500 if seed not decrypted
    - returns {"valid": true/false}
    """
    if not req.code:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    target = _target_seed_path()
    if not target.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    seed_hex = target.read_text().strip()
    try:
        valid = verify_totp_code(seed_hex, req.code, valid_window=1)
    except Exception as e:
        # treat any unexpected errors as server error
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})

    return {"valid": bool(valid)}
