# 🚀 Secure PKI-Based 2FA Microservice (FastAPI + Docker + RSA + TOTP)

This project implements a secure microservice that uses:

- **RSA-4096 encryption/decryption**
- **TOTP 2-Factor Authentication**
- **Docker containerization with cron jobs**
- **Persistent seed storage**
- **FastAPI REST API**

The microservice decrypts an encrypted seed using your RSA private key, generates TOTP codes, verifies them, and logs codes via a cron job every minute.

---

## 🔐 Features

### ✔ RSA Cryptography
- RSA-4096 key pair
- Seed decryption using **RSA-OAEP (SHA-256, MGF1)**
- Commit proof using **RSA-PSS signatures**
- Signature encrypted using instructor public key (RSA-OAEP)

### ✔ TOTP 2FA
- SHA-1 algorithm  
- 30-second intervals  
- 6-digit OTPs  
- ±1 time-window tolerance  
- Hex seed → Base32 conversion  

### ✔ REST API Endpoints

#### **POST /decrypt-seed**
Decrypts encrypted seed and stores result in `/data/seed.txt`.

#### **GET /generate-2fa**
Generates current TOTP code + seconds remaining in current 30-sec window.

#### **POST /verify-2fa**
Verifies a submitted TOTP code (±30 seconds tolerance).

---

## 🐳 Dockerized Architecture

- Multi-stage Dockerfile
- Cron daemon running inside container
- Volumes:
  - `/data` → persistent seed storage
  - `/cron` → cron logs
- All timestamps logged in **UTC**

---

## 📁 Project Structure

gpp-docker/
│
├── app/
│ ├── main.py
│ ├── crypto_utils.py
│ └── totp_utils.py
│
├── scripts/
│ └── log_2fa_cron.py
│
├── cron/
│ └── mycron
│
├── Dockerfile
├── docker-compose.yml
├── start.sh
├── requirements.txt
│
├── student_private.pem
├── student_public.pem
├── instructor_public.pem
│
├── commit_proof.py
├── .gitattributes
├── .gitignore
└── README.md
