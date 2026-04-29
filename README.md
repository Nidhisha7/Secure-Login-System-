# Secure Login System

A Flask-based secure authentication system showcasing key security mechanisms such as password hashing (bcrypt), protection against credential stuffing attacks, rate limiting with account lockout, and TOTP-based Two-Factor Authentication (2FA) using Google Authenticator.

---

## File Descriptions

- **`app.py`**-Basic login system demonstrating bcrypt and account lockout (without 2FA).

- **`attack.py`**-Script to simulate credential stuffing using a password wordlist.

- **`totp_demo.py`**-Main Flask application handling registration, login, rate limiting, account lockout, and TOTP-based 2FA.

---

## Installation

### Install dependencies
```bash
pip install flask bcrypt pyotp qrcode[pil] requests
```
