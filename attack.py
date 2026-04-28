import requests

# --- Configuration ---
TARGET_URL = "http://127.0.0.1:5000/login"
TARGET_USER = "demo"
WORDLIST = r"C:\Users\nidhi\Downloads\rockyou.txt"


def test_login_security():
    print(f"Testing login security for user: {TARGET_USER}")
    session = requests.Session()
    with open(WORDLIST, 'r', encoding='latin-1') as f:
        for line in f:
            password = line.strip()
            payload = {
                "username": TARGET_USER,
                "password": password
            }
            response = session.post(TARGET_URL, data=payload)
            if "Welcome" in response.text:
                print("\nLogin succeeded")
                print(f"Username: {TARGET_USER}")
                print(f"Password: {password}")
                return
            elif "ACCOUNT_LOCKED" in response.text:
                print("\nAccount locked ")
                return
            else:
                print(f"Trying: {password} | Status: {response.status_code}", end="\r")

if __name__ == "__main__":
    test_login_security()