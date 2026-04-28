from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import bcrypt
import time
import pyotp
import qrcode
import os

app = Flask(__name__)
app.secret_key = "secret123"

DB_NAME = "users.db"
LOCK_LIMIT = 3
LOCK_TIME = 60

last_used_otp = {}

def init_db():
    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until INTEGER DEFAULT 0
        )
    """)

    con.commit()
    con.close()

init_db()

@app.route("/")
@app.route("/login", methods=["GET"])
def login_page():
    return """
    <h2>Login </h2>
    <form method="POST" action="/login">
        <input name="username" placeholder="Username" required><br><br>
        <input name="password" type="password" placeholder="Password" required><br><br>
        <button type="submit">Next</button>
    </form>
    <br>
    <a href="/register">Create Account</a>
    """
#Registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            con = sqlite3.connect(DB_NAME, timeout=5)
            cur = con.cursor()

            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed)
            )
            con.commit()

        except sqlite3.IntegrityError:
            return "User already exists"

        except Exception as e:
            return f"Error: {e}"

        finally:
            con.close()

        session["user"] = username
        return redirect("/setup_2fa")

    return """
    <h2>Register</h2>
    <form method="POST">
        <input name="username" required><br><br>
        <input name="password" type="password" required><br><br>
        <button type="submit">Register</button>
    </form>
    """
#2FA setup page
@app.route("/setup_2fa", methods=["GET", "POST"])
def setup_2fa():
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    cur.execute(
        "SELECT totp_secret FROM users WHERE username=?",
        (username,)
    )
    row = cur.fetchone()

    if row and row[0]:
        secret = row[0]
    else:
        secret = pyotp.random_base32()
        cur.execute(
            "UPDATE users SET totp_secret=? WHERE username=?",
            (secret, username)
        )
        con.commit()

    con.close()

    totp = pyotp.TOTP(secret)

    if not os.path.exists("static"):
        os.makedirs("static")

    uri = totp.provisioning_uri(name=username, issuer_name="SecureApp")
    img = qrcode.make(uri)
    img.save("static/qrcode.png")

    if request.method == "POST":
        otp = request.form["otp"]

        if totp.verify(otp):
            return redirect("/login")
        else:
            return "Invalid OTP during setup"

    return f"""
    <h2>Setup 2FA</h2>
    <p>Scan using Google Authenticator</p>
    <img src="/static/qrcode.png"><br><br>

    <form method="POST">
        Enter OTP: <input name="otp">
        <button type="submit">Verify & Activate</button>
    </form>
    """
#Login page
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    con = sqlite3.connect(DB_NAME, timeout=5)
    cur = con.cursor()

    cur.execute(
        "SELECT password_hash, failed_attempts, locked_until FROM users WHERE username=?",
        (username,)
    )
    user = cur.fetchone()

    if not user:
        time.sleep(1)
        return "Invalid username or password"

    password_hash, attempts, locked_until = user
    now = int(time.time())

    if locked_until > now:
        return "ACCOUNT_LOCKED"

    if bcrypt.checkpw(password.encode(), password_hash.encode()):
        cur.execute(
            "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
            (username,)
        )
        con.commit()

        session["temp_user"] = username
        return redirect("/verify_2fa")

    attempts += 1

    if attempts >= LOCK_LIMIT:
        locked_until = now + LOCK_TIME
        cur.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
            (attempts, locked_until, username)
        )
        con.commit()
        return "ACCOUNT_LOCKED"

    cur.execute(
        "UPDATE users SET failed_attempts=? WHERE username=?",
        (attempts, username)
    )
    con.commit()

    time.sleep(1)
    return "Invalid username or password"
#2FA verficaton page
@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if "temp_user" not in session:
        return redirect("/login")

    username = session["temp_user"]

    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    cur.execute(
        "SELECT totp_secret FROM users WHERE username=?",
        (username,)
    )
    row = cur.fetchone()
    con.close()

    if not row or not row[0]:
        return "2FA not setup"

    secret = row[0]
    totp = pyotp.TOTP(secret)

    message = ""

    if request.method == "POST":
        otp = request.form["otp"]

        if last_used_otp.get(username) == otp:
            message = "Replay attack detected"
        elif not totp.verify(otp):
            message = "Invalid OTP"
        else:
            last_used_otp[username] = otp
            session["user"] = username
            session.pop("temp_user", None)
            return redirect("/welcome")

    return f"""
    <h2>Two-Factor Authentication</h2>

    <form method="POST">
        Enter 6-digit code: <input name="otp"><br><br>
        <button type="submit">Verify</button>
    </form>

    <script>
        var msg = "{message}";
        if(msg) {{
            alert(msg);
        }}
    </script>
    """
#welcome page
@app.route("/welcome")
def welcome():
    if "user" not in session:
        return redirect("/login")

    return f"<h2>Welcome, {session['user']}!</h2>"

if __name__ == "__main__":
    app.run(debug=True)

