from flask import Flask, request, render_template_string
import sqlite3
import bcrypt
import time

app = Flask(__name__)

DB_NAME = "users.db"
LOCK_LIMIT = 3
LOCK_TIME = 60

#DATABSE CREATION
def init_db():
    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until INTEGER DEFAULT 0
        )
    """)

    con.commit()
    con.close()

init_db()

#LOGIN PAGE
@app.route("/")
@app.route("/login", methods=["GET"])
def login_page():
    return render_template_string("""
    <h2>Login</h2>
    <form method="POST" action="/login">
        <input name="username" placeholder="Username" required><br><br>
        <input name="password" type="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>

    <br>
    <a href="/register">Create Account</a>
    """)

#REGISTRATION PAGE
@app.route("/register", methods=["GET"])
def register_page():
    return render_template_string("""
    <h2>Register</h2>
    <form method="POST" action="/register">
        <input name="username" placeholder="Username" required><br><br>
        <input name="password" type="password" placeholder="Password" required><br><br>
        <button type="submit">Register</button>
    </form>

    <br>
    <a href="/login">Back to Login</a>
    """)


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed)
        )
        con.commit()
    except:
        return "User already exists"

    return f"Registered successfully! Hash: {hashed}"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    con = sqlite3.connect(DB_NAME)
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
        return "Welcome"

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


if __name__ == "__main__":
    app.run(debug=True)