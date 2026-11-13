
from flask import Flask, request, redirect, session, render_template_string
import sqlite3
import bcrypt
import secrets
import hmac
import os
from functools import wraps

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY", "change-this-secret-key-for-local-testing"
)

DATABASE = "users.db"


# DATABASE CONNECTION
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# CREATE DATABASE
def create_table():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# CSRF TOKEN
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


def check_csrf():
    token = request.form.get("csrf_token", "")

    return (
        isinstance(token, str)
        and hmac.compare_digest(
            token, session.get("csrf_token", "")
        )
    )


# LOGIN PROTECTION
def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect("/login")

        return function(*args, **kwargs)

    return wrapper


# HOME PAGE
@app.route("/")
def home():
    return redirect("/login")


# REGISTRATION PAGE
@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":

        if not check_csrf():
            return "Invalid request", 400

        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            message = "All fields are required."

        elif len(username) < 3 or len(username) > 30:
            message = "Username must contain 3-30 characters."

        elif not username.replace("_", "").isalnum():
            message = "Username can contain letters, numbers and underscore."

        elif len(password) < 8 or len(password) > 72:
            message = "Password must contain 8-72 bytes."

        elif not any(c.isupper() for c in password):
            message = "Password needs an uppercase letter."

        elif not any(c.islower() for c in password):
            message = "Password needs a lowercase letter."

        elif not any(c.isdigit() for c in password):
            message = "Password needs a number."

        else:

            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt()
            )

            conn = get_db()

            try:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_password.decode("utf-8"))
                )

                conn.commit()
                conn.close()

                return redirect("/login")

            except sqlite3.IntegrityError:
                conn.close()
                message = "Username already exists."

    return render_template_string("""
    <html>
    <head>
        <title>Register</title>
        <style>
            body {
                font-family: Arial;
                background: #eaf0f8;
                text-align: center;
                padding-top: 80px;
            }

            .box {
                background: white;
                padding: 30px;
                width: 320px;
                margin: auto;
                border-radius: 10px;
            }

            input, button {
                width: 90%;
                padding: 12px;
                margin: 10px;
            }

            button {
                background: #2563eb;
                color: white;
                border: none;
                cursor: pointer;
            }

            a { color: blue; }
        </style>
    </head>

    <body>
        <div class="box">
            <h2>Create Account</h2>

            <form method="POST">
                <input type="hidden" name="csrf_token"
                       value="{{ token }}">

                <input type="text" name="username"
                       placeholder="Username" required>

                <input type="password" name="password"
                       placeholder="Password" required>

                <button type="submit">Register</button>
            </form>

            <p style="color:red;">{{ message }}</p>

            <p>Already registered?
                <a href="/login">Login</a>
            </p>
        </div>
    </body>
    </html>
    """, message=message, token=csrf_token())


# LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():

    message = ""

    if request.method == "POST":

        if not check_csrf():
            return "Invalid request", 400

        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and bcrypt.checkpw(
            password.encode("utf-8"),
            user["password"].encode("utf-8")
        ):

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["csrf_token"] = secrets.token_hex(32)

            return redirect("/dashboard")

        else:
            message = "Invalid username or password."

    return render_template_string("""
    <html>
    <head>
        <title>Secure Login</title>

        <style>
            body {
                font-family: Arial;
                background: #eaf0f8;
                text-align: center;
                padding-top: 80px;
            }

            .box {
                background: white;
                padding: 30px;
                width: 320px;
                margin: auto;
                border-radius: 10px;
            }

            input, button {
                width: 90%;
                padding: 12px;
                margin: 10px;
            }

            button {
                background: #2563eb;
                color: white;
                border: none;
                cursor: pointer;
            }

            a { color: blue; }
        </style>
    </head>

    <body>
        <div class="box">

            <h2>Secure Login System</h2>

            <form method="POST">

                <input type="hidden" name="csrf_token"
                       value="{{ token }}">

                <input type="text" name="username"
                       placeholder="Username" required>

                <input type="password" name="password"
                       placeholder="Password" required>

                <button type="submit">Login</button>

            </form>

            <p style="color:red;">{{ message }}</p>

            <p>New user?
                <a href="/register">Create Account</a>
            </p>

        </div>
    </body>
    </html>
    """, message=message, token=csrf_token())


# DASHBOARD
@app.route("/dashboard")
@login_required
def dashboard():

    return render_template_string("""
    <html>
    <head>
        <title>Dashboard</title>
    </head>

    <body style="text-align:center;font-family:Arial;
                 padding-top:100px;">

        <h1>Welcome, {{ username }}!</h1>

        <h3>Login Successful</h3>

        <p>Your account is protected.</p>

        <form action="/logout" method="POST">
            <input type="hidden" name="csrf_token"
                   value="{{ token }}">
            <button type="submit">Logout</button>
        </form>

    </body>
    </html>
    """, username=session["username"], token=csrf_token())


# LOGOUT
@app.route("/logout", methods=["POST"])
@login_required
def logout():

    if not check_csrf():
        return "Invalid request", 400

    session.clear()

    return redirect("/login")


# RUN APPLICATION
if __name__ == "__main__":

    create_table()

    print("Secure Login System Started!")
    print("Open http://127.0.0.1:5000")

    app.run(debug=False)
