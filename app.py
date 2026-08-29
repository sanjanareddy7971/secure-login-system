from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
import bcrypt
import re

app = Flask(__name__)

# Used for securely signing Flask sessions.
# For a real deployment, replace this with a strong random secret.
app.secret_key = "change-this-secret-key-for-production"

DATABASE = "users.db"


# ---------------------------------------------------------
# DATABASE
# ---------------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():

    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# VALIDATION
# ---------------------------------------------------------

def valid_username(username):

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9_]{3,30}",
            username
        )
    )


def valid_password(password):

    return len(password) >= 6


# ---------------------------------------------------------
# HTML TEMPLATE
# ---------------------------------------------------------

PAGE = """
<!DOCTYPE html>

<html>

<head>

<title>Secure Login System</title>

<style>

body {
    font-family: Arial, sans-serif;
    background: #f2f5f9;
    text-align: center;
    margin-top: 70px;
}

.container {
    background: white;
    width: 90%;
    max-width: 420px;
    margin: auto;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

input {
    width: 90%;
    padding: 12px;
    margin: 8px;
    border: 1px solid #ccc;
    border-radius: 6px;
}

button {
    padding: 12px 25px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
}

a {
    text-decoration: none;
}

.message {
    margin: 15px;
    font-weight: bold;
}

</style>

</head>

<body>

<div class="container">

<h1>Secure Login System</h1>

{{ content | safe }}

</div>

</body>

</html>
"""


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.route("/")
def home():

    if "username" in session:

        content = f"""
        <h2>Welcome, {session["username"]}!</h2>

        <p>You are successfully logged in.</p>

        <a href="/logout">
            <button>Logout</button>
        </a>
        """

    else:

        content = """
        <h2>Login</h2>

        <form method="POST" action="/login">

            <input
                type="text"
                name="username"
                placeholder="Username"
                required
            >

            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            >

            <br>

            <button type="submit">
                Login
            </button>

        </form>

        <p>
            Don't have an account?
            <a href="/register">Register</a>
        </p>
        """

    return render_template_string(
        PAGE,
        content=content
    )


# ---------------------------------------------------------
# REGISTER
# ---------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not valid_username(username):

            message = (
                "Username must contain 3-30 "
                "letters, numbers or underscores."
            )

        elif not valid_password(password):

            message = (
                "Password must contain at least 6 characters."
            )

        else:

            connection = get_db()

            try:

                # bcrypt password hashing
                password_hash = bcrypt.hashpw(
                    password.encode("utf-8"),
                    bcrypt.gensalt()
                )

                # Parameterized SQL query
                connection.execute(
                    """
                    INSERT INTO users
                    (username, password_hash)
                    VALUES (?, ?)
                    """,
                    (
                        username,
                        password_hash.decode("utf-8")
                    )
                )

                connection.commit()

                connection.close()

                return redirect(
                    url_for("home")
                )

            except sqlite3.IntegrityError:

                connection.close()

                message = "Username already exists."

    content = f"""

    <h2>Create Account</h2>

    <p class="message">
        {message}
    </p>

    <form method="POST">

        <input
            type="text"
            name="username"
            placeholder="Username"
            required
        >

        <input
            type="password"
            name="password"
            placeholder="Password"
            required
        >

        <br>

        <button type="submit">
            Register
        </button>

    </form>

    <p>
        <a href="/">Back to Login</a>
    </p>

    """

    return render_template_string(
        PAGE,
        content=content
    )


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    connection = get_db()

    user = connection.execute(
        """
        SELECT * FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    connection.close()

    if user:

        stored_hash = user["password_hash"]

        if bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8")
        ):

            session["username"] = username

            return redirect(
                url_for("home")
            )

    return render_template_string(
        PAGE,
        content="""
        <h2>Login Failed</h2>

        <p class="message">
            Invalid username or password.
        </p>

        <a href="/">
            <button>Try Again</button>
        </a>
        """
    )


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ---------------------------------------------------------
# START APPLICATION
# ---------------------------------------------------------

if __name__ == "__main__":

    create_database()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
