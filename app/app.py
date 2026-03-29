from flask import Flask, request, g
import sqlite3
import subprocess
import os

app = Flask(__name__)

# VULNERABILITY 1 — Hardcoded secret key
# What it is: Flask uses secret_key to sign session cookies.
# If an attacker knows this value they can forge any session,
# bypassing your entire authentication system.
# Who catches it: Semgrep + Gitleaks
app.secret_key = "super-secret-hardcoded-key-123"

def get_db():
    # Flask's g object lives for exactly one request then is destroyed.
    # Each request gets its own SQLite connection, created in its own
    # thread. This satisfies SQLite's thread-safety requirement.
    # Without this, a global DB connection gets shared across threads
    # and SQLite throws the error you saw earlier.
    if "db" not in g:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
        )
        conn.execute("INSERT INTO users VALUES (1, 'admin', 'password123')")
        conn.execute("INSERT INTO users VALUES (2, 'alice', 'alice456')")
        conn.execute("INSERT INTO users VALUES (3, 'bob', 'bob789')")
        conn.commit()
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(error):
    # Flask calls this automatically when the request ends.
    # It closes the DB connection cleanly so memory is freed.
    db = g.pop("db", None)
    if db is not None:
        db.close()

@app.route("/")
def index():
    return "Vulnerable Flask App — DevSecOps Project 1"

@app.route("/user")
def get_user():
    # VULNERABILITY 2 — SQL Injection
    # The username from the URL is pasted directly into the SQL string.
    # Attacker sends: username=' OR '1'='1
    # Query becomes: SELECT * FROM users WHERE username = '' OR '1'='1'
    # '1'='1' is always true — every row matches — full DB returned.
    # Real world impact: data breach, authentication bypass.
    # Who catches it: Semgrep (python.flask.security.injection rule)
    username = request.args.get("username", "")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = get_db().execute(query)
    rows = cursor.fetchall()
    return str(rows)

@app.route("/run")
def run_command():
    # VULNERABILITY 3 — Command Injection via shell=True
    # cmd parameter passed directly to the shell.
    # Attacker sends: cmd=ls;cat /etc/passwd
    # shell=True hands the entire string to /bin/sh unchanged.
    # Both commands execute — yours and theirs.
    # Real world impact: full remote code execution on the server.
    # Who catches it: Semgrep (subprocess-shell-true rule)
    cmd = request.args.get("cmd", "echo hello")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)