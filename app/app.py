from flask import Flask, request, g
import sqlite3
import subprocess
import shlex
import os
import boto3

app = Flask(__name__)

# SECRET KEY — fetched from AWS Secrets Manager at runtime
# Never hardcoded. boto3 uses the credential provider chain:
# 1. Local: ~/.aws/credentials (your Mac)
# 2. CI/CD: OIDC temporary credentials from GitHub Actions
# 3. Fallback: environment variable for local dev without AWS
def get_secret(secret_name: str, region: str = "us-east-1") -> str:
    client = boto3.client("secretsmanager", region_name=region)
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response["SecretString"]
    except Exception as e:
        print(f"Warning: Could not fetch secret from AWS: {e}")
        fallback = os.environ.get("FLASK_SECRET_KEY", "local-dev-only-not-for-production")
        print("Using fallback secret — DO NOT use in production")
        return fallback

app.secret_key = get_secret("devsecops-project1/flask-secret-key")

def get_db():
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
    db = g.pop("db", None)
    if db is not None:
        db.close()

@app.route("/")
def index():
    return "Vulnerable Flask App — DevSecOps Project 1"

@app.route("/user")
def get_user():
    # FIX for SQL Injection — parameterised query
    # The ? placeholder tells SQLite to treat the value as data, never as SQL.
    # No matter what the user sends, it cannot break out of the string context.
    # Before: "SELECT * FROM users WHERE username = '" + username + "'"
    # After:  "SELECT * FROM users WHERE username = ?"  with (username,) separate
    # The database driver handles escaping — you never touch the SQL string.
    username = request.args.get("username", "")
    query = "SELECT * FROM users WHERE username = ?"
    cursor = get_db().execute(query, (username,))
    rows = cursor.fetchall()
    return str(rows)

@app.route("/run")
def run_command():
    # FIX for Command Injection — allowlist + shell=False
    # shell=False means Python executes the command directly without /bin/sh
    # No shell means no chaining with ; && || — each argument is literal
    # The allowlist restricts which commands are permitted at all
    # An attacker sending "ls;cat /etc/passwd" gets "command not allowed"
    ALLOWED_COMMANDS = ["ls", "pwd", "whoami", "date"]
    cmd = request.args.get("cmd", "ls")

    if cmd not in ALLOWED_COMMANDS:
        return f"Command not allowed. Permitted: {', '.join(ALLOWED_COMMANDS)}", 403

    # shlex.split safely tokenises the command string into a list
    # shell=False means each token is passed as a literal argument
   result = subprocess.run(  # nosemgrep: python.flask.security.injection.subprocess-injection.subprocess-injection,python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use
        shlex.split(cmd),
        shell=False,
        capture_output=True,
        text=True
    )
    return result.stdout

if __name__ == "__main__":
    # FIX for Flask misconfigs:
    # host="127.0.0.1" binds to localhost only — not publicly exposed
    # debug=False — no interactive debugger in production
    # In production this file is not called directly — a WSGI server
    # like gunicorn runs the app. This block is for local dev only.
    app.run(host="127.0.0.1", port=5000, debug=False)