"""
Deliberately vulnerable Flask app for VVAH detection testing.
DO NOT DEPLOY. Every endpoint contains an intentional security flaw.
"""

import os
import pickle
import sqlite3
import base64
from flask import Flask, request, make_response, jsonify

app = Flask(__name__)

# CWE-798: Hardcoded credentials
# VVAH-DETECT: hardcoded-secret
API_KEY = "sk_live_4f9a2b7c1e8d3a6b5c9e2f7a1d4b8c3e"
DB_PASSWORD = "supersecret123!"
JWT_SECRET = "my_jwt_secret_do_not_change"

DB_PATH = "test.db"
UPLOAD_BASE = "/tmp/uploads"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password) "
        "VALUES (1, 'admin', 'admin123')"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # CWE-89: SQL Injection
    # VVAH-DETECT: sql-injection
    # User input is concatenated directly into the query string.
    query = (
        f"SELECT * FROM users WHERE username = '{username}' "
        f"AND password = '{password}'"
    )
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({"status": "ok", "user_id": row[0]})
    return jsonify({"status": "fail"}), 401


@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: OS Command Injection
    # VVAH-DETECT: command-injection
    # User-controlled `host` is passed straight to the shell.
    result = os.system(f"ping -c 1 {host}")
    return jsonify({"return_code": result})


@app.route("/profile", methods=["GET"])
def profile():
    raw = request.cookies.get("profile", "")
    if not raw:
        return jsonify({"error": "no profile cookie"}), 400

    try:
        # CWE-502: Insecure Deserialization
        # VVAH-DETECT: insecure-deserialization
        # A pickle loaded from an untrusted cookie runs arbitrary code.
        data = pickle.loads(base64.b64decode(raw))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"profile": data})


@app.route("/set_profile", methods=["POST"])
def set_profile():
    data = request.get_json(force=True)
    # Helper endpoint so a tester can mint a valid cookie without pickle.
    raw = base64.b64encode(pickle.dumps(data)).decode()
    resp = make_response(jsonify({"status": "ok"}))
    resp.set_cookie("profile", raw)
    return resp


@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("file", "readme.txt")
    # CWE-22: Path Traversal
    # VVAH-DETECT: path-traversal
    # No normalization/sandboxing; `../` escapes UPLOAD_BASE.
    path = os.path.join(UPLOAD_BASE, filename)
    try:
        with open(path, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        return jsonify({"error": "not found"}), 404
    return content


@app.route("/health", methods=["GET"])
def health():
    # Benign endpoint so the app is "runnable" and gives VVAH a control.
    return jsonify({"status": "healthy"})


if __name__ == "__main__":
    os.makedirs(UPLOAD_BASE, exist_ok=True)
    init_db()
    # CWE-489: Debug mode in production
    app.run(host="0.0.0.0", port=5000, debug=True)
