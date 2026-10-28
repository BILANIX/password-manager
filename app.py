import os, json, sqlite3, secrets
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "password_manager.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Keep the local development secret stable across application restarts.
SECRET_KEY_PATH = os.path.join(BASE_DIR, "instance", ".flask_secret_key")
if os.environ.get("FLASK_SECRET_KEY"):
    app_secret_key = os.environ["FLASK_SECRET_KEY"]
else:
    if not os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "w") as secret_file:
            secret_file.write(secrets.token_hex(32))
        os.chmod(SECRET_KEY_PATH, 0o600)
    with open(SECRET_KEY_PATH, "r") as secret_file:
        app_secret_key = secret_file.read().strip()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=app_secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,  # Local HTTP development only. Set True behind HTTPS.
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
)
hasher = PasswordHasher()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

init_db()

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 80:
            flash("Username must be between 3 and 80 characters.")
            return render_template("register.html")
        if len(password) < 12:
            flash("Use a master password with at least 12 characters.")
            return render_template("register.html")
        try:
            get_db().execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hasher.hash(password))
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("That username is already registered.")
            return render_template("register.html")
        flash("Account created. You can now sign in.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        try:
            valid = user is not None and hasher.verify(user["password_hash"], password)
        except VerifyMismatchError:
            valid = False
        if not valid:
            flash("Invalid username or master password.")
            return render_template("login.html")
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = username
        session.permanent = True
        return redirect(url_for("vault"))
    return render_template("login.html")

@app.route("/vault")
def vault():
    if "user_id" not in session:
        return redirect(url_for("login"))
    rows = get_db().execute(
        "SELECT id, encrypted_payload, created_at FROM vault_entries WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("vault.html", entries=rows)

@app.route("/api/entries", methods=["POST"])
def add_entry():
    if "user_id" not in session:
        return jsonify(error="Authentication required"), 401
    payload = request.get_json(silent=True) or {}
    encrypted_payload = payload.get("encrypted_payload")
    if not isinstance(encrypted_payload, str) or not encrypted_payload or len(encrypted_payload) > 100000:
        return jsonify(error="Invalid encrypted payload"), 400
    cursor = get_db().execute(
        "INSERT INTO vault_entries (user_id, encrypted_payload) VALUES (?, ?)",
        (session["user_id"], encrypted_payload)
    )
    get_db().commit()
    return jsonify(id=cursor.lastrowid), 201

@app.route("/api/entries/<int:entry_id>", methods=["DELETE"])
def delete_entry(entry_id):
    if "user_id" not in session:
        return jsonify(error="Authentication required"), 401
    cursor = get_db().execute(
        "DELETE FROM vault_entries WHERE id = ? AND user_id = ?",
        (entry_id, session["user_id"])
    )
    get_db().commit()
    if cursor.rowcount == 0:
        return jsonify(error="Entry not found"), 404
    return jsonify(ok=True)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
