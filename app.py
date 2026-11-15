import os, json, sqlite3, secrets, uuid, base64
from io import BytesIO
from pathlib import Path
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g, send_file
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(INSTANCE_DIR, "password_manager.db")
FILES_DIR = os.path.join(INSTANCE_DIR, "encrypted_files")
FILE_KEY_PATH = os.path.join(INSTANCE_DIR, ".file_encryption_key")
os.makedirs(INSTANCE_DIR, mode=0o700, exist_ok=True)
os.makedirs(FILES_DIR, mode=0o700, exist_ok=True)
app_max_upload_bytes = 10 * 1024 * 1024

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
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=app_max_upload_bytes,
)
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
)

hasher = PasswordHasher()

# The server-side file-encryption key is generated once and kept outside the web root.
# Losing this key makes previously uploaded files unrecoverable.
if not os.path.exists(FILE_KEY_PATH):
    with open(FILE_KEY_PATH, "wb") as key_file:
        key_file.write(Fernet.generate_key())
    os.chmod(FILE_KEY_PATH, 0o600)
with open(FILE_KEY_PATH, "rb") as key_file:
    file_cipher = Fernet(key_file.read().strip())


def user_files_dir(user_id):
    path = os.path.join(FILES_DIR, str(int(user_id)))
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def get_user_files(user_id):
    files = []
    for path in Path(user_files_dir(user_id)).glob("*.enc"):
        try:
            file_id = path.stem
            if len(file_id) != 32:
                continue
            data = json.loads(file_cipher.decrypt(path.read_bytes()).decode("utf-8"))
            files.append({"id": file_id, "filename": data["filename"], "size": len(base64.b64decode(data["content"]))})
        except (InvalidToken, ValueError, KeyError, OSError):
            continue
    return sorted(files, key=lambda item: item["filename"].lower())

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
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
@limiter.limit("5 per minute", methods=["POST"])
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
    return render_template("vault.html", entries=rows, files=get_user_files(session["user_id"]))

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

@app.route("/files", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return redirect(url_for("login"))
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        flash("Choose a file to encrypt and upload.")
        return redirect(url_for("vault"))
    original_name = secure_filename(uploaded.filename) or "uploaded-file"
    content = uploaded.read(app_max_upload_bytes + 1)
    if not content or len(content) > app_max_upload_bytes:
        flash("The file must be non-empty and no larger than 10 MB.")
        return redirect(url_for("vault"))
    file_id = uuid.uuid4().hex
    encrypted = file_cipher.encrypt(json.dumps({
        "filename": original_name,
        "content": base64.b64encode(content).decode("ascii")
    }).encode("utf-8"))
    destination = os.path.join(user_files_dir(session["user_id"]), file_id + ".enc")
    with open(destination, "xb") as encrypted_file:
        encrypted_file.write(encrypted)
    os.chmod(destination, 0o600)
    flash("File encrypted on the server and saved.")
    return redirect(url_for("vault"))


@app.route("/files/<file_id>/download", methods=["GET"])
def download_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if len(file_id) != 32 or any(ch not in "0123456789abcdef" for ch in file_id):
        return "File not found", 404
    path = os.path.join(user_files_dir(session["user_id"]), file_id + ".enc")
    try:
        data = json.loads(file_cipher.decrypt(Path(path).read_bytes()).decode("utf-8"))
        content = base64.b64decode(data["content"], validate=True)
    except (OSError, InvalidToken, ValueError, KeyError):
        return "File not found", 404
    return send_file(BytesIO(content), as_attachment=True, download_name=data["filename"], mimetype="application/octet-stream")


@app.route("/files/<file_id>/delete", methods=["POST"])
def delete_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if len(file_id) != 32 or any(ch not in "0123456789abcdef" for ch in file_id):
        return "File not found", 404
    path = os.path.join(user_files_dir(session["user_id"]), file_id + ".enc")
    try:
        os.remove(path)
    except FileNotFoundError:
        return "File not found", 404
    flash("Encrypted file deleted.")
    return redirect(url_for("vault"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    # Werkzeug creates a temporary self-signed certificate for local HTTPS.
    app.run(host="127.0.0.1", port=5000, debug=False, ssl_context="adhoc")
