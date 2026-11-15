import os, json, sqlite3, secrets, uuid, base64, logging
from logging.handlers import RotatingFileHandler
from io import BytesIO
from pathlib import Path
from datetime import timedelta, datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g, send_file, has_request_context
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_wtf.csrf import CSRFProtect, CSRFError
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

# Security logs are stored outside the web root and contain event metadata only.
# Passwords, session cookies, encryption keys, and vault contents are never logged.
SECURITY_LOG_PATH = os.path.join(INSTANCE_DIR, "security.log")


class SecurityJsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": getattr(record, "event", "application_event"),
            "message": record.getMessage(),
        }
        for field in ("remote_addr", "user_id", "path"):
            value = getattr(record, field, None)
            if value is not None:
                entry[field] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


security_logger = logging.getLogger("password_manager.security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

if not any(
    isinstance(handler, RotatingFileHandler)
    and getattr(handler, "baseFilename", None) == os.path.abspath(SECURITY_LOG_PATH)
    for handler in security_logger.handlers
):
    security_handler = RotatingFileHandler(
        SECURITY_LOG_PATH, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    security_handler.setFormatter(SecurityJsonFormatter())
    security_logger.addHandler(security_handler)
    os.chmod(SECURITY_LOG_PATH, 0o600)


def log_security_event(level, event):
    """Write a metadata-only security event; never pass secrets or user content."""
    details = {
        "event": event,
        "remote_addr": request.remote_addr if has_request_context() else None,
        "user_id": session.get("user_id") if has_request_context() else None,
        "path": request.path if has_request_context() else None,
    }
    security_logger.log(level, event, extra=details)



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


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    log_security_event(logging.WARNING, "csrf_validation_failed")
    if request.path.startswith("/api/"):
        return jsonify(error="Request could not be verified"), 400
    return "Request could not be verified. Refresh the page and try again.", 400


@app.errorhandler(404)
def handle_not_found(_error):
    return "The requested resource was not found.", 404


@app.errorhandler(413)
def handle_request_too_large(_error):
    log_security_event(logging.WARNING, "request_size_limit_exceeded")
    return "The uploaded request is too large.", 413


@app.errorhandler(429)
def handle_rate_limit(_error):
    log_security_event(logging.WARNING, "rate_limit_exceeded")
    return "Too many requests. Please wait and try again.", 429


@app.errorhandler(500)
def handle_internal_error(error):
    original = getattr(error, "original_exception", None)
    if original is not None:
        security_logger.error(
            "unhandled_application_exception",
            extra={
                "event": "unhandled_application_exception",
                "remote_addr": request.remote_addr if has_request_context() else None,
                "user_id": session.get("user_id") if has_request_context() else None,
                "path": request.path if has_request_context() else None,
            },
            exc_info=(type(original), original, original.__traceback__),
        )
    else:
        log_security_event(logging.ERROR, "internal_server_error")
    return "An internal error occurred. Please try again later.", 500


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if (
            not 3 <= len(username) <= 80
            or not all(
                ch.isascii() and (ch.isalnum() or ch in "_.-")
                for ch in username
            )
        ):
            flash("Username must be 3-80 characters and contain only letters, numbers, dots, underscores, or hyphens.")
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
            log_security_event(logging.WARNING, "registration_duplicate_username")
            flash("That username is already registered.")
            return render_template("register.html")
        log_security_event(logging.INFO, "account_registered")
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
            log_security_event(logging.WARNING, "login_failed")
            flash("Invalid username or master password.")
            return render_template("login.html")
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = username
        session.permanent = True
        log_security_event(logging.INFO, "login_succeeded")
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
    log_security_event(logging.INFO, "vault_entry_created")
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
        log_security_event(logging.WARNING, "vault_entry_delete_not_found_or_not_owned")
        return jsonify(error="Entry not found"), 404
    log_security_event(logging.INFO, "vault_entry_deleted")
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
    log_security_event(logging.INFO, "file_uploaded_and_encrypted")
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
        log_security_event(logging.WARNING, "file_download_not_found_or_not_owned")
        return "File not found", 404
    log_security_event(logging.INFO, "file_downloaded")
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
        log_security_event(logging.WARNING, "file_delete_not_found_or_not_owned")
        return "File not found", 404
    log_security_event(logging.INFO, "file_deleted")
    flash("Encrypted file deleted.")
    return redirect(url_for("vault"))


@app.route("/logout", methods=["POST"])
def logout():
    log_security_event(logging.INFO, "user_logged_out")
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    # Werkzeug creates a temporary self-signed certificate for local HTTPS.
    app.run(host="127.0.0.1", port=5000, debug=False, ssl_context="adhoc")
