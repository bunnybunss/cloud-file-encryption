import os
import sqlite3
import uuid
import datetime
import hashlib


from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, send_from_directory
)
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# ─── App Setup ────────────────────────────────────────────────────────────────

load_dotenv()  # Load SECRET_KEY & JWT_SECRET_KEY from .env

app = Flask(__name__)
CORS(app)

app.config.update({
    "SECRET_KEY":         os.getenv("SECRET_KEY", "your-secret-key"),
    "JWT_SECRET_KEY":     os.getenv("JWT_SECRET_KEY", "super-secret-key"),
    "JWT_TOKEN_LOCATION": ["headers"],
    "JWT_HEADER_NAME":    "x-access-token",
    "JWT_HEADER_TYPE":    "",
    "UPLOAD_FOLDER":      os.path.join(os.getcwd(), "uploads")
})
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

jwt = JWTManager(app)


# ─── Database Helpers ────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_email(email: str):
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    return dict(row) if row else None

def derive_key(password: str) -> bytes:
    # Derive a 256-bit key from the password
    salt = b"fixed-salt"
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=32)


# ─── Public Page Routes (no JWT required) ──────────────────────────────────

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json()
    email = data.get("email", "").strip().lower()
    pw    = data.get("password", "")

    user = get_user_by_email(email)
    if not user or not check_password_hash(user["password_hash"], pw):
        return jsonify(success=False, message="Invalid credentials"), 401

    token = create_access_token(identity=email)
    return jsonify(success=True, token=token)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    data     = request.get_json()
    email    = data.get("email", "").strip().lower()   # Fixed .strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify(success=False, message="Email and password required"), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, generate_password_hash(password))
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(success=False, message="Email already registered"), 400

    return jsonify(success=True)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/encrypt", methods=["GET"])
def encrypt_page():
    return render_template("encrypt.html")

@app.route("/decrypt", methods=["GET"])
def decrypt_page():
    return render_template("decrypt.html")

@app.route("/share", methods=["GET"])
def share_page():
    return render_template("share.html")


# ─── Protected API Endpoints ────────────────────────────────────────────────

@app.route("/encrypt", methods=["POST"])
@jwt_required()
def encrypt_file():
    f  = request.files.get("file")
    pw = request.form.get("password", "")
    if not f or not pw:
        return jsonify(success=False, message="File + password required"), 400

    # Save incoming file
    orig_name = f.filename
    safe_name = uuid.uuid4().hex + "__" + secure_filename(orig_name)
    path_orig = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    f.save(path_orig)

    # Read & encrypt
    plaintext = open(path_orig, "rb").read()
    key       = derive_key(pw)
    aesgcm    = AESGCM(key)
    nonce     = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    enc_name = safe_name + ".enc"
    with open(os.path.join(app.config["UPLOAD_FOLDER"], enc_name), "wb") as out:
        out.write(nonce + ciphertext)

    return jsonify(success=True, encrypted=enc_name)

@app.route("/decrypt", methods=["POST"])
@jwt_required()
def decrypt_file():
    f  = request.files.get("file")
    pw = request.form.get("password", "")
    if not f or not pw:
        return jsonify(success=False, message="File + password required"), 400

    filename = secure_filename(f.filename)
    path_enc  = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    f.save(path_enc)

    data      = open(path_enc, "rb").read()
    nonce, ct = data[:12], data[12:]

    key    = derive_key(pw)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        return jsonify(success=False, message="Decryption failed"), 400

    dec_name = filename.replace(".enc", "")
    with open(os.path.join(app.config["UPLOAD_FOLDER"], dec_name), "wb") as out:
        out.write(pt)

    return jsonify(success=True, decrypted=dec_name)

@app.route("/share", methods=["POST"])
@jwt_required()
def create_share():
    f      = request.files.get("file")
    pw     = request.form.get("password", "")
    expiry = request.form.get("expiry", type=int)

    if not f or not pw or not expiry:
        return jsonify(success=False, message="File, password & expiry required"), 400

    # Save the file
    filename  = secure_filename(f.filename)
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    f.save(save_path)

    # Hash password and set expiry
    pwd_hash   = hashlib.sha256(pw.encode()).hexdigest()
    expires_at = (datetime.datetime.utcnow()
                  + datetime.timedelta(minutes=expiry)
                 ).isoformat()

    # Insert share record
    token = uuid.uuid4().hex
    db = get_db()
    db.execute(
        "INSERT INTO shares (token, filename, pwd_hash, expires_at) VALUES (?,?,?,?)",
        (token, filename, pwd_hash, expires_at)
    )
    db.commit()

    link = url_for("access_share", token=token, _external=True)
    return jsonify(success=True, link=link)

@app.route("/share/<token>", methods=["GET", "POST"])
def access_share(token):
    row = get_db().execute(
        "SELECT filename, pwd_hash, expires_at FROM shares WHERE token = ?",
        (token,)
    ).fetchone()
    if not row:
        return render_template("access_share.html", error="Invalid link")

    if request.method == "POST":
        pw = request.form.get("password", "")
        if not pw:
            return render_template("access_share.html", error="Password required")

        now_iso = datetime.datetime.utcnow().isoformat()
        if now_iso > row["expires_at"]:
            return render_template("access_share.html", error="Link expired")

        if hashlib.sha256(pw.encode()).hexdigest() != row["pwd_hash"]:
            return render_template("access_share.html", error="Incorrect password")

        # All good—send the file
        return send_from_directory(
            app.config["UPLOAD_FOLDER"],
            row["filename"],
            as_attachment=True
        )

    # GET: show password form
    return render_template("access_share.html", filename=row["filename"])


# ─── Static File Serving ────────────────────────────────────────────────────

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True
    )

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    traceback.print_exc()
    return jsonify({"success": False, "message": str(e)}), 500


# ─── Run Server ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)
