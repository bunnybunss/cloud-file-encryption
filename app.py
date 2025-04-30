#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────────────
#  Secure-Cloud-App · Flask backend
#  – Signup / Login (JWT) · AES file-encryption endpoints
#  – GET views for login & signup pages so links work in browser
# ──────────────────────────────────────────────────────────────────────────────
import os, sqlite3, logging, datetime, traceback, jwt
from functools import wraps
from pathlib import Path

from flask import (
    Flask, g, request, jsonify, render_template, send_from_directory
)
from werkzeug.utils      import secure_filename
from werkzeug.security   import generate_password_hash, check_password_hash
from dotenv              import load_dotenv
from cryptography.exceptions import InvalidTag

from secure_crypto.secure_crypto import encrypt_file, decrypt_file

# ─── Load .env ────────────────────────────────────────────────────────────────
load_dotenv()                                              # fills os.environ

# ─── App object & config ─────────────────────────────────────────────────────
app = Flask(__name__, instance_relative_config=True)

app.config.update(
    SECRET_KEY          = os.getenv('SECRET_KEY',   'dev-secret'),
    UPLOAD_FOLDER       = os.getenv('UPLOAD_FOLDER', 'uploads'),
    MAX_CONTENT_LENGTH  = int(os.getenv('MAX_CONTENT_LENGTH', 50 * 1024**2)),
)
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'txt,png,jpg,pdf,enc')
                         .split(','))

Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True, parents=True)

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ─── Database helpers ────────────────────────────────────────────────────────
DATABASE = Path(__file__).with_name('users.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    db = g.pop('db', None)
    if db:
        db.close()

# ─── Utility ─────────────────────────────────────────────────────────────────
def allowed_file(fname: str) -> bool:
    return '.' in fname and fname.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS

# ─── JWT decorator ───────────────────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def _wrap(*a, **kw):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify(success=False, message='Token missing'), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = payload['user']
        except jwt.ExpiredSignatureError:
            return jsonify(success=False, message='Token expired'), 403
        except jwt.InvalidTokenError:
            return jsonify(success=False, message='Invalid token'), 403
        return f(*a, **kw)
    return _wrap

# ╭───────────────────────────  PUBLIC PAGES  ───────────────────────────────╮
@app.route('/')
def home():                       return render_template('index.html')

@app.route('/login',  methods=['GET'])
def login_page():                 return render_template('login.html')

@app.route('/signup', methods=['GET'])
def signup_page():                return render_template('signup.html')
# ╰───────────────────────────────────────────────────────────────────────────╯

# ─── Auth API (POST) ─────────────────────────────────────────────────────────
@app.route('/signup', methods=['POST'])
def signup_post():
    data = request.form or request.get_json(silent=True) or {}
    email, password = data.get('email'), data.get('password')
    if not (email and password):
        return jsonify(success=False, message='Email and password required'), 400

    db = get_db()
    if db.execute('SELECT 1 FROM users WHERE email=?', (email,)).fetchone():
        return jsonify(success=False, message='User exists'), 409

    db.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)',
               (email, generate_password_hash(password)))
    db.commit()
    return jsonify(success=True, message='Account created'), 201

@app.route('/login', methods=['POST'])
def login_post():
    try:
        data = request.get_json(silent=True) or request.form
        email, password = data.get('email'), data.get('password')
        if not (email and password):
            return jsonify(success=False, message='Email and password required'), 400

        row = get_db().execute('SELECT password_hash FROM users WHERE email=?',
                               (email,)).fetchone()
        if not row or not check_password_hash(row['password_hash'], password):
            return jsonify(success=False, message='Invalid credentials'), 401

        token = jwt.encode({
            'user': email,
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify(success=True, token=token), 200

    except Exception as e:
        logger.exception(e)
        return jsonify(success=False, message=str(e)), 500

# ─── Encryption API ─────────────────────────────────────────────────────────
@app.route('/encrypt', methods=['POST'])
@token_required
def encrypt_route():
    if 'file' not in request.files or 'password' not in request.form:
        return jsonify(success=False, message='Missing file or password'), 400

    file = request.files['file']
    if not file.filename or not allowed_file(file.filename):
        return jsonify(success=False, message='Invalid file'), 400

    fp = Path(app.config['UPLOAD_FOLDER']) / secure_filename(file.filename)
    file.save(fp)
    enc_path = encrypt_file(str(fp), request.form['password'])
    return jsonify(success=True, encrypted=Path(enc_path).name), 200

@app.route('/decrypt', methods=['POST'])
@token_required
def decrypt_route():
    if 'file' not in request.files or 'password' not in request.form:
        return jsonify(success=False, message='Missing file or password'), 400

    file = request.files['file']
    if not file.filename or not allowed_file(file.filename):
        return jsonify(success=False, message='Invalid file'), 400

    fp = Path(app.config['UPLOAD_FOLDER']) / secure_filename(file.filename)
    file.save(fp)
    try:
        dec_path = decrypt_file(str(fp), request.form['password'])
    except InvalidTag:
        return jsonify(success=False,
                       message='Wrong password or corrupted file'), 400
    return jsonify(success=True, decrypted=Path(dec_path).name), 200

# ─── Tiny helpers ────────────────────────────────────────────────────────────
@app.route('/favicon.ico')                # stop 404 spam in logs
def favicon(): return send_from_directory('static', 'favicon.ico')

@app.errorhandler(413)  # file too large
def too_large(_):       return jsonify(success=False, message='File too large'), 413

@app.errorhandler(404)
def not_found(_):       return jsonify(success=False, message='Not found'), 404

@app.errorhandler(500)
def server_err(e):
    logger.exception(e)
    return jsonify(success=False, message='Internal error'), 500

# ─── Run local dev server ────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(port=5001, debug=True)
