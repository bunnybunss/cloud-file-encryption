import os
import sqlite3
import logging
import datetime
import traceback
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, g, request, jsonify, send_from_directory
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from secure_crypto.secure_crypto import encrypt_file, decrypt_file
import jwt
from cryptography.exceptions import InvalidTag

# ─── Load .env ────────────────────────────────────────────────────────────────
load_dotenv()  # Populates os.environ from .env

# ─── App Configuration ────────────────────────────────────────────────────────
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY']         = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER']      = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 50 * 1024**2))
ALLOWED_EXTENSIONS               = set(os.getenv('ALLOWED_EXTENSIONS', '').split(','))

print("🔑 SECRET_KEY is:", app.config['SECRET_KEY'])

# Ensure upload folder exists
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Database Helpers ─────────────────────────────────────────────────────────
DATABASE = Path(__file__).parent / 'users.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

# ─── Utility Functions ────────────────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS

# ─── JWT Decorator ────────────────────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user = payload['user']
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 403
        return f(*args, **kwargs)
    return decorated

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.route('/signup', methods=['POST'])
def signup_post():
    data     = request.form or request.get_json(silent=True) or {}
    email    = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    db = get_db()
    c  = db.cursor()
    c.execute("SELECT id FROM users WHERE email = ?", (email,))
    if c.fetchone():
        return jsonify({'success': False, 'message': 'User already exists'}), 409

    hashed = generate_password_hash(password)
    c.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hashed))
    db.commit()
    return jsonify({'success': True, 'message': 'Account created'}), 201

@app.route('/login', methods=['POST'])
def login():
    try:
        data     = request.get_json(silent=True) or request.form
        email    = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400

        db = get_db()
        c  = db.cursor()
        c.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        if not row or not check_password_hash(row['password_hash'], password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        sk = app.config.get('SECRET_KEY')
        token = jwt.encode({
            'user': email,
            'exp':  datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, sk, algorithm='HS256')

        return jsonify({'success': True, 'token': token}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/encrypt', methods=['POST'])
@token_required
def encrypt_file_route():
    if 'file' not in request.files or 'password' not in request.form:
        return jsonify({'success': False, 'message': 'Missing file or password'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'Invalid file'}), 400

    filename = secure_filename(file.filename)
    filepath = Path(app.config['UPLOAD_FOLDER']) / filename
    file.save(filepath)

    encrypted_path = encrypt_file(str(filepath), request.form['password'])
    return jsonify({'success': True, 'encrypted': Path(encrypted_path).name}), 200

@app.route('/decrypt', methods=['POST'])
@token_required
def decrypt_file_route():
    if 'file' not in request.files or 'password' not in request.form:
        return jsonify({'success': False, 'message': 'Missing file or password'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'Invalid file'}), 400

    filename = secure_filename(file.filename)
    filepath = Path(app.config['UPLOAD_FOLDER']) / filename
    file.save(filepath)

    try:
        decrypted_path = decrypt_file(str(filepath), request.form['password'])
    except InvalidTag:
        return jsonify({
            'success': False,
            'message': 'Decryption failed: wrong password or corrupted file'
        }), 400

    return jsonify({'success': True, 'decrypted': Path(decrypted_path).name}), 200

# ─── Error Handlers ──────────────────────────────────────────────────────────
@app.errorhandler(413)
def file_too_large(e):
    return jsonify({'success': False, 'message': 'File too large'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'message': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logger.exception(e)
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

# ─── Run Server ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(port=5001, debug=True)
