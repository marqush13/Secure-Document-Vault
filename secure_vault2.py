# Secure Document Vault - PKI-Based File Storage System
import os
import json
import hashlib
import base64
import datetime
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, render_template_string, session, send_file
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography import x509
from cryptography.x509.oid import NameOID
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
# Configure file-based sessions (removing Redis dependency)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_DIR'] = '/app/sessions'

# Configuration
UPLOAD_FOLDER = '/app/vault_files'
DATABASE_FILE = '/app/db/vault.db'  # Path inside Docker container
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE_FILE), exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            certificate TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS revoked_certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            certificate_serial TEXT NOT NULL,
            revocation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reason TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# PKI Functions (unchanged)
class PKIManager:
    @staticmethod
    def generate_key_pair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def create_certificate(private_key, public_key, username, email):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Secure"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Vault"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Document Vault"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            public_key).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.now()).not_valid_after(
            datetime.datetime.now() + datetime.timedelta(days=365)).add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False).sign(
            private_key, hashes.SHA256())
        return cert
    
    @staticmethod
    def sign_data(private_key, data):
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def verify_signature(public_key, data, signature):
        try:
            signature_bytes = base64.b64decode(signature)
            public_key.verify(
                signature_bytes,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def encrypt_data(public_key, data):
        from cryptography.fernet import Fernet
        symmetric_key = Fernet.generate_key()
        fernet = Fernet(symmetric_key)
        encrypted_data = fernet.encrypt(data)
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        result = base64.b64encode(encrypted_key).decode() + '|||' + base64.b64encode(encrypted_data).decode()
        return result
    
    @staticmethod
    def decrypt_data(private_key, encrypted_data):
        from cryptography.fernet import Fernet
        parts = encrypted_data.split('|||')
        encrypted_key = base64.b64decode(parts[0])
        encrypted_content = base64.b64decode(parts[1])
        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        fernet = Fernet(symmetric_key)
        decrypted_data = fernet.decrypt(encrypted_content)
        return decrypted_data

# Utility functions
def log_audit(user_id, action, details=None, ip_address=None):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
        (user_id, action, details, ip_address)
    )
    conn.commit()
    conn.close()

def get_user_by_email(email):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

# CRL check
def is_certificate_revoked(user_id, certificate):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cert = x509.load_pem_x509_certificate(certificate.encode())
    serial = str(cert.serial_number)
    cursor.execute(
        'SELECT 1 FROM revoked_certificates WHERE user_id = ? AND certificate_serial = ?',
        (user_id, serial)
    )
    result = cursor.fetchone()
    conn.close()
    return bool(result)

# Routes
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        if not all([username, email, password]):
            return jsonify({'error': 'All fields required'}), 400
        # Password strength validation
        if len(password) < 12 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password) or not any(c in '!@#$%^&*' for c in password):
            return jsonify({'error': 'Password must be at least 12 characters long and include uppercase, numbers, and special characters'}), 400
        if get_user_by_email(email):
            return jsonify({'error': 'Email already exists'}), 400
        private_key, public_key = PKIManager.generate_key_pair()
        certificate = PKIManager.create_certificate(private_key, public_key, username, email)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, public_key, certificate) VALUES (?, ?, ?, ?, ?)',
            (username, email, generate_password_hash(password), public_pem, cert_pem)
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        log_audit(user_id, 'USER_REGISTERED', f'User {username} registered', request.remote_addr)
        return jsonify({
            'message': 'Registration successful',
            'private_key': private_pem,
            'certificate': cert_pem
        })
    except Exception as e:
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not all([email, password]):
            return jsonify({'error': 'Email and password required'}), 400
        user = get_user_by_email(email)
        if not user or not check_password_hash(user[3], password):
            log_audit(None, 'LOGIN_FAILED', f'Failed login attempt for {email}', request.remote_addr)
            return jsonify({'error': 'Invalid credentials'}), 401
        if not user[7]:
            return jsonify({'error': 'Account disabled'}), 403
        if is_certificate_revoked(user[0], user[5]):
            log_audit(user[0], 'LOGIN_FAILED', f'Revoked certificate for {email}', request.remote_addr)
            return jsonify({'error': 'Certificate revoked'}), 403
        session['user_id'] = user[0]
        session['email'] = user[1]
        session.permanent = True
        log_audit(user[0], 'USER_LOGIN', f'User {email} logged in', request.remote_addr)
        return jsonify({
            'message': 'Login successful',
            'email': email,
            'certificate': user[5]
        })
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_audit(user_id, 'USER_LOGOUT', 'User logged out', request.remote_addr)
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        file = request.files['file']
        private_key_file = request.files.get('private_key_file')
        private_key_pem = request.form.get('private_key')
        
        if not file.filename:
            return jsonify({'error': 'File required'}), 400
        if not private_key_file and not private_key_pem:
            return jsonify({'error': 'Private key or private key file required'}), 400
        
        # Read private key from file if provided, otherwise use text input
        if private_key_file:
            private_key_pem = private_key_file.read().decode('utf-8')
        
        # Read file data in chunks to handle large files
        file_data = file.read(MAX_FILE_SIZE + 1)
        if len(file_data) > MAX_FILE_SIZE:
            return jsonify({'error': f'File too large, max size is {MAX_FILE_SIZE // (1024 * 1024)}MB'}), 400
        
        try:
            private_key = load_pem_private_key(private_key_pem.encode(), password=None)
        except Exception as e:
            return jsonify({'error': f'Invalid private key: {str(e)}'}), 400
        
        public_key = private_key.public_key()
        file_hash = hashlib.sha256(file_data).hexdigest()
        signature = PKIManager.sign_data(private_key, file_data)
        encrypted_data = PKIManager.encrypt_data(public_key, file_data)
        
        secure_name = secure_filename(file.filename)
        unique_filename = f"{session['user_id']}_{secrets.token_hex(16)}_{secure_name}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Write encrypted data in binary mode
        with open(file_path, 'wb') as f:
            f.write(encrypted_data.encode())  # Encode string to bytes
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO files (user_id, filename, original_filename, file_hash, signature, file_size) VALUES (?, ?, ?, ?, ?, ?)',
            (session['user_id'], unique_filename, file.filename, file_hash, signature, len(file_data))
        )
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'FILE_UPLOADED', f'File {file.filename} uploaded', request.remote_addr)
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'filename': file.filename,
            'hash': file_hash
        })
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/files', methods=['GET'])
def list_files():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, original_filename, file_size, upload_time, file_hash FROM files WHERE user_id = ? ORDER BY upload_time DESC',
            (session['user_id'],)
        )
        files = cursor.fetchall()
        conn.close()
        file_list = [{
            'id': f[0],
            'name': f[1],
            'size': f[2],
            'upload_time': f[3],
            'hash': f[4]
        } for f in files]
        return jsonify({'files': file_list})
    except Exception as e:
        return jsonify({'error': 'Failed to list files'}), 500

@app.route('/api/download/<int:file_id>', methods=['POST'])
def download_file(file_id):
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        data = request.get_json()
        private_key_pem = data.get('private_key')
        if not private_key_pem:
            return jsonify({'error': 'Private key required'}), 400
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT filename, original_filename, file_hash, signature FROM files WHERE id = ? AND user_id = ?',
            (file_id, session['user_id'])
        )
        file_info = cursor.fetchone()
        conn.close()
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        filename, original_filename, file_hash, signature = file_info
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on disk'}), 404
        private_key = load_pem_private_key(private_key_pem.encode(), password=None)
        public_key = private_key.public_key()
        with open(file_path, 'rb') as f:
            encrypted_data = f.read().decode()  # Decode bytes to string
        decrypted_data = PKIManager.decrypt_data(private_key, encrypted_data)
        if not PKIManager.verify_signature(public_key, decrypted_data, signature):
            log_audit(session['user_id'], 'SIGNATURE_VERIFICATION_FAILED', f'File {original_filename}', request.remote_addr)
            return jsonify({'error': 'Signature verification failed'}), 400
        current_hash = hashlib.sha256(decrypted_data).hexdigest()
        if current_hash != file_hash:
            log_audit(session['user_id'], 'INTEGRITY_CHECK_FAILED', f'File {original_filename}', request.remote_addr)
            return jsonify({'error': 'File integrity check failed'}), 400
        log_audit(session['user_id'], 'FILE_DOWNLOADED', f'File {original_filename} downloaded', request.remote_addr)
        return jsonify({
            'filename': original_filename,
            'data': base64.b64encode(decrypted_data).decode(),
            'verified': True
        })
    except Exception as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/delete/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT filename, original_filename FROM files WHERE id = ? AND user_id = ?',
            (file_id, session['user_id'])
        )
        file_info = cursor.fetchone()
        if not file_info:
            conn.close()
            return jsonify({'error': 'File not found'}), 404
        filename, original_filename = file_info
        cursor.execute('DELETE FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
        conn.commit()
        conn.close()
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        log_audit(session['user_id'], 'FILE_DELETED', f'File {original_filename} deleted', request.remote_addr)
        return jsonify({'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'error': 'Delete failed'}), 500

@app.route('/api/audit-logs', methods=['GET'])
def get_audit_logs():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT action, details, timestamp, ip_address FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50',
            (session['user_id'],)
        )
        logs = cursor.fetchall()
        conn.close()
        log_list = [{
            'action': log[0],
            'details': log[1],
            'timestamp': log[2],
            'ip_address': log[3]
        } for log in logs]
        return jsonify({'logs': log_list})
    except Exception as e:
        return jsonify({'error': 'Failed to fetch logs'}), 500

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Document Vault</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .vault-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem 0; }
        .file-item { border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; transition: all 0.3s ease; }
        .file-item:hover { box-shadow: 0 4px 8px rgba(0,0,0,0.1); transform: translateY(-2px); }
        .key-display { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 1rem; font-family: monospace; font-size: 0.8rem; max-height: 200px; overflow-y: auto; word-break: break-all; }
        .audit-log { background: #f8f9fa; border-left: 4px solid #007bff; padding: 0.5rem 1rem; margin-bottom: 0.5rem; }
        .security-indicator { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
        .security-high { background: #d1ecf1; color: #0c5460; }
        .security-verified { background: #d4edda; color: #155724; }
        #previewModal .modal-dialog { max-width: 80%; }
        #preview-content { max-height: 70vh; overflow: auto; }
    </style>
</head>
<body>
    <div class="vault-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1><i class="fas fa-shield-alt"></i> Secure Document Vault</h1>
                    <p class="mb-0">PKI-Based End-to-End Encrypted File Storage</p>
                </div>
                <div class="col-md-4 text-end">
                    <div id="user-info" style="display: none;">
                        <span id="email-display"></span>
                        <button class="btn btn-outline-light btn-sm ms-2" onclick="logout()">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container mt-4">
        <div id="auth-section">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <ul class="nav nav-tabs card-header-tabs" role="tablist">
                                <li class="nav-item">
                                    <a class="nav-link active" data-bs-toggle="tab" href="#login-tab">Login</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" data-bs-toggle="tab" href="#register-tab">Register</a>
                                </li>
                            </ul>
                        </div>
                        <div class="card-body">
                            <div class="tab-content">
                                <div class="tab-pane fade show active" id="login-tab">
                                    <form id="login-form">
                                        <div class="mb-3">
                                            <label class="form-label">Email</label>
                                            <input type="email" class="form-control" id="login-email" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Password</label>
                                            <input type="password" class="form-control" id="login-password" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">
                                            <i class="fas fa-sign-in-alt"></i> Login
                                        </button>
                                    </form>
                                </div>
                                <div class="tab-pane fade" id="register-tab">
                                    <form id="register-form">
                                        <div class="mb-3">
                                            <label class="form-label">Username</label>
                                            <input type="text" class="form-control" id="register-username" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Email</label>
                                            <input type="email" class="form-control" id="register-email" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Password</label>
                                            <input type="password" class="form-control" id="register-password" required>
                                            <div class="form-text">Must be 12+ characters with uppercase, numbers, and special characters.</div>
                                        </div>
                                        <button type="submit" class="btn btn-success w-100">
                                            <i class="fas fa-user-plus"></i> Register
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="app-section" style="display: none;">
            <div class="row">
                <div class="col-md-8">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5><i class="fas fa-upload"></i> Upload File</h5>
                        </div>
                        <div class="card-body">
                            <form id="upload-form" enctype="multipart/form-data">
                                <div class="mb-3">
                                    <label class="form-label">Select File</label>
                                    <input type="file" class="form-control" id="file-input" required>
                                    <div class="form-text">Maximum file size: 50MB</div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Private Key (for signing)</label>
                                    <textarea class="form-control key-display" id="private-key-upload" rows="6" placeholder="Paste your private key here..."></textarea>
                                    <div class="form-text">Or upload a private key file:</div>
                                    <input type="file" class="form-control mt-2" id="private-key-file" accept=".pem,.txt">
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-shield-alt"></i> Encrypt & Upload
                                </button>
                            </form>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5><i class="fas fa-folder"></i> My Files</h5>
                            <button class="btn btn-sm btn-outline-primary" onclick="loadFiles()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                        </div>
                        <div class="card-body">
                            <div id="files-list"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h6><i class="fas fa-key"></i> Key Management</h6>
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label class="form-label">Your Certificate</label>
                                <div class="key-display" id="certificate-display"></div>
                            </div>
                            <div class="security-indicator security-high">
                                <i class="fas fa-shield-alt"></i> RSA 2048-bit Encryption
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="fas fa-history"></i> Audit Trail</h6>
                        </div>
                        <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                            <div id="audit-logs"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="downloadModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-download"></i> Download File</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> 
                        This file will be decrypted and signature verified before download.
                    </div>
                    <div id="download-error" class="alert alert-danger" style="display: none;"></div>
                    <div class="mb-3">
                        <label class="form-label">Private Key</label>
                        <textarea class="form-control key-display" id="download-private-key" rows="6" placeholder="Paste your private key here..."></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="confirm-download-btn">
                        <i class="fas fa-shield-alt"></i> Decrypt & Download
                    </button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="registrationModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title text-success">
                        <i class="fas fa-check-circle"></i> Registration Successful
                    </h5>
                </div>
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i>
                        <strong>Important:</strong> Save your private key and certificate securely. 
                        You cannot recover your files without them! Download them using the button below.
                    </div>
                    <div class="mb-3">
                        <label class="form-label"><strong>Your Certificate:</strong></label>
                        <div class="key-display" id="new-certificate"></div>
                        <button class="btn btn-sm btn-outline-primary mt-2" onclick="copyToClipboard('new-certificate')">
                            <i class="fas fa-copy"></i> Copy Certificate
                        </button>
                    </div>
                    <div class="mb-3">
                        <button class="btn btn-primary" onclick="exportKeys()">
                            <i class="fas fa-download"></i> Download Private Key & Certificate
                        </button>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-primary" data-bs-dismiss="modal">
                        I've Saved My Keys Securely
                    </button>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="previewModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-body">
                    <div id="preview-content"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentUser = null;
        let userCertificate = null;
        let downloadFileId = null;
        let previewFileId = null;
        let newPrivateKey = null; // Store private key temporarily for registration

        async function deriveKey(password, salt) {
            const enc = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
            );
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );
        }

        async function encryptKey(privateKey, password) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await deriveKey(password, salt);
            const enc = new TextEncoder();
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv }, key, enc.encode(privateKey)
            );
            return {
                encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
                salt: btoa(String.fromCharCode(...salt)),
                iv: btoa(String.fromCharCode(...iv))
            };
        }

        async function decryptKey(encryptedData, password) {
            const salt = Uint8Array.from(atob(encryptedData.salt), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
            const encrypted = Uint8Array.from(atob(encryptedData.encrypted), c => c.charCodeAt(0));
            const key = await deriveKey(password, salt);
            try {
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv }, key, encrypted
                );
                return new TextDecoder().decode(decrypted);
            } catch (e) {
                throw new Error('Invalid password or corrupted key');
            }
        }

        async function storeKeyLocally() {
            const privateKey = newPrivateKey; // Use stored private key
            const password = document.getElementById('key-password').value;
            if (!password) {
                showAlert('Please enter a password to encrypt your key', 'warning');
                return;
            }
            try {
                const encryptedKey = await encryptKey(privateKey, password);
                localStorage.setItem('vault_private_key', JSON.stringify(encryptedKey));
                showAlert('Private key stored securely in browser!', 'success');
            } catch (error) {
                showAlert('Failed to store key: ' + error.message, 'danger');
            }
        }

        async function exportKeys() {
            const certificate = document.getElementById('new-certificate').textContent;
            const blob = new Blob([`Private Key:\n${newPrivateKey}\n\nCertificate:\n${certificate}`], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${currentUser || 'user'}_vault_keys.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showAlert('Keys downloaded successfully!', 'success');
        }

        async function checkAuthStatus() {
            try {
                const response = await fetch('/api/files');
                if (response.ok) {
                    showApp();
                    loadFiles();
                    loadAuditLogs();
                }
            } catch (error) {
                console.log('Not authenticated');
            }
        }

        async function handleLogin(e) {
            e.preventDefault();
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await response.json();
                if (response.ok) {
                    currentUser = data.email;
                    userCertificate = data.certificate;
                    document.getElementById('email-display').textContent = currentUser;
                    document.getElementById('certificate-display').textContent = userCertificate;
                    showApp();
                    loadFiles();
                    loadAuditLogs();
                    showAlert('Login successful!', 'success');
                } else {
                    showAlert(data.error, 'danger');
                }
            } catch (error) {
                showAlert('Login failed: ' + error.message, 'danger');
            }
        }

        async function handleRegister(e) {
            e.preventDefault();
            const username = document.getElementById('register-username').value;
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            if (password.length < 12 || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[!@#$%^&*]/.test(password)) {
                showAlert('Password must be at least 12 characters long and include uppercase, numbers, and special characters', 'warning');
                return;
            }
            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password })
                });
                const data = await response.json();
                if (response.ok) {
                    currentUser = email;
                    newPrivateKey = data.private_key; // Store private key temporarily
                    document.getElementById('new-certificate').textContent = data.certificate;
                    const modal = new bootstrap.Modal(document.getElementById('registrationModal'));
                    modal.show();
                    document.getElementById('register-form').reset();
                    showAlert('Registration successful! Please download and save your keys securely.', 'success');
                } else {
                    showAlert(data.error, 'danger');
                }
            } catch (error) {
                showAlert('Registration failed: ' + error.message, 'danger');
            }
        }

        async function handleUpload(e) {
            e.preventDefault();
            const fileInput = document.getElementById('file-input');
            const privateKeyInput = document.getElementById('private-key-upload').value;
            const privateKeyFile = document.getElementById('private-key-file').files[0];
            let privateKey = privateKeyInput;

            // If a private key file is provided, read it
            if (privateKeyFile) {
                try {
                    privateKey = await new Promise((resolve, reject) => {
                        const reader = new FileReader();
                        reader.onload = () => resolve(reader.result);
                        reader.onerror = () => reject(new Error('Failed to read private key file'));
                        reader.readAsText(privateKeyFile);
                    });
                } catch (error) {
                    showAlert('Failed to read private key file: ' + error.message, 'danger');
                    return;
                }
            } else if (localStorage.getItem('vault_private_key')) {
                const password = prompt('Enter your key decryption password:');
                if (password) {
                    try {
                        const encryptedKey = JSON.parse(localStorage.getItem('vault_private_key'));
                        privateKey = await decryptKey(encryptedKey, password);
                    } catch (error) {
                        showAlert('Failed to decrypt key: ' + error.message, 'danger');
                        return;
                    }
                }
            }

            if (!fileInput.files[0] || (!privateKey.trim() && !privateKeyFile)) {
                showAlert('Please select a file and provide your private key (via text or file)', 'warning');
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            if (privateKeyFile) {
                formData.append('private_key_file', privateKeyFile);
            } else {
                formData.append('private_key', privateKey);
            }

            try {
                showAlert('Encrypting and uploading file...', 'info');
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                if (response.ok) {
                    showAlert(`File "${data.filename}" uploaded successfully!`, 'success');
                    document.getElementById('upload-form').reset();
                    loadFiles();
                    loadAuditLogs();
                } else {
                    showAlert(data.error, 'danger');
                }
            } catch (error) {
                showAlert('Upload failed: ' + error.message, 'danger');
            }
        }

        async function loadFiles() {
            try {
                const response = await fetch('/api/files');
                const data = await response.json();
                if (response.ok) {
                    displayFiles(data.files);
                } else {
                    showAlert(data.error, 'danger');
                }
            } catch (error) {
                showAlert('Failed to load files: ' + error.message, 'danger');
            }
        }

        function displayFiles(files) {
            const container = document.getElementById('files-list');
            if (files.length === 0) {
                container.innerHTML = '<p class="text-muted">No files uploaded yet.</p>';
                return;
            }
            let html = '';
            files.forEach(file => {
                const isPreviewable = /\.(png|jpg|jpeg|gif|pdf)$/i.test(file.name);
                html += `
                    <div class="file-item">
                        <div class="row align-items-center">
                            <div class="col-md-6">
                                <h6><i class="fas fa-file"></i> ${escapeHtml(file.name)}</h6>
                                <small class="text-muted">
                                    Size: ${formatFileSize(file.size)} | 
                                    Uploaded: ${new Date(file.upload_time).toLocaleString()}
                                </small>
                            </div>
                            <div class="col-md-4">
                                <div class="security-indicator security-verified">
                                    <i class="fas fa-check-circle"></i> Encrypted & Signed
                                </div>
                                <br>
                                <small class="text-muted">Hash: ${file.hash.substring(0, 16)}...</small>
                            </div>
                            <div class="col-md-2 text-end">
                                ${isPreviewable ? `
                                ` : ''}
                                <button class="btn btn-sm btn-primary me-1" onclick="downloadFile(${file.id}, '${escapeHtml(file.name)}')">
                                    <i class="fas fa-download"></i>
                                </button>
                                <button class="btn btn-sm btn-danger" onclick="deleteFile(${file.id}, '${escapeHtml(file.name)}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            });
            container.innerHTML = html;
        }

        function downloadFile(fileId, filename) {
            downloadFileId = fileId;
            const privateKey = localStorage.getItem('vault_private_key') ? 'Stored locally (enter password if prompted)' : '';
            document.getElementById('download-private-key').value = privateKey;
            document.getElementById('download-error').style.display = 'none';
            const modal = new bootstrap.Modal(document.getElementById('downloadModal'));
            modal.show();
        }

        async function confirmDownload() {
            const privateKeyInput = document.getElementById('download-private-key').value.trim();
            let privateKey = privateKeyInput;
            const errorDiv = document.getElementById('download-error');

            if (privateKeyInput === 'Stored locally (enter password if prompted)') {
                const password = prompt('Enter your key decryption password:');
                if (!password) {
                    errorDiv.textContent = 'Password required to decrypt stored key.';
                    errorDiv.style.display = 'block';
                    return;
                }
                try {
                    const encryptedKey = JSON.parse(localStorage.getItem('vault_private_key'));
                    privateKey = await decryptKey(encryptedKey, password);
                } catch (error) {
                    errorDiv.textContent = 'Failed to decrypt key: ' + error.message;
                    errorDiv.style.display = 'block';
                    return;
                }
            }

            if (!privateKey) {
                errorDiv.textContent = 'Please provide your private key.';
                errorDiv.style.display = 'block';
                return;
            }

            try {
                showAlert('Decrypting and verifying file...', 'info');
                const response = await fetch(`/api/download/${downloadFileId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ private_key: privateKey })
                });
                const data = await response.json();
                if (response.ok) {
                    const blob = base64ToBlob(data.data);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = data.filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    showAlert(`File "${data.filename}" downloaded and verified successfully!`, 'success');
                    bootstrap.Modal.getInstance(document.getElementById('downloadModal')).hide();
                    loadAuditLogs();
                } else {
                    errorDiv.textContent = data.error || 'Download failed.';
                    errorDiv.style.display = 'block';
                    showAlert(data.error, 'danger');
                }
            } catch (error) {
                errorDiv.textContent = 'Download failed: ' + error.message;
                errorDiv.style.display = 'block';
                showAlert('Download failed: ' + error.message, 'danger');
            }
        }

        async function previewFile(fileId, filename) {
            previewFileId = fileId;
            const privateKey = document.getElementById('download-private-key').value;
            if (!privateKey.trim()) {
                showAlert('Please provide your private key in the Key Management section', 'warning');
                return;
            }
            try {
                showAlert('Decrypting file for preview...', 'info');
                const response = await fetch(`/api/download/${fileId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ private_key: privateKey })
                });
                const data = await response.json();
                if (response.ok) {
                    const blob = base64ToBlob(data.data);
                    const url = URL.createObjectURL(blob);
                    const contentDiv = document.getElementById('preview-content');
                    if (/\.pdf$/i.test(filename)) {
                        contentDiv.innerHTML = `<iframe src="${url}" style="width:100%;height:60vh;"></iframe>`;
                    } else {
                        contentDiv.innerHTML = `<img src="${url}" style="max-width:100%;max-height:60vh;">`;
                    }
                    const modal = new bootstrap.Modal(document.getElementById('previewModal'));
                    modal.show();
                    showAlert('File preview loaded successfully!', 'success');
                } else {
                    showAlert(data.error, 'danger');
                }
            } catch (error) {
                showAlert('Preview failed: ' + error.message, 'danger');
            }
        }

        async function deleteFile(fileId, filename) {
            if (!confirm(`Are you sure you want to delete "${filename}"? This action cannot be undone.`)) {
                return;
            }
            try {
                const response = await fetch(`/api/delete/${fileId}`, {
                    method: 'DELETE'
                });
                const data = await response.json();
                if (response.ok) {
                    showAlert(`File "${filename}" deleted successfully!`, 'success');
                    loadFiles();
                    loadAuditLogs();
                } else {
                    showAlert(data.error, 'danger');
                }
            } catch (error) {
                showAlert('Delete failed: ' + error.message, 'danger');
            }
        }

        async function loadAuditLogs() {
            try {
                const response = await fetch('/api/audit-logs');
                const data = await response.json();
                if (response.ok) {
                    displayAuditLogs(data.logs);
                }
            } catch (error) {
                console.error('Failed to load audit logs:', error);
            }
        }

        function displayAuditLogs(logs) {
            const container = document.getElementById('audit-logs');
            if (logs.length === 0) {
                container.innerHTML = '<p class="text-muted small">No audit logs yet.</p>';
                return;
            }
            let html = '';
            logs.forEach(log => {
                html += `
                    <div class="audit-log">
                        <div class="d-flex justify-content-between">
                            <strong class="small">${log.action}</strong>
                            <span class="small text-muted">${new Date(log.timestamp).toLocaleString()}</span>
                        </div>
                        ${log.details ? `<div class="small text-muted">${escapeHtml(log.details)}</div>` : ''}
                        <div class="small text-muted">IP: ${log.ip_address}</div>
                    </div>
                `;
            });
            container.innerHTML = html;
        }

        async function logout() {
            try {
                await fetch('/api/logout', { method: 'POST' });
                currentUser = null;
                userCertificate = null;
                document.querySelectorAll('form').forEach(form => form.reset());
                document.querySelectorAll('.key-display').forEach(el => el.textContent = '');
                showAuth();
                showAlert('Logged out successfully!', 'success');
            } catch (error) {
                showAlert('Logout failed: ' + error.message, 'danger');
            }
        }

        function showApp() {
            document.getElementById('auth-section').style.display = 'none';
            document.getElementById('app-section').style.display = 'block';
            document.getElementById('user-info').style.display = 'block';
        }

        function showAuth() {
            document.getElementById('auth-section').style.display = 'block';
            document.getElementById('app-section').style.display = 'none';
            document.getElementById('user-info').style.display = 'none';
        }

        function showAlert(message, type) {
            const alertHtml = `
                <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                    ${escapeHtml(message)}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `;
            const container = document.querySelector('.container');
            container.insertAdjacentHTML('afterbegin', alertHtml);
            setTimeout(() => {
                const alert = container.querySelector('.alert');
                if (alert) {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }
            }, 5000);
        }

        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            navigator.clipboard.writeText(text).then(() => {
                showAlert('Copied to clipboard!', 'success');
            }).catch(() => {
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showAlert('Copied to clipboard!', 'success');
            });
        }

        function base64ToBlob(base64) {
            const byteCharacters = atob(base64);
            const byteArrays = [];
            for (let offset = 0; offset < byteCharacters.length; offset += 512) {
                const slice = byteCharacters.slice(offset, offset + 512);
                const byteNumbers = new Array(slice.length);
                for (let i = 0; i < slice.length; i++) {
                    byteNumbers[i] = slice.charCodeAt(i);
                }
                const byteArray = new Uint8Array(byteNumbers);
                byteArrays.push(byteArray);
            }
            return new Blob(byteArrays);
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('login-form').addEventListener('submit', handleLogin);
            document.getElementById('register-form').addEventListener('submit', handleRegister);
            document.getElementById('upload-form').addEventListener('submit', handleUpload);
            const confirmDownloadBtn = document.getElementById('confirm-download-btn');
            if (confirmDownloadBtn) {
                confirmDownloadBtn.addEventListener('click', confirmDownload);
            }
            checkAuthStatus();
        });
    </script>
</body>
</html>
'''

# Initialize database and run application
if __name__ == '__main__':
    init_db()
    print("🔒 Secure Document Vault Starting...")
    print("🔑 Features:")
    print("   • PKI-based RSA encryption (2048-bit)")
    print("   • Digital signatures for integrity")
    print("   • X.509 certificate management")
    print("   • End-to-end encryption")
    print("   • Comprehensive audit logging")
    print("   • Zero-trust architecture")
    print("\n🌐 Server starting on http://localhost:5000")
    print("📝 Register a new account to generate your PKI keypair!")
    app.run(debug=True, host='0.0.0.0', port=5000)