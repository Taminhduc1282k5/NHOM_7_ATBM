
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import base64
import hashlib
import json
import os
import time
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure_audio_cloud'
socketio = SocketIO(app, cors_allowed_origins="*")

# Tạo thư mục
os.makedirs('uploads', exist_ok=True)
os.makedirs('keys', exist_ok=True)

def generate_rsa_keypair():
    """Tạo cặp key RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, public_key, private_pem, public_pem

class AudioCloud:
    def __init__(self):
        self.users = {}  # Lưu thông tin users và keys
        self.files = {}  # Lưu thông tin files
        self.load_data()
        
    def load_data(self):
        """Load dữ liệu từ file"""
        try:
            if os.path.exists('users.json'):
                with open('users.json', 'r') as f:
                    self.users = json.load(f)
            if os.path.exists('files.json'):
                with open('files.json', 'r') as f:
                    self.files = json.load(f)
        except:
            pass
    
    def save_data(self):
        """Lưu dữ liệu vào file"""
        with open('users.json', 'w') as f:
            json.dump(self.users, f, indent=2)
        with open('files.json', 'w') as f:
            json.dump(self.files, f, indent=2)
    
    def create_user(self, user_id):
        """Tạo user mới với cặp key"""
        if user_id not in self.users:
            private_key, public_key, private_pem, public_pem = generate_rsa_keypair()
            
            self.users[user_id] = {
                'private_key': private_pem.decode(),
                'public_key': public_pem.decode(),
                'created_at': datetime.now().isoformat()
            }
            self.save_data()
            
        return self.users[user_id]
    
    def get_user_keys(self, user_id):
        """Lấy keys của user"""
        if user_id not in self.users:
            return None, None
            
        private_pem = self.users[user_id]['private_key'].encode()
        public_pem = self.users[user_id]['public_key'].encode()
        
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(public_pem)
        
        return private_key, public_key
    
    def encrypt_file(self, file_data, user_id):
        """Mã hóa file bằng AES và RSA"""
        # Tạo session key AES
        session_key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        
        # Mã hóa file bằng AES
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        
        # Lấy public key của user để mã hóa session key
        _, public_key = self.get_user_keys(user_id)
        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.PKCS1v15()
        )
        
        return {
            'nonce': base64.b64encode(nonce).decode(),
            'cipher': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode()
        }
    
    def decrypt_file(self, encryption_data, user_id):
        """Giải mã file"""
        try:
            # Lấy private key của user
            private_key, _ = self.get_user_keys(user_id)
            
            # Giải mã session key
            encrypted_session_key = base64.b64decode(encryption_data['encrypted_session_key'])
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.PKCS1v15()
            )
            
            # Giải mã file
            nonce = base64.b64decode(encryption_data['nonce'])
            ciphertext = base64.b64decode(encryption_data['cipher'])
            tag = base64.b64decode(encryption_data['tag'])
            
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext
        except:
            return None

cloud = AudioCloud()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload')
def upload_page():
    return render_template('upload.html')

@app.route('/download')
def download_page():
    return render_template('download.html')

@app.route('/create_user/<user_id>')
def create_user(user_id):
    """Tạo user mới"""
    user_data = cloud.create_user(user_id)
    return jsonify({
        'user_id': user_id,
        'public_key': user_data['public_key'],
        'message': f'User {user_id} created successfully!'
    })

@app.route('/get_user/<user_id>')
def get_user(user_id):
    """Lấy thông tin user"""
    if user_id in cloud.users:
        return jsonify({
            'user_id': user_id,
            'public_key': cloud.users[user_id]['public_key']
        })
    return jsonify({'error': 'User not found'}), 404

@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to Secure Audio Cloud'})

@socketio.on('upload_file')
def handle_upload(data):
    try:
        user_id = data['user_id']
        filename = data['filename']
        file_data = base64.b64decode(data['file_data'])
        
        # Kiểm tra file MP3
        if not filename.lower().endswith('.mp3'):
            emit('upload_error', {'error': 'Chỉ cho phép file MP3!'})
            return
        
        # Kiểm tra user tồn tại
        if user_id not in cloud.users:
            emit('upload_error', {'error': 'User không tồn tại! Hãy tạo user trước.'})
            return
        
        # Mã hóa file
        encryption_data = cloud.encrypt_file(file_data, user_id)
        
        # Tạo hash cho file
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        # Tạo signature
        private_key, _ = cloud.get_user_keys(user_id)
        metadata = {
            'filename': filename,
            'user_id': user_id,
            'size': len(file_data),
            'hash': file_hash,
            'timestamp': datetime.now().isoformat()
        }
        
        metadata_json = json.dumps(metadata, sort_keys=True).encode()
        signature = private_key.sign(
            metadata_json,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Lưu file gốc (chưa mã hóa)
        safe_filename = f"{user_id}_{filename}"
        file_path = os.path.join('uploads', safe_filename)
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # Tạo JSON output
        output_data = {
            "nonce": encryption_data['nonce'],
            "cipher": encryption_data['cipher'],
            "tag": encryption_data['tag'],
            "hash": file_hash,
            "sig": base64.b64encode(signature).decode()
        }
        
        # Lưu thông tin file
        cloud.files[filename] = {
            'user_id': user_id,
            'metadata': metadata,
            'encryption_data': encryption_data,
            'file_path': file_path,
            'upload_time': datetime.now().isoformat()
        }
        cloud.save_data()
        
        emit('upload_success', {
            'message': '✅ Upload thành công!',
            'filename': filename,
            'user_id': user_id,
            'encryption_data': output_data,
            'public_key': cloud.users[user_id]['public_key'],
            'instructions': 'Lưu lại encryption_data và chia sẻ public_key để người khác download'
        })
        
    except Exception as e:
        emit('upload_error', {'error': str(e)})

@socketio.on('download_file')
def handle_download(data):
    try:
        filename = data['filename']
        user_public_key_pem = data['user_public_key']
        encryption_data = data['encryption_data']
        
        # Kiểm tra file tồn tại
        if filename not in cloud.files:
            emit('download_error', {'error': 'File không tồn tại!'})
            return
        
        file_info = cloud.files[filename]
        user_id = file_info['user_id']
        
        # Xác thực public key
        if user_public_key_pem.strip() != cloud.users[user_id]['public_key'].strip():
            emit('download_error', {'error': 'Public key không đúng!'})
            return
        
        # Xác thực signature
        public_key = serialization.load_pem_public_key(user_public_key_pem.encode())
        metadata_json = json.dumps(file_info['metadata'], sort_keys=True).encode()
        signature = base64.b64decode(encryption_data['sig'])
        
        try:
            public_key.verify(
                signature,
                metadata_json,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except:
            emit('download_error', {'error': 'Signature không hợp lệ!'})
            return
        
        # Giải mã file
        file_encryption_data = {
            'nonce': encryption_data['nonce'],
            'cipher': encryption_data['cipher'],
            'tag': encryption_data['tag'],
            'encrypted_session_key': file_info['encryption_data']['encrypted_session_key']
        }
        
        decrypted_data = cloud.decrypt_file(file_encryption_data, user_id)
        
        if decrypted_data is None:
            emit('download_error', {'error': 'Không thể giải mã file!'})
            return
        
        emit('download_success', {
            'filename': filename,
            'file_data': base64.b64encode(decrypted_data).decode(),
            'message': '✅ Xác thực thành công! File đã được giải mã.'
        })
        
    except Exception as e:
        emit('download_error', {'error': str(e)})

@app.route('/list_files')
def list_files():
    """Liệt kê tất cả files"""
    files = []
    for filename, info in cloud.files.items():
        files.append({
            'filename': filename,
            'user_id': info['user_id'],
            'size': info['metadata']['size'],
            'upload_time': info['upload_time']
        })
    return jsonify(files)

@app.route('/list_users')
def list_users():
    """Liệt kê tất cả users"""
    users = []
    for user_id, info in cloud.users.items():
        users.append({
            'user_id': user_id,
            'public_key': info['public_key'],
            'created_at': info['created_at']
        })
    return jsonify(users)

if __name__ == '__main__':
    print("🚀 Secure Audio Cloud starting...")
    print("📁 Upload: http://localhost:3000/upload")
    print("📥 Download: http://localhost:3000/download")
    socketio.run(app, host='0.0.0.0', port=3000, debug=True)
