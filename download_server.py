
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import base64
import hashlib
import json
import os
import time
import requests
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'download_server_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# URL của upload server
UPLOAD_SERVER_URL = "http://192.168.1.101:5000"  # Thay đổi IP theo máy upload server

# Tạo thư mục lưu trữ
os.makedirs('downloads', exist_ok=True)
os.makedirs('keys', exist_ok=True)
os.makedirs('shared_data', exist_ok=True)

def load_keys():
    try:
        with open('keys/server_private.pem', 'rb') as f:
            private_pem = f.read()
        with open('keys/server_public.pem', 'rb') as f:
            public_pem = f.read()
        with open('keys/client_private.pem', 'rb') as f:
            client_private_pem = f.read()
        with open('keys/client_public.pem', 'rb') as f:
            client_public_pem = f.read()
            
        server_private_key = serialization.load_pem_private_key(private_pem, password=None)
        server_public_key = serialization.load_pem_public_key(public_pem)
        client_private_key = serialization.load_pem_private_key(client_private_pem, password=None)
        client_public_key = serialization.load_pem_public_key(client_public_pem)
        
        return server_private_key, server_public_key, client_private_key, client_public_key, public_pem, client_public_pem
    except:
        print("Error loading keys from upload server")
        return None, None, None, None, None, None

server_private_key, server_public_key, client_private_key, client_public_key, server_public_pem, client_public_pem = load_keys()

class SecureFileHandler:
    def __init__(self):
        self.uploaded_files = {}
        self.load_shared_data()
        
    def load_shared_data(self):
        try:
            if os.path.exists('shared_data/file_registry.json'):
                with open('shared_data/file_registry.json', 'r') as f:
                    self.uploaded_files = json.load(f)
        except:
            self.uploaded_files = {}
    
    def sync_from_upload_server(self):
        try:
            response = requests.get(f"{UPLOAD_SERVER_URL}/list_files", timeout=5)
            if response.status_code == 200:
                files = response.json()
                print(f"Synced {len(files)} files from upload server")
        except:
            print("Could not sync from upload server")
        
    def encrypt_file(self, file_data, session_key):
        nonce = get_random_bytes(12)
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        return nonce, ciphertext, tag
    
    def decrypt_file(self, nonce, ciphertext, tag, session_key):
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            return None
    
    def sign_metadata(self, metadata, private_key):
        metadata_json = json.dumps(metadata, sort_keys=True)
        signature = private_key.sign(
            metadata_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, metadata, signature, public_key):
        try:
            metadata_json = json.dumps(metadata, sort_keys=True)
            signature_bytes = base64.b64decode(signature)
            public_key.verify(
                signature_bytes,
                metadata_json.encode(),
                padding.PKCS1v15(),
                hashes.SHA512()
            )
            return True
        except:
            return False

file_handler = SecureFileHandler()

@app.route('/')
def index():
    return render_template('download.html')

@app.route('/get_public_key')
def get_public_key():
    if server_public_pem and client_public_pem:
        return jsonify({
            'public_key': server_public_pem.decode(),
            'client_public_key': client_public_pem.decode()
        })
    else:
        return jsonify({'error': 'Keys not loaded'}), 500

@app.route('/sync_data', methods=['POST'])
def sync_data():
    try:
        data = request.get_json()
        file_handler.uploaded_files = data
        
        # Lưu vào file local
        with open('shared_data/file_registry.json', 'w') as f:
            json.dump(data, f, indent=2)
            
        return jsonify({'status': 'synced', 'files': len(data)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('handshake')
def handle_handshake():
    emit('handshake_response', {'message': 'Download Server Ready!'})

@socketio.on('download_request')
def handle_download_request(data):
    try:
        filename = data['filename']
        user_key = data.get('user_key', '')
        
        if filename not in file_handler.uploaded_files:
            emit('download_error', {'error': '❌ File không tồn tại trên server'})
            return
        
        # Kiểm tra key người dùng với session key đã lưu
        stored_session_key = base64.b64decode(file_handler.uploaded_files[filename]['session_key'])
        try:
            # Thử giải mã với key người dùng nhập
            provided_key = base64.b64decode(user_key)
            if provided_key != stored_session_key:
                emit('download_error', {'error': '🔐 Key xác thực không đúng! Không thể giải mã file.'})
                return
        except:
            emit('download_error', {'error': '🔐 Key xác thực sai định dạng! Vui lòng kiểm tra lại.'})
            return
        
        # Verify download signature
        download_request = {'filename': filename, 'timestamp': data['timestamp']}
        if not file_handler.verify_signature(
            download_request,
            data['signature'],
            client_public_key
        ):
            emit('download_error', {'error': '❌ Xác thực chữ ký thất bại! Không có quyền tải file.'})
            return
        
        # Lấy file từ upload server
        try:
            file_url = f"{UPLOAD_SERVER_URL}/get_file/{filename}"
            response = requests.get(file_url, timeout=30)
            if response.status_code != 200:
                emit('download_error', {'error': 'Could not retrieve file from upload server'})
                return
            file_data = response.content
        except:
            emit('download_error', {'error': 'Upload server not accessible'})
            return
        
        # Mã hóa file
        session_key = base64.b64decode(file_handler.uploaded_files[filename]['session_key'])
        nonce, ciphertext, tag = file_handler.encrypt_file(file_data, session_key)
        
        # Tạo hash
        file_hash = hashlib.sha512(nonce + ciphertext + tag).hexdigest()
        
        # Ký metadata
        metadata = file_handler.uploaded_files[filename]['metadata']
        metadata_signature = file_handler.sign_metadata(metadata, server_private_key)
        
        response_data = {
            'nonce': base64.b64encode(nonce).decode(),
            'cipher': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'hash': file_hash,
            'metadata': metadata,
            'metadata_signature': metadata_signature,
            'decrypted_file': base64.b64encode(file_data).decode(),
            'success_message': '✅ Xác thực thành công! File đã được giải mã và sẵn sàng tải xuống.'
        }
        
        emit('download_response', response_data)
        
    except Exception as e:
        emit('download_error', {'error': str(e)})

@app.route('/list_files')
def list_files():
    files = []
    for filename, info in file_handler.uploaded_files.items():
        files.append({
            'filename': filename,
            'size': info['metadata']['size'],
            'upload_time': info['upload_time']
        })
    return jsonify(files)

if __name__ == '__main__':
    print("🚀 Download Server starting on port 5001...")
    # Sync dữ liệu khi khởi động
    file_handler.sync_from_upload_server()
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
