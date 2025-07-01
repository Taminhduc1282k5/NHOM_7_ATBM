
#!/usr/bin/env python3
import subprocess
import sys

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 STARTING UPLOAD SERVER")
    print("=" * 50)
    print("Server sẽ chạy trên: http://0.0.0.0:5000")
    print("Nhớ cập nhật IP của máy này trong download_server.py")
    print("=" * 50)
    
    try:
        subprocess.run([sys.executable, 'upload_server.py'])
    except KeyboardInterrupt:
        print("\n⏹️  Upload Server stopped")
