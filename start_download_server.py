
#!/usr/bin/env python3
import subprocess
import sys

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 STARTING DOWNLOAD SERVER")
    print("=" * 50)
    print("Server sẽ chạy trên: http://0.0.0.0:5001")
    print("Nhớ cập nhật IP của upload server trong download_server.py")
    print("=" * 50)
    
    try:
        subprocess.run([sys.executable, 'download_server.py'])
    except KeyboardInterrupt:
        print("\n⏹️  Download Server stopped")
