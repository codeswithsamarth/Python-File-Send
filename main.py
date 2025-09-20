import os
import zipfile
import tempfile
import base64
from datetime import datetime
from flask import Flask, request, render_template_string, send_file
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from supabase import create_client, Client

# ---------------- Configuration ---------------- #
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://ilogfpecjcgaltylrftd.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imlsb2dmcGVjamNnYWx0eWxyZnRkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1ODI5NDI0NywiZXhwIjoyMDczODcwMjQ3fQ.Q4140qgLQNPqaUl8xjaDRUlkvuu9icWUTqvFP9PKgLg")  # Must be service_role key
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "Samarth Patil")
USE_SUPABASE = SUPABASE_URL and SUPABASE_KEY

# Initialize Supabase client
if USE_SUPABASE:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- Flask App ---------------- #
app = Flask(__name__)

# ---------------- Encryption Functions ---------------- #
def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(file_path: str, password: str) -> tuple:
    key, salt = generate_key_from_password(password)
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    return encrypted_data, salt

def decrypt_file(encrypted_data: bytes, password: str, salt: bytes) -> bytes:
    key, _ = generate_key_from_password(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

# ---------------- Storage Functions (Fixed) ---------------- #
def upload_file(file_data: bytes, filename: str) -> str:
    unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    if USE_SUPABASE:
        try:
            # Upload to Supabase private storage using service role key
            supabase.storage.from_(SUPABASE_BUCKET).upload(unique_filename, file_data)
            return unique_filename
        except Exception as e:
            raise Exception(f"Supabase upload failed: {e}")
    else:
        os.makedirs("storage", exist_ok=True)
        path = os.path.join("storage", unique_filename)
        with open(path, "wb") as f:
            f.write(file_data)
        return unique_filename

def download_file(filename: str) -> bytes:
    if USE_SUPABASE:
        try:
            # Download file from private Supabase storage
            data = supabase.storage.from_(SUPABASE_BUCKET).download(filename)
            return data
        except Exception as e:
            raise Exception(f"Supabase download failed: {e}")
    else:
        path = os.path.join("storage", filename)
        if not os.path.exists(path):
            raise FileNotFoundError("File not found in local storage")
        with open(path, "rb") as f:
            return f.read()

# ---------------- Helper Functions ---------------- #
def create_zip_file(file_path: str, original_filename: str) -> str:
    zip_path = tempfile.mktemp(suffix='.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, original_filename)
    return zip_path

def generate_encrypted_code(filename: str, salt: bytes) -> str:
    combined = f"{filename}:{base64.b64encode(salt).decode()}"
    encoded = base64.urlsafe_b64encode(combined.encode()).decode()
    return encoded

def decode_encrypted_code(code: str) -> tuple:
    decoded = base64.urlsafe_b64decode(code.encode()).decode()
    filename, salt_b64 = decoded.split(':', 1)
    salt = base64.b64decode(salt_b64.encode())
    return filename, salt

# ---------------- HTML Template ---------------- #
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>File Encryption App</title>
</head>
<body>
  <h1>🔐 File Encryption App</h1>
  <p>Mode: {{ 'Supabase' if use_supabase else 'Local Storage' }}</p>

  <h2>Encrypt & Upload</h2>
  <form method="POST" action="/encrypt" enctype="multipart/form-data">
    <label>Select File:</label><br>
    <input type="file" name="file" required><br><br>

    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>

    <button type="submit">Encrypt & Upload</button>
  </form>

  <hr>

  <h2>Decrypt & Download</h2>
  <form method="POST" action="/decrypt">
    <label>Encrypted Code:</label><br>
    <input type="text" name="code" required><br><br>

    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>

    <button type="submit">Decrypt & Download</button>
  </form>
</body>
</html>
"""

# ---------------- Routes ---------------- #
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, use_supabase=USE_SUPABASE)

@app.route('/encrypt', methods=['POST'])
def handle_encrypt_file():
    try:
        if 'file' not in request.files:
            return "No file uploaded", 400
        file = request.files['file']
        password = request.form.get('password')
        if not password or file.filename == '':
            return "File and password required", 400

        temp_file_path = tempfile.mktemp()
        file.save(temp_file_path)

        try:
            # Zip → Encrypt
            zip_path = create_zip_file(temp_file_path, file.filename)
            encrypted_data, salt = encrypt_file(zip_path, password)

            # Upload to Supabase
            uploaded_filename = upload_file(encrypted_data, f"encrypted_{file.filename}.zip")

            # Generate retrieval code
            code = generate_encrypted_code(uploaded_filename, salt)
            return f"<h3>✅ File Encrypted & Uploaded</h3><p>Your retrieval code:</p><textarea rows='3' cols='80'>{code}</textarea><br><a href='/'>Back</a>"
        finally:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            if 'zip_path' in locals() and os.path.exists(zip_path):
                os.unlink(zip_path)

    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/decrypt', methods=['POST'])
def handle_decrypt_file():
    try:
        code = request.form.get('code')
        password = request.form.get('password')
        if not code or not password:
            return "Code and password required", 400

        filename, salt = decode_encrypted_code(code)
        encrypted_data = download_file(filename)
        decrypted_data = decrypt_file(encrypted_data, password, salt)

        temp_file_path = tempfile.mktemp(suffix='.zip')
        with open(temp_file_path, "wb") as f:
            f.write(decrypted_data)

        return send_file(temp_file_path, as_attachment=True, download_name='decrypted_file.zip')

    except Exception as e:
        return f"Error: {str(e)}", 500

# ---------------- Run ---------------- #
if __name__ == '__main__':
    print("🚀 File Encryption App Starting...")
    if USE_SUPABASE:
        print("✅ Using Supabase Storage (Service Role Key)")
    else:
        print("📦 Using Local Storage (storage/ folder)")
    app.run(debug=True, host='0.0.0.0', port=5000)
