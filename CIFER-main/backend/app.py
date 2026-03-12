"""
CIFER v3 — Flask Backend
Endpoints:
  POST /api/register
  POST /api/login
  POST /api/logout
  GET  /api/me
  POST /api/encrypt        multipart: file, receivers(JSON), expiry_hours
  GET  /api/file/<token>   file info
  POST /api/request-otp    { token, email }
  POST /api/decrypt        { token, email, otp }  → streams file
  GET  /api/history        list user's records
"""

import os, io, json, time, hashlib, secrets, string, random
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_file, session, g
from flask_cors import CORS
from flask_mail import Mail, Message
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

# Allow Cross-Origin cookies (For when frontend is running on 5500/3000/5173, etc. and backend is on 5000)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False, # Required for SameSite="None" (Browsers require secure context/localhost)
    SESSION_COOKIE_HTTPONLY=True
)

CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:5500"]
)

# ── Mail config ──
app.config.update(
    MAIL_SERVER   = "smtp.gmail.com",
    MAIL_PORT     = 587,
    MAIL_USE_TLS  = True,
    MAIL_USERNAME = os.getenv("MAIL_USER"),
    MAIL_PASSWORD = os.getenv("MAIL_PASS"),
    MAIL_DEFAULT_SENDER = ("CIFER Security", os.getenv("MAIL_USER","cifer@example.com")),
)
mail = Mail(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SERVER_KEY = bytes.fromhex(os.getenv("SERVER_KEY", secrets.token_hex(32)))[:32]

# ── Cute cover image themes (assigned randomly at encrypt time) ──
COVER_THEMES = [
    {"emoji": "🌸", "name": "Cherry Blossom", "color": "#1a0a12"},
    {"emoji": "🦋", "name": "Butterfly",      "color": "#0a101a"},
    {"emoji": "🌿", "name": "Forest",         "color": "#061208"},
    {"emoji": "🐱", "name": "Cat",            "color": "#100a1a"},
    {"emoji": "🌺", "name": "Hibiscus",       "color": "#1a0808"},
    {"emoji": "🐦", "name": "Bird",           "color": "#08101a"},
    {"emoji": "🍃", "name": "Leaves",         "color": "#06120a"},
    {"emoji": "🦊", "name": "Fox",            "color": "#1a0e06"},
    {"emoji": "🌻", "name": "Sunflower",      "color": "#1a1206"},
    {"emoji": "🐢", "name": "Turtle",         "color": "#06120e"},
]

# ─────────────────────────────────────────────
#  DB helpers
# ─────────────────────────────────────────────
def get_db():
    if "db" not in g:
        mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
        client = MongoClient(mongo_uri)
        g.db_client = client
        db_name = os.getenv("DB_NAME", "cifer_db")
        g.db = client[db_name]
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    client = g.pop("db_client", None)
    if client: client.close()
    g.pop("db", None)

# ── Auth decorator ──
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Not logged in"}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
#  Crypto helpers
# ─────────────────────────────────────────────
def aes_encrypt(data: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(SERVER_KEY), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded  = data + bytes([pad_len] * pad_len)
    return iv + enc.update(padded) + enc.finalize()

def aes_decrypt(blob: bytes) -> bytes:
    iv, ct = blob[:16], blob[16:]
    cipher  = Cipher(algorithms.AES(SERVER_KEY), modes.CBC(iv), backend=default_backend())
    dec     = cipher.decryptor()
    padded  = dec.update(ct) + dec.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def gen_token() -> str:
    return secrets.token_hex(16)

def gen_otp() -> str:
    return "".join(random.choices(string.digits, k=6))

# ─────────────────────────────────────────────
#  Email helper
# ─────────────────────────────────────────────
def send_otp_email(to_email: str, otp: str, filename: str):
    is_login = filename == "Account Login"
    title_text = "Login Required" if is_login else f"Decryption requested for: <strong style='color:#e0f0ff'>{filename}</strong>"
    
    html = f"""
    <div style="background:#030b18;color:#e0f0ff;font-family:Arial,sans-serif;
                padding:2.5rem;border-radius:14px;max-width:480px;margin:auto;
                border:1px solid #0a3a6e">
      <div style="text-align:center;margin-bottom:2rem">
        <h1 style="color:#3b9eff;font-size:2.2rem;letter-spacing:4px;margin:0">CIFER</h1>
        <p style="color:#4a7aab;font-size:.85rem;margin:.3rem 0 0">Secure File Encryption System</p>
      </div>
      <h2 style="font-size:1rem;margin-bottom:.5rem;color:#b8d4f0">🔐 Your OTP</h2>
      <p style="color:#4a7aab;font-size:.85rem;margin-bottom:1.5rem">
        {title_text}
      </p>
      <div style="background:rgba(59,158,255,.08);border:1px solid rgba(59,158,255,.3);
                  border-radius:12px;padding:1.5rem;text-align:center;margin-bottom:1.5rem">
        <div style="font-size:3rem;font-weight:900;letter-spacing:14px;
                    color:#3b9eff;font-family:monospace">{otp}</div>
      </div>
      <p style="color:#4a7aab;font-size:.8rem;margin:.3rem 0">⏱ Valid for <strong style="color:#f5c518">{"5 minutes" if is_login else "2 minutes"}</strong></p>
      <p style="color:#4a7aab;font-size:.8rem;margin:.3rem 0">🚫 Max <strong style="color:#e0f0ff">3 attempts</strong></p>
      <p style="color:#4a7aab;font-size:.8rem;margin:.3rem 0">If you didn't request this, ignore this email.</p>
      <hr style="border:none;border-top:1px solid #0a3a6e;margin:1.5rem 0"/>
      <p style="color:#1e3a5f;font-size:.72rem;text-align:center">CIFER — Secure System</p>
    </div>"""
    msg = Message("🔐 CIFER — Your OTP", recipients=[to_email], html=html)
    mail.send(msg)


# ─────────────────────────────────────────────
#  AUTH routes
# ─────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    d = request.json
    name, email, pw = d.get("name","").strip(), d.get("email","").strip().lower(), d.get("password","")
    if not all([name, email, pw]):
        return jsonify({"error": "All fields required"}), 400
    if len(pw) < 8:
        return jsonify({"error": "Password min 8 chars"}), 400
        
    db = get_db()
    existing = db.users.find_one({"email": email})
    if existing:
        return jsonify({"error": "Email already registered"}), 409
        
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
    user_doc = {
        "name": name,
        "email": email,
        "password_hash": pw_hash,
        "created_at": datetime.utcnow()
    }
    result = db.users.insert_one(user_doc)
    session["user_id"] = str(result.inserted_id)
    session["user_name"] = name
    return jsonify({"success": True, "name": name})

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json
    email, pw = d.get("email","").strip().lower(), d.get("password","")
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
    
    db = get_db()
    user = db.users.find_one({"email": email, "password_hash": pw_hash})
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401
    
    # Generate OTP for Login
    otp = gen_otp()
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(minutes=5)
    
    db.auth_otp.update_one(
        {"email": email},
        {"$set": {
            "otp_hash": otp_hash,
            "expires_at": expires,
            "attempts": 0
        }},
        upsert=True
    )
    
    try:
        send_otp_email(email, otp, "Account Login")
        return jsonify({"require_otp": True, "email": email, "message": f"OTP sent to {email}"})
    except Exception as e:
        app.logger.error(f"Mail error: {e}")
        if os.getenv("FLASK_ENV") == "development":
            return jsonify({"require_otp": True, "email": email, "dev_otp": otp,
                           "message": f"[DEV] OTP: {otp} (email failed: {str(e)})"})
        return jsonify({"error": "Failed to send email. Check MAIL_USER/MAIL_PASS in .env"}), 500

@app.route("/api/verify-login", methods=["POST"])
def verify_login():
    d = request.json
    email, otp = d.get("email","").lower(), d.get("otp","").strip()
    
    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400
        
    db = get_db()
    otp_rec = db.auth_otp.find_one({"email": email})
    if not otp_rec:
        return jsonify({"error": "No OTP requested. Please login again."}), 400
        
    if datetime.utcnow() > otp_rec["expires_at"]:
        return jsonify({"error": "OTP expired. Please login again."}), 401
        
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    attempts = otp_rec.get("attempts", 0) + 1
    
    db.auth_otp.update_one({"_id": otp_rec["_id"]}, {"$set": {"attempts": attempts}})
    
    if otp_hash != otp_rec["otp_hash"]:
        if attempts >= 3:
            db.auth_otp.delete_one({"_id": otp_rec["_id"]})
            return jsonify({"error": "Too many attempts. Blocked. Please login again."}), 429
        return jsonify({"error": f"Wrong OTP. {3 - attempts} attempt(s) remaining."}), 401
        
    # Success, clear OTP and log user in
    db.auth_otp.delete_one({"_id": otp_rec["_id"]})
    
    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User no longer exists"}), 404
        
    session["user_id"]   = str(user["_id"])
    session["user_name"] = user["name"]
    return jsonify({"success": True, "name": user["name"]})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"logged_in": False}), 200
        
    db = get_db()
    user = db.users.find_one({"_id": ObjectId(session["user_id"])})
    
    # Aggregation for stats
    stats_pipeline = [
        {"$match": {"user_id": session["user_id"]}},
        {"$group": {
            "_id": None,
            "total_enc": {"$sum": {"$cond": [{"$eq": ["$event", "encrypt"]}, 1, 0]}},
            "total_dec": {"$sum": {"$cond": [{"$eq": ["$event", "decrypt"]}, 1, 0]}},
            "total_tamper": {"$sum": {"$cond": [{"$eq": ["$event", "tamper"]}, 1, 0]}},
            "total_block": {"$sum": {"$cond": [{"$eq": ["$status", "blocked"]}, 1, 0]}}
        }}
    ]
    stats_res = list(db.activity_log.aggregate(stats_pipeline))
    stats = stats_res[0] if stats_res else {"total_enc": 0, "total_dec": 0, "total_tamper": 0, "total_block": 0}
    
    active_cnt = db.encrypted_files.count_documents({
        "user_id": session["user_id"],
        "$or": [{"expires_at": None}, {"expires_at": {"$gt": datetime.utcnow()}}],
        "deleted": 0
    })
    
    if user:
        user["id"] = str(user["_id"])
        del user["_id"]
        if "password_hash" in user: del user["password_hash"]
        user["created_at"] = str(user.get("created_at",""))
        
    return jsonify({"logged_in": True, "user": user, "stats": stats, "active_files": active_cnt})

# ─────────────────────────────────────────────
#  ENCRYPT
# ─────────────────────────────────────────────
@app.route("/api/encrypt", methods=["POST"])
@login_required
def encrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    try:
        receivers = json.loads(request.form.get("receivers", "[]"))
    except:
        return jsonify({"error": "Invalid receivers JSON"}), 400
    if not receivers:
        return jsonify({"error": "At least one receiver required"}), 400

    expiry_hours = int(request.form.get("expiry_hours", 24))  # 0 = unlimited

    raw = f.read()
    if len(raw) > 50 * 1024 * 1024:
        return jsonify({"error": "File too large (max 50MB)"}), 413

    start = time.time()
    file_hash = sha256(raw)
    encrypted = aes_encrypt(raw)
    elapsed_ms = int((time.time() - start) * 1000)
    throughput = f"{(len(raw)/1024)/(elapsed_ms/1000):.1f} KB/s" if elapsed_ms > 0 else "—"

    token = gen_token()
    # Randomly pick local cover
    random_num = random.randint(1, 5)
    theme = COVER_THEMES[random_num % 5] # Roughly pick one of the cute themes
    cover_path = os.path.join(os.path.dirname(__file__), f"covers/cover{random_num}.jpg")

    # Combine cover image with payload
    # Format: [ original JPEG bytes ] + [ marker: bytes('[CIFER_DATA]') ] + [ token (32 bytes) ] + [ encrypted payload ]
    marker = b"[CIFER_DATA]"
    
    out_filename = f"{token}.jpg"
    out_path = os.path.join(UPLOAD_FOLDER, out_filename)
        
    try:
        with open(cover_path, "rb") as cover_file:
            cover_bytes = cover_file.read()
            
        with open(out_path, "wb") as w_file:
            w_file.write(cover_bytes)
            w_file.write(marker)
            w_file.write(token.encode("utf-8"))
            w_file.write(encrypted)
    except Exception as e:
        app.logger.error(f"Failed to generate steganography image: {e}")
        return jsonify({"error": "Failed to bundle encrypted image"}), 500

    expires_at = None
    if expiry_hours > 0:
        expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)

    enc_path = out_path
    db = get_db()
    file_doc = {
        "token": token,
        "user_id": session["user_id"],
        "original_name": f.filename,
        "file_hash": file_hash,
        "enc_path": enc_path,
        "receivers": receivers,
        "expires_at": expires_at,
        "cover_emoji": theme["emoji"],
        "cover_name": theme["name"],
        "file_size": len(raw),
        "enc_time_ms": elapsed_ms,
        "deleted": 0,
        "created_at": datetime.utcnow()
    }
    result = db.encrypted_files.insert_one(file_doc)
    fid = str(result.inserted_id)

    db.activity_log.insert_one({
        "user_id": session["user_id"],
        "file_id": fid,
        "event": "encrypt",
        "detail": f"Receivers: {', '.join(receivers)}",
        "status": "success",
        "created_at": datetime.utcnow()
    })

    return jsonify({
        "success": True,
        "token": token,
        "file_hash": file_hash,
        "file_name": f.filename,
        "receivers": receivers,
        "expires_at": str(expires_at) if expires_at else "Unlimited",
        "cover_emoji": theme["emoji"],
        "cover_name": theme["name"],
        "enc_time": f"{elapsed_ms}ms",
        "throughput": throughput
    })

@app.route("/api/download/<token>")
@login_required
def download_enc(token):
    db = get_db()
    f = db.encrypted_files.find_one({"token": token, "deleted": 0})
    if not f or not os.path.exists(f["enc_path"]):
        return jsonify({"error": "File not found"}), 404
        
    return send_file(
        f["enc_path"],
        as_attachment=True,
        download_name=f"{token}.jpg",
        mimetype="image/jpeg"
    )

# ─────────────────────────────────────────────
#  FILE INFO FROM IMAGE (Steganography Extraction)
# ─────────────────────────────────────────────
@app.route("/api/decrypt-upload", methods=["POST"])
def decrypt_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    f = request.files["file"]
    raw = f.read()
    
    marker = b"[CIFER_DATA]"
    idx = raw.find(marker)
    if idx == -1:
        return jsonify({"error": "This image does not contain CIFER encrypted data"}), 400
        
    # Extract token
    token_start = idx + len(marker)
    token = raw[token_start:token_start+32].decode("utf-8")
    
    db = get_db()
    file_doc = db.encrypted_files.find_one({"token": token, "deleted": 0})
    if not file_doc:
        return jsonify({"error": "File not found or deleted from server"}), 404
        
    expired = file_doc.get("expires_at") and datetime.utcnow() > file_doc["expires_at"]
    return jsonify({
        "token":         token,
        "original_name": file_doc.get("original_name"),
        "file_hash":     file_doc.get("file_hash"),
        "receivers":     file_doc.get("receivers", []),
        "expires_at":    str(file_doc["expires_at"]) if file_doc.get("expires_at") else "Unlimited",
        "cover_emoji":   file_doc.get("cover_emoji"),
        "cover_name":    file_doc.get("cover_name"),
        "file_size":     file_doc.get("file_size"),
        "expired":       bool(expired),
    })

# ─────────────────────────────────────────────
#  FILE INFO (Fallback for History Links)
# ─────────────────────────────────────────────
@app.route("/api/file/<token>")
def file_info(token):
    db = get_db()
    f = db.encrypted_files.find_one({"token": token, "deleted": 0})
    if not f:
        return jsonify({"error": "File not found"}), 404
        
    expired = f.get("expires_at") and datetime.utcnow() > f["expires_at"]
    return jsonify({
        "original_name": f.get("original_name"),
        "file_hash":     f.get("file_hash"),
        "receivers":     f.get("receivers", []),
        "expires_at":    str(f["expires_at"]) if f.get("expires_at") else "Unlimited",
        "cover_emoji":   f.get("cover_emoji"),
        "cover_name":    f.get("cover_name"),
        "file_size":     f.get("file_size"),
        "expired":       bool(expired),
    })

# ─────────────────────────────────────────────
#  REQUEST OTP
# ─────────────────────────────────────────────
@app.route("/api/request-otp", methods=["POST"])
def request_otp():
    d = request.json
    token = d.get("token","")
    if not token:
        return jsonify({"error": "Token required"}), 400

    db = get_db()
    f = db.encrypted_files.find_one({"token": token, "deleted": 0})
    if not f:
        return jsonify({"error": "File not found or expired"}), 404

    if f.get("expires_at") and datetime.utcnow() > f["expires_at"]:
        return jsonify({"error": "File has expired"}), 410

    receivers = f.get("receivers", [])
    if not receivers:
        return jsonify({"error": "No receivers configured for this file"}), 403

    fid_str = str(f["_id"])

    # Check block globally for file
    block_rec = db.otp_attempts.find_one({
        "file_id": fid_str, 
        "blocked_until": {"$gt": datetime.utcnow()}
    })
    if block_rec:
        return jsonify({"error": "Access temporarily blocked. Try after 30 minutes."}), 429

    otp = gen_otp()
    # Debug print the OTP so the user can easily test
    print(f"\n\n=== DEVELOPMENT OTP for {token}: {otp} ===\n\n")
    
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(minutes=2)

    # Upsert OTP record for the file
    db.otp_store.update_one(
        {"file_id": fid_str},
        {"$set": {
            "otp_hash": otp_hash,
            "expires_at": expires,
            "attempts": 0
        }},
        upsert=True
    )

    # Send email to all receivers
    errors = []
    for email in receivers:
        try:
            send_otp_email(email, otp, f.get("original_name", "a file"))
        except Exception as e:
            errors.append(str(e))
            
    if errors and len(errors) == len(receivers):
        app.logger.error(f"Mail errors: {errors}")
        if os.getenv("FLASK_ENV") == "development":
            return jsonify({"success": True, "dev_otp": otp,
                           "message": f"OTP dispatched to receivers (simulated due to email errors)"})
        return jsonify({"error": "Failed to send emails to receivers."}), 500

    return jsonify({"success": True, "message": f"OTP successfully sent to all receivers.", "dev_otp": otp if os.getenv("FLASK_ENV") == "development" else None})

# ─────────────────────────────────────────────
#  DECRYPT
# ─────────────────────────────────────────────
@app.route("/api/decrypt", methods=["POST"])
@login_required
def decrypt_file():
    d = request.json
    token  = d.get("token","")
    otp    = d.get("otp","").strip()

    if not all([token, otp]):
        return jsonify({"error": "Token and OTP required"}), 400

    db = get_db()
    f = db.encrypted_files.find_one({"token": token, "deleted": 0})
    if not f:
        return jsonify({"error": "File not found"}), 404

    if f.get("expires_at") and datetime.utcnow() > f["expires_at"]:
        return jsonify({"error": "File has expired"}), 410

    fid_str = str(f["_id"])

    # Block check globally for file
    block_rec = db.otp_attempts.find_one({
        "file_id": fid_str, 
        "blocked_until": {"$gt": datetime.utcnow()}
    })
    if block_rec:
        return jsonify({"error": "Access blocked for 30 minutes"}), 429

    # Get OTP record for file
    otp_rec = db.otp_store.find_one({"file_id": fid_str})
    if not otp_rec:
        return jsonify({"error": "No OTP requested. Request OTP first."}), 400
    if datetime.utcnow() > otp_rec["expires_at"]:
        return jsonify({"error": "OTP expired. Request a new one."}), 401

    # Verify OTP
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    attempts = otp_rec.get("attempts", 0) + 1
    
    db.otp_store.update_one(
        {"_id": otp_rec["_id"]},
        {"$set": {"attempts": attempts}}
    )

    if otp_hash != otp_rec["otp_hash"]:
        if attempts >= 3:
            blocked_until = datetime.utcnow() + timedelta(minutes=30)
            db.otp_attempts.update_one(
                {"file_id": fid_str},
                {"$set": {"blocked_until": blocked_until}},
                upsert=True
            )
            db.activity_log.insert_one({
                "user_id": f.get("user_id"),
                "file_id": fid_str,
                "event": "failed",
                "detail": f"Blocked file due to 3 failed OTPs",
                "status": "blocked",
                "created_at": datetime.utcnow()
            })
            return jsonify({"error": "Too many attempts. Blocked for 30 minutes.", "blocked": True}), 429
        left = 3 - attempts
        return jsonify({"error": f"Wrong OTP. {left} attempt(s) remaining.", "attempts_left": left}), 401

    # Decrypt
    try:
        # User uploaded the file again for decryption, or we can use the stored enc_path
        # But wait, we modified the stored enc_path in encrypt to use the JPG.
        # So we can just read from f["enc_path"] on the server.
        enc_path = f.get("enc_path")
        if not enc_path or not os.path.exists(enc_path):
            return jsonify({"error": "Encrypted file missing from server"}), 404
            
        with open(enc_path, "rb") as fp:
            raw_data = fp.read()
            
        marker = b"[CIFER_DATA]"
        idx = raw_data.find(marker)
        if idx == -1:
            return jsonify({"error": "Corrupted file structure"}), 500
            
        payload_start = idx + len(marker) + 32 # Skip marker and token
        encrypted = raw_data[payload_start:]
        
        decrypted = aes_decrypt(encrypted)

        # Tamper check
        actual_hash = sha256(decrypted)
        if actual_hash != f["file_hash"]:
            db.activity_log.insert_one({
                "user_id": f.get("user_id"),
                "file_id": fid_str,
                "event": "tamper",
                "detail": "Hash mismatch",
                "status": "tampered",
                "created_at": datetime.utcnow()
            })
            return jsonify({"error": "TAMPER DETECTED — file integrity check failed!", "tamper": True}), 422

        # Clear OTP
        db.otp_store.delete_one({"_id": otp_rec["_id"]})
        db.activity_log.insert_one({
            "user_id": f.get("user_id"),
            "file_id": fid_str,
            "event": "decrypt",
            "detail": f"Decrypted by OTP",
            "status": "success",
            "created_at": datetime.utcnow()
        })

        return send_file(
            io.BytesIO(decrypted),
            as_attachment=True,
            download_name=f.get("original_name", "decrypted_file"),
            mimetype="application/octet-stream"
        )
    except Exception as e:
        app.logger.error(f"Decrypt error: {e}")
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
#  HISTORY
# ─────────────────────────────────────────────
@app.route("/api/history")
@login_required
def history():
    db = get_db()
    logs = list(db.activity_log.find({"user_id": session["user_id"]}).sort("created_at", -1).limit(100))
    for r in logs:
        r["id"] = str(r["_id"])
        del r["_id"]
        r["created_at"] = str(r.get("created_at",""))
        
        # Populate file details
        if "file_id" in r and r["file_id"]:
            f = db.encrypted_files.find_one({"_id": ObjectId(r["file_id"])})
            if f:
                r["original_name"] = f.get("original_name")
                r["cover_emoji"] = f.get("cover_emoji")
                r["cover_name"] = f.get("cover_name")
                
    return jsonify(logs)

@app.route("/api/active-files")
@login_required
def active_files():
    db = get_db()
    cursor = db.encrypted_files.find({
        "user_id": session["user_id"],
        "deleted": 0,
        "$or": [{"expires_at": None}, {"expires_at": {"$gt": datetime.utcnow()}}]
    }).sort("created_at", -1).limit(20)
    
    rows = []
    for f in cursor:
        rows.append({
            "token": f.get("token"),
            "original_name": f.get("original_name"),
            "file_size": f.get("file_size"),
            "cover_emoji": f.get("cover_emoji"),
            "cover_name": f.get("cover_name"),
            "created_at": str(f.get("created_at", "")),
            "expires_at": str(f.get("expires_at")) if f.get("expires_at") else "Unlimited"
        })
    return jsonify(rows)

if __name__ == "__main__":
    app.run(debug=True, host="localhost", port=5000)
