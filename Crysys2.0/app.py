import os
import json
import uuid
import socket
import threading
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import wrapper
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import phe
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
RECEIVED_FOLDER = os.path.join(BASE_DIR, "received")
MESSAGES_FILE = os.path.join(BASE_DIR, "messages.json")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RECEIVED_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max
app.secret_key = os.urandom(32)
CORS(app)

messages_lock = threading.Lock()

def load_messages():
    if os.path.exists(MESSAGES_FILE):
        try:
            with open(MESSAGES_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_messages(msgs):
    with open(MESSAGES_FILE, "w") as f:
        json.dump(msgs, f, indent=2)

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

@app.route("/")
def index():
    local_ip = get_local_ip()
    return render_template("index.html", local_ip=local_ip, port=5000)

# --- Encryption Engine APIs ---
@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json()
    algo = data.get("algo", "aes")
    text = data.get("text", "")
    key = data.get("key", "")
    if algo == "otp":
        if not key:
            return jsonify({"success": False, "error": "OTP requires a key", "output": ""})
        out = []
        for i, char in enumerate(text):
            out.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return jsonify({"success": True, "output": "".join(out).encode("utf-8").hex(), "error": ""})
    # Python fallback for symmetric encryption
    if algo in ["aes", "des", "rc4", "rc6", "serpent"]:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import base64
            
            # Pad key to required length
            if algo == "aes":
                key_bytes = (key + '\0' * 32)[:32].encode('utf-8')
                iv = b'\x00' * 16  # Simple IV for demo
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            elif algo == "des":
                key_bytes = (key + '\0' * 8)[:8].encode('utf-8')
                iv = b'\x00' * 8
                from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
                cipher = Cipher(TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
            elif algo == "rc4":
                from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
                key_bytes = (key + '\0' * 16)[:16].encode('utf-8')
                cipher = Cipher(ARC4(key_bytes), mode=None, backend=default_backend())
            else:
                # Fallback to wrapper for unsupported algorithms
                return jsonify(wrapper.encrypt_text(algo, text, key, **data.get("extras", {})))
            
            encryptor = cipher.encryptor()
            # Simple PKCS7 padding
            pad_len = 16 - (len(text.encode('utf-8')) % 16)
            padded = text.encode('utf-8') + bytes([pad_len] * pad_len)
            encrypted = encryptor.update(padded) + encryptor.finalize()
            return jsonify({"success": True, "output": base64.b64encode(encrypted).decode('utf-8'), "error": ""})
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "output": ""})
    return jsonify(wrapper.encrypt_text(algo, text, key, **data.get("extras", {})))

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json()
    algo = data.get("algo", "aes")
    text = data.get("text", "")
    key = data.get("key", "")
    if algo == "otp":
        if not key:
            return jsonify({"success": False, "error": "OTP requires a key", "output": ""})
        try:
            raw_text = bytes.fromhex(text).decode("utf-8")
        except Exception:
            raw_text = text
        out = []
        for i, char in enumerate(raw_text):
            out.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return jsonify({"success": True, "output": "".join(out), "error": ""})
    # Python fallback for symmetric decryption
    if algo in ["aes", "des", "rc4", "rc6", "serpent"]:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import base64
            
            # Pad key to required length
            if algo == "aes":
                key_bytes = (key + '\0' * 32)[:32].encode('utf-8')
                iv = b'\x00' * 16
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            elif algo == "des":
                key_bytes = (key + '\0' * 8)[:8].encode('utf-8')
                iv = b'\x00' * 8
                from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
                cipher = Cipher(TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
            elif algo == "rc4":
                from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
                key_bytes = (key + '\0' * 16)[:16].encode('utf-8')
                cipher = Cipher(ARC4(key_bytes), mode=None, backend=default_backend())
            else:
                return jsonify(wrapper.decrypt_text(algo, text, key, **data.get("extras", {})))
            
            decryptor = cipher.decryptor()
            encrypted = base64.b64decode(text)
            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            # Remove PKCS7 padding
            pad_len = decrypted[-1]
            decrypted = decrypted[:-pad_len]
            return jsonify({"success": True, "output": decrypted.decode('utf-8'), "error": ""})
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "output": ""})
    return jsonify(wrapper.decrypt_text(algo, text, key, **data.get("extras", {})))

@app.route("/api/hash", methods=["POST"])
def api_hash():
    data = request.get_json()
    algo = data.get("algo", "sha256")
    text = data.get("text", "")
    if algo == "sha512":
        h = hashlib.sha512(text.encode("utf-8")).hexdigest()
        return jsonify({"success": True, "output": h, "error": ""})
    return jsonify(wrapper.hash_text(algo, text))

@app.route("/api/keygen", methods=["POST"])
def api_keygen():
    data = request.get_json()
    algo = data.get("algo", "rsa").strip()
    if algo in ["ecc", "rsa-pss", "dsa", "ecdsa"]:
        try:
            if algo == "rsa-pss":
                priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            elif algo == "dsa":
                priv = dsa.generate_private_key(key_size=2048)
            else: # ecc, ecdsa
                priv = ec.generate_private_key(ec.SECP256R1())
            
            pub = priv.public_key()
            priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
            return jsonify({
                "success": True, 
                "output": f"--- PRIVATE KEY ---\n{priv_pem}\n--- PUBLIC KEY ---\n{pub_pem}", 
                "private_key": priv_pem,
                "public_key": pub_pem,
                "error": ""
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "output": ""})
    return jsonify(wrapper.keygen(algo, **data.get("extras", {})))

@app.route("/api/tp/analyze", methods=["POST"])
def api_tp_analyze():
    data = request.get_json()
    return jsonify(wrapper.analyze_text(data.get("algo", "ic"), data.get("text", ""), **data.get("extras", {})))

@app.route("/api/tp/sign", methods=["POST"])
def api_tp_sign():
    data = request.get_json()
    algo = data.get("algo", "rsa-pss")
    text = data.get("text", "").encode("utf-8")
    key_str = data.get("key", "").strip()
    if "-----BEGIN" in key_str:
        key_str = key_str[key_str.find("-----BEGIN"):]
    try:
        priv_key = serialization.load_pem_private_key(key_str.encode("utf-8"), password=None)
        if algo == "rsa-pss":
            sig = priv_key.sign(text, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        elif algo == "dsa":
            sig = priv_key.sign(text, hashes.SHA256())
        elif algo == "ecdsa":
            sig = priv_key.sign(text, ec.ECDSA(hashes.SHA256()))
        else:
            return jsonify({"success": False, "error": "Unknown signature algorithm"})
        return jsonify({"success": True, "signature": sig.hex()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/tp/verify", methods=["POST"])
def api_tp_verify():
    data = request.get_json()
    algo = data.get("algo", "rsa-pss")
    text = data.get("text", "").encode("utf-8")
    key_str = data.get("key", "").strip()
    sig_hex = data.get("signature", "").strip()
    if "-----BEGIN" in key_str:
        key_str = key_str[key_str.find("-----BEGIN"):]
    try:
        pub_key = serialization.load_pem_public_key(key_str.encode("utf-8"))
        # Strip all whitespaces, tabs, newlines from signature
        sig_cleaned = "".join(sig_hex.split())
        sig = bytes.fromhex(sig_cleaned)
        if algo == "rsa-pss":
            pub_key.verify(sig, text, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        elif algo == "dsa":
            pub_key.verify(sig, text, hashes.SHA256())
        elif algo == "ecdsa":
            pub_key.verify(sig, text, ec.ECDSA(hashes.SHA256()))
        else:
            return jsonify({"success": False, "error": "Unknown signature algorithm"})
        return jsonify({"success": True, "valid": True})
    except InvalidSignature:
        return jsonify({"success": True, "valid": False})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# --- Electronic Voting APIs (Homomorphic) ---
@app.route("/api/vote/keygen", methods=["POST"])
def api_vote_keygen():
    try:
        pub, priv = phe.generate_paillier_keypair(n_length=1024)
        return jsonify({"success": True, "pub_n": str(pub.n), "priv_p": str(priv.p), "priv_q": str(priv.q)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/vote/cast", methods=["POST"])
def api_vote_cast():
    data = request.get_json()
    try:
        vote = int(data.get("vote", 0))
        pub_n = int(data.get("pub_n", 0))
        pub = phe.PaillierPublicKey(n=pub_n)
        enc_vote = pub.encrypt(vote)
        return jsonify({"success": True, "ciphertext": str(enc_vote.ciphertext())})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/vote/tally", methods=["POST"])
def api_vote_tally():
    data = request.get_json()
    try:
        pub_n = int(data.get("pub_n", 0))
        pub = phe.PaillierPublicKey(n=pub_n)
        votes = data.get("votes", [])
        if not votes:
            return jsonify({"success": False, "error": "No votes provided"})
        
        tally = phe.EncryptedNumber(pub, int(votes[0]))
        for v in votes[1:]:
            tally = tally + phe.EncryptedNumber(pub, int(v))
            
        return jsonify({"success": True, "tally_ciphertext": str(tally.ciphertext())})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/vote/decrypt", methods=["POST"])
def api_vote_decrypt():
    data = request.get_json()
    try:
        pub_n = int(data.get("pub_n", 0))
        priv_p = int(data.get("priv_p", 0))
        priv_q = int(data.get("priv_q", 0))
        ciphertext = int(data.get("ciphertext", 0))
        
        pub = phe.PaillierPublicKey(n=pub_n)
        priv = phe.PaillierPrivateKey(pub, p=priv_p, q=priv_q)
        
        enc_num = phe.EncryptedNumber(pub, ciphertext)
        result = priv.decrypt(enc_num)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/encrypt_file", methods=["POST"])
def api_encrypt_file():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400
    f = request.files["file"]
    algo = request.form.get("algo", "aes")
    key = request.form.get("key", "")
    extras = {}
    if algo == "caesar": extras["shift"] = int(request.form.get("shift", 3))
    elif algo == "affine":
        extras["a_param"] = int(request.form.get("a_param", 1))
        extras["b_param"] = int(request.form.get("b_param", 0))
    result = wrapper.encrypt_file(algo, f.read(), key, **extras)
    if result["success"]:
        filename = secure_filename(f.filename or "encrypted") + ".crysys"
        out_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(out_path, "w") as out_f:
            json.dump({"algo": algo, "original_name": f.filename, "encrypted_at": datetime.utcnow().isoformat(), "content": result["output"]}, out_f)
        result["filename"] = filename
        result["download_url"] = f"/api/download/{filename}"
    return jsonify(result)

@app.route("/api/decrypt_file", methods=["POST"])
def api_decrypt_file():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400
    f = request.files["file"]
    algo = request.form.get("algo", "aes")
    try:
        raw = f.read().decode("utf-8")
        meta = json.loads(raw)
        content_bytes = meta["content"].encode("utf-8")
        algo = meta.get("algo", algo)
    except Exception:
        f.seek(0)
        content_bytes = f.read()
    key = request.form.get("key", "")
    extras = {}
    if algo == "caesar": extras["shift"] = int(request.form.get("shift", 3))
    elif algo == "affine":
        extras["a_param"] = int(request.form.get("a_param", 1))
        extras["b_param"] = int(request.form.get("b_param", 0))
    return jsonify(wrapper.decrypt_file(algo, content_bytes, key, **extras))

@app.route("/api/download/<filename>")
def api_download(filename):
    safe = secure_filename(filename)
    path = os.path.join(UPLOAD_FOLDER, safe)
    if not os.path.exists(path): return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True, download_name=safe)

@app.route("/api/download_received/<filename>")
def api_download_received(filename):
    safe = secure_filename(filename)
    path = os.path.join(RECEIVED_FOLDER, safe)
    if not os.path.exists(path): return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True, download_name=safe)

# --- P2P Secure Chat APIs ---
@app.route("/api/messages", methods=["GET"])
def api_get_messages():
    with messages_lock:
        return jsonify(load_messages())

@app.route("/api/clear_messages", methods=["POST"])
def api_clear_messages():
    with messages_lock:
        save_messages([])
    return jsonify({"success": True})

@app.route("/api/send", methods=["POST"])
def api_send():
    data = request.get_json()
    target_ip, target_port = data.get("target_ip", ""), int(data.get("target_port", 5000))
    algo, key, message, sender_name = data.get("algo", "aes"), data.get("key", ""), data.get("message", ""), data.get("sender_name", "Anonymous")
    if not target_ip or not message: return jsonify({"success": False, "error": "Target IP and message are required"}), 400
    enc_result = wrapper.encrypt_text(algo, message, key)
    if not enc_result["success"]: return jsonify({"success": False, "error": f"Encryption failed: {enc_result['error']}"}), 500
    payload = {"id": str(uuid.uuid4()), "sender_ip": get_local_ip(), "sender_name": sender_name, "algo": algo, "encrypted_content": enc_result["output"], "timestamp": datetime.utcnow().isoformat(), "type": "message"}
    try:
        resp = requests.post(f"http://{target_ip}:{target_port}/api/receive", json=payload, timeout=10)
        if resp.status_code == 200:
            with messages_lock:
                msgs = load_messages()
                msgs.append({**payload, "direction": "sent", "plain": message})
                save_messages(msgs)
            return jsonify({"success": True, "message": "Message sent"})
        return jsonify({"success": False, "error": f"Remote returned {resp.status_code}: {resp.text}"}), 500
    except requests.exceptions.ConnectionError: return jsonify({"success": False, "error": f"Cannot connect to {target_ip}:{target_port}"}), 503
    except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/send_file", methods=["POST"])
def api_send_file():
    target_ip, target_port = request.form.get("target_ip", ""), int(request.form.get("target_port", 5000))
    algo, key, sender_name = request.form.get("algo", "aes"), request.form.get("key", ""), request.form.get("sender_name", "Anonymous")
    if "file" not in request.files or not target_ip: return jsonify({"success": False, "error": "File or Target IP missing"}), 400
    f = request.files["file"]
    enc_result = wrapper.encrypt_file(algo, f.read(), key)
    if not enc_result["success"]: return jsonify({"success": False, "error": f"Encryption failed: {enc_result['error']}"}), 500
    payload = {"id": str(uuid.uuid4()), "sender_ip": get_local_ip(), "sender_name": sender_name, "algo": algo, "encrypted_content": enc_result["output"], "original_filename": f.filename, "timestamp": datetime.utcnow().isoformat(), "type": "file"}
    try:
        resp = requests.post(f"http://{target_ip}:{target_port}/api/receive", json=payload, timeout=30)
        if resp.status_code == 200:
            with messages_lock:
                msgs = load_messages()
                msgs.append({**payload, "direction": "sent"})
                save_messages(msgs)
            return jsonify({"success": True, "message": "File sent"})
        return jsonify({"success": False, "error": f"Remote returned {resp.status_code}"}), 500
    except requests.exceptions.ConnectionError: return jsonify({"success": False, "error": f"Cannot connect"}), 503
    except Exception as e: return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/receive", methods=["POST"])
def api_receive():
    data = request.get_json()
    if not data: return jsonify({"success": False, "error": "Invalid payload"}), 400
    if data.get("type", "message") == "file":
        filename = secure_filename(data.get("original_filename", "received_file"))
        save_path = os.path.join(RECEIVED_FOLDER, datetime.utcnow().strftime("%Y%m%d_%H%M%S_") + filename + ".crysys")
        with open(save_path, "w") as mf:
            json.dump({"algo": data.get("algo", ""), "original_name": filename, "content": data.get("encrypted_content", ""), "sender": data.get("sender_name", "Unknown")}, mf)
        data["saved_filename"] = os.path.basename(save_path)
    with messages_lock:
        msgs = load_messages()
        msgs.append({**data, "direction": "received"})
        save_messages(msgs)
    return jsonify({"success": True})

# --- Crypto Lab (Academic TPs) APIs ---
@app.route("/api/tp1/cesar", methods=["POST"])
def api_tp1_cesar():
    try:
        from crypto.classic.cesar import chiffrer_cesar, dechiffrer_cesar, indice_coincidence, attaque_par_ic, attaque_force_brute
        data = request.json
        msg, k, action = data.get("message", ""), int(data.get("key", 3)), data.get("action", "encrypt")
        if action == "encrypt": return jsonify({"result": chiffrer_cesar(msg, k), "ic": round(indice_coincidence(chiffrer_cesar(msg, k)), 4)})
        if action == "decrypt": return jsonify({"result": dechiffrer_cesar(msg, k)})
        if action == "attack":
            k_found, brute = attaque_par_ic(msg), attaque_force_brute(msg)
            return jsonify({"key_found": k_found, "decrypted": dechiffrer_cesar(msg, k_found), "top5": [(cle, texte, round(score, 2)) for cle, (texte, score) in list(brute.items())[:5]]})
    except Exception as e: return jsonify({"error": str(e)}), 400

@app.route("/api/status")
def api_status():
    return jsonify({"engine": "crysys2.0", "cli_available": wrapper.engine_available(), "local_ip": get_local_ip()})

if __name__ == "__main__":
    print(f"Crysys 2.0 Web Interface\nAvailable at: http://{get_local_ip()}:5000 and http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
