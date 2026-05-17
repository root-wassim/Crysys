"""
CryptoLab — Interface graphique web professionnelle
Flask backend pour exécuter les TPs de cryptographie
"""
import os, sys, json, time, hashlib, traceback
from pathlib import Path
from flask import Flask, render_template, request, jsonify

# Ajouter le répertoire racine au path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

app = Flask(__name__,
            template_folder=str(ROOT / "templates"),
            static_folder=str(ROOT / "static"))
app.secret_key = os.urandom(32)


@app.route("/")
def index():
    return render_template("index.html")


# ═══════════════════════════════════════════════════
#  API TP1 — Chiffres classiques
# ═══════════════════════════════════════════════════

@app.route("/api/tp1/cesar", methods=["POST"])
def api_cesar():
    try:
        from tp1_classique.cesar import chiffrer_cesar, dechiffrer_cesar, indice_coincidence, attaque_par_ic, attaque_force_brute
        data = request.json
        msg = data.get("message", "")
        k = int(data.get("key", 3))
        action = data.get("action", "encrypt")
        if action == "encrypt":
            result = chiffrer_cesar(msg, k)
            ic = indice_coincidence(result)
            return jsonify({"result": result, "ic": round(ic, 4)})
        elif action == "decrypt":
            result = dechiffrer_cesar(msg, k)
            return jsonify({"result": result})
        elif action == "attack":
            k_found = attaque_par_ic(msg)
            brute = attaque_force_brute(msg)
            top5 = [(cle, texte, round(score, 2)) for cle, (texte, score) in list(brute.items())[:5]]
            return jsonify({"key_found": k_found, "decrypted": dechiffrer_cesar(msg, k_found), "top5": top5})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp1/vigenere", methods=["POST"])
def api_vigenere():
    try:
        from tp1_classique.vigenere import chiffrer_vigenere, dechiffrer_vigenere, cryptanalyse_vigenere
        data = request.json
        msg = data.get("message", "")
        key = data.get("key", "CLE")
        action = data.get("action", "encrypt")
        if action == "encrypt":
            return jsonify({"result": chiffrer_vigenere(msg, key)})
        elif action == "decrypt":
            return jsonify({"result": dechiffrer_vigenere(msg, key)})
        elif action == "attack":
            cle, clair = cryptanalyse_vigenere(msg)
            return jsonify({"key_found": cle, "decrypted": clair})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp1/hill", methods=["POST"])
def api_hill():
    try:
        from tp1_classique.hill import chiffrer_hill, dechiffrer_hill, valider_matrice_cle
        data = request.json
        msg = data.get("message", "")
        matrix = data.get("matrix", [[3, 3], [2, 5]])
        action = data.get("action", "encrypt")
        valid = valider_matrice_cle(matrix)
        if not valid:
            return jsonify({"error": "Matrice non inversible mod 26"}), 400
        if action == "encrypt":
            return jsonify({"result": chiffrer_hill(msg, matrix), "valid": valid})
        elif action == "decrypt":
            return jsonify({"result": dechiffrer_hill(msg, matrix)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP2 — Chiffrement symétrique
# ═══════════════════════════════════════════════════

@app.route("/api/tp2/aes", methods=["POST"])
def api_aes():
    try:
        from tp2_symetrique.aes_modes import (aes_ecb_chiffrer, aes_ecb_dechiffrer,
            aes_cbc_chiffrer, aes_cbc_dechiffrer, aes_ctr_chiffrer, aes_ctr_dechiffrer)
        data = request.json
        msg = data.get("message", "").encode()
        mode = data.get("mode", "CBC")
        action = data.get("action", "encrypt")
        key_size = int(data.get("key_size", 256))
        key = os.urandom(key_size // 8)
        if action == "encrypt":
            if mode == "ECB":
                ct = aes_ecb_chiffrer(msg, key)
                return jsonify({"ciphertext": ct.hex(), "key": key.hex()})
            elif mode == "CBC":
                ct, iv = aes_cbc_chiffrer(msg, key)
                return jsonify({"ciphertext": ct.hex(), "key": key.hex(), "iv": iv.hex()})
            elif mode == "CTR":
                ct, nonce = aes_ctr_chiffrer(msg, key)
                return jsonify({"ciphertext": ct.hex(), "key": key.hex(), "nonce": nonce.hex()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP3 — Chiffrement asymétrique
# ═══════════════════════════════════════════════════

@app.route("/api/tp3/rsa", methods=["POST"])
def api_rsa():
    try:
        from tp3_asymetrique.rsa import generer_paire_rsa, rsa_chiffrer_oaep, rsa_dechiffrer_oaep, exporter_cles
        data = request.json
        bits = int(data.get("bits", 2048))
        msg = data.get("message", "Hello RSA!").encode()
        t0 = time.perf_counter()
        priv, pub = generer_paire_rsa(bits)
        t_gen = time.perf_counter() - t0
        t0 = time.perf_counter()
        ct = rsa_chiffrer_oaep(msg, pub)
        t_enc = time.perf_counter() - t0
        t0 = time.perf_counter()
        pt = rsa_dechiffrer_oaep(ct, priv)
        t_dec = time.perf_counter() - t0
        pem = exporter_cles(priv, pub)
        return jsonify({
            "ciphertext": ct.hex()[:60] + "...",
            "decrypted": pt.decode(),
            "correct": pt == msg,
            "key_gen_ms": round(t_gen * 1000, 1),
            "encrypt_ms": round(t_enc * 1000, 2),
            "decrypt_ms": round(t_dec * 1000, 2),
            "public_key_pem": pem["public_pem"][:200] + "..."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp3/dh", methods=["POST"])
def api_dh():
    try:
        from tp3_asymetrique.diffie_hellman import echange_dh
        from tp3_asymetrique.mitm_attack import simulation_mitm
        data = request.json
        action = data.get("action", "exchange")
        if action == "exchange":
            res = echange_dh()
            return jsonify({
                "p_bits": res["p_bits"],
                "secrets_match": res["secrets_identiques"],
                "aes_key": res["cle_aes_hex"][:32] + "...",
                "a_pub": hex(res["A_pub"])[-16:] + "...",
                "b_pub": hex(res["B_pub"])[-16:] + "...",
            })
        elif action == "mitm":
            mitm = simulation_mitm()
            return jsonify(mitm)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP4 — Hachage
# ═══════════════════════════════════════════════════

@app.route("/api/tp4/hash", methods=["POST"])
def api_hash():
    try:
        data = request.json
        msg = data.get("message", "").encode()
        algo = data.get("algo", "sha256")
        h = hashlib.new(algo, msg).hexdigest()
        # Avalanche
        if len(msg) > 0:
            msg_mod = bytes([msg[0] ^ 0x01]) + msg[1:]
        else:
            msg_mod = b'\x00'
        h_mod = hashlib.new(algo, msg_mod).hexdigest()
        h_bytes = bytes.fromhex(h)
        h_mod_bytes = bytes.fromhex(h_mod)
        bits_diff = sum(bin(a ^ b).count('1') for a, b in zip(h_bytes, h_mod_bytes))
        bits_total = len(h_bytes) * 8
        return jsonify({
            "hash": h,
            "hash_modified": h_mod,
            "bits_diff": bits_diff,
            "bits_total": bits_total,
            "avalanche_pct": round(bits_diff / bits_total * 100, 1),
            "algo": algo.upper(),
            "output_bits": bits_total
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp4/sha256_scratch", methods=["POST"])
def api_sha256_scratch():
    try:
        from tp4_hachage.sha256_impl import sha256_impl
        data = request.json
        msg = data.get("message", "").encode()
        our = sha256_impl(msg)
        ref = hashlib.sha256(msg).hexdigest()
        return jsonify({"our_hash": our, "ref_hash": ref, "match": our == ref})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP5 — Signatures
# ═══════════════════════════════════════════════════

@app.route("/api/tp5/rsa_pss", methods=["POST"])
def api_rsa_pss():
    try:
        from tp5_signatures.rsa_pss import generer_paire, signer_rsa_pss, verifier_rsa_pss
        data = request.json
        msg = data.get("message", "Document à signer").encode()
        priv, pub = generer_paire(2048)
        sig = signer_rsa_pss(msg, priv)
        valid = verifier_rsa_pss(msg, sig, pub)
        falsified = not verifier_rsa_pss(msg + b"X", sig, pub)
        sig2 = signer_rsa_pss(msg, priv)
        return jsonify({
            "signature": sig.hex()[:60] + "...",
            "valid": valid,
            "falsification_detected": falsified,
            "non_deterministic": sig != sig2,
            "sig_size_bytes": len(sig)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp5/ecdsa", methods=["POST"])
def api_ecdsa():
    try:
        from tp5_signatures.dsa_ecdsa import ecdsa_generer_cles, ecdsa_signer, ecdsa_verifier
        data = request.json
        msg = data.get("message", "Document ECDSA").encode()
        priv, pub = ecdsa_generer_cles()
        sig = ecdsa_signer(msg, priv)
        valid = ecdsa_verifier(msg, sig, pub)
        falsified = not ecdsa_verifier(msg + b"X", sig, pub)
        return jsonify({
            "signature": sig.hex()[:60] + "...",
            "valid": valid,
            "falsification_detected": falsified,
            "sig_size_bytes": len(sig),
            "curve": "P-256"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP6 — Vote Paillier
# ═══════════════════════════════════════════════════

@app.route("/api/tp6/vote", methods=["POST"])
def api_vote():
    try:
        from phe import paillier
        data = request.json
        votes = data.get("votes", [1, 0, 1, 1, 0, 1])
        pub, priv = paillier.generate_paillier_keypair(n_length=1024)
        encrypted = [pub.encrypt(v) for v in votes]
        total_enc = encrypted[0]
        for v in encrypted[1:]:
            total_enc = total_enc + v
        total = priv.decrypt(total_enc)
        n = len(votes)
        return jsonify({
            "nb_voters": n,
            "yes": total,
            "no": n - total,
            "pct_yes": round(total / n * 100, 1),
            "correct": total == sum(votes),
            "homomorphic": True,
            "individual_votes_decrypted": False
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400



# ═══════════════════════════════════════════════════
#  API TP1 — OTP
# ═══════════════════════════════════════════════════

@app.route("/api/tp1/otp", methods=["POST"])
def api_otp():
    try:
        from tp1_classique.otp import chiffrer_otp, dechiffrer_otp, generer_cle_otp
        data = request.json
        msg = data.get("message", "").encode()
        action = data.get("action", "encrypt")
        if action == "encrypt":
            cle = generer_cle_otp(len(msg))
            ct = chiffrer_otp(msg, cle)
            return jsonify({"ciphertext": ct.hex(), "key": cle.hex(), "key_len": len(cle)})
        elif action == "reuse_demo":
            m1 = data.get("message", "Secret A").encode()
            m2 = data.get("message2", "Secret B").encode()
            maxl = max(len(m1), len(m2))
            m1 = m1.ljust(maxl, b'\x00'); m2 = m2.ljust(maxl, b'\x00')
            cle = generer_cle_otp(maxl)
            c1 = chiffrer_otp(m1, cle); c2 = chiffrer_otp(m2, cle)
            xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
            xor_pt = bytes(a ^ b for a, b in zip(m1, m2))
            return jsonify({"c1": c1.hex(), "c2": c2.hex(), "xor_ct": xor_ct.hex(), "xor_pt": xor_pt.hex(), "match": xor_ct == xor_pt, "vuln": "XOR des chiffrés = XOR des clairs !"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP2 — RC4 + DES + NIST
# ═══════════════════════════════════════════════════

@app.route("/api/tp2/rc4", methods=["POST"])
def api_rc4():
    try:
        from tp2_symetrique.rc4 import rc4_chiffrer, rc4_dechiffrer, ksa, prga
        data = request.json
        msg = data.get("message", "").encode()
        key = data.get("key", "SecretKey").encode()
        ct = rc4_chiffrer(msg, key)
        pt = rc4_dechiffrer(ct, key)
        S = ksa(key); ks = prga(S, min(16, len(msg)))
        return jsonify({"ciphertext": ct.hex(), "decrypted": pt.decode(errors='replace'), "correct": pt == msg, "keystream_16": ks.hex(), "key_hex": key.hex()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp2/des", methods=["POST"])
def api_des():
    try:
        from tp2_symetrique.des_modes import des_ecb_chiffrer, des_ecb_dechiffrer, des_cbc_chiffrer, des_cbc_dechiffrer, triple_des_cbc_chiffrer, triple_des_cbc_dechiffrer
        data = request.json
        msg = data.get("message", "").encode()
        mode = data.get("mode", "CBC")
        algo = data.get("algo", "DES")
        if algo == "3DES":
            key = os.urandom(24)
            ct, iv = triple_des_cbc_chiffrer(msg, key)
            pt = triple_des_cbc_dechiffrer(ct, key, iv)
            return jsonify({"ciphertext": ct.hex(), "key": key.hex(), "iv": iv.hex(), "decrypted": pt.decode(errors='replace'), "correct": pt == msg, "algo": "3DES-CBC"})
        else:
            key = b"DESKEY!!"
            if mode == "ECB":
                ct = des_ecb_chiffrer(msg, key)
                pt = des_ecb_dechiffrer(ct, key)
                return jsonify({"ciphertext": ct.hex(), "key": key.hex(), "decrypted": pt.decode(errors='replace'), "correct": pt == msg, "algo": "DES-ECB"})
            else:
                ct, iv = des_cbc_chiffrer(msg, key)
                pt = des_cbc_dechiffrer(ct, key, iv)
                return jsonify({"ciphertext": ct.hex(), "key": key.hex(), "iv": iv.hex(), "decrypted": pt.decode(errors='replace'), "correct": pt == msg, "algo": "DES-CBC"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp2/nist", methods=["POST"])
def api_nist():
    try:
        data = request.json
        algo = data.get("algo", "twofish")
        msg = data.get("message", "Test NIST finalist").encode()
        key = os.urandom(32)
        t0 = time.perf_counter()
        if algo == "twofish":
            from tp2_symetrique.nist_finalists.twofish_demo import twofish_encrypt, twofish_decrypt
            ct = twofish_encrypt(msg, key); pt = twofish_decrypt(ct, key)
            info = "Feistel modifié, 16 tours, S-Boxes dépendantes de la clé"
        elif algo == "serpent":
            from tp2_symetrique.nist_finalists.serpent_demo import serpent_encrypt
            ct = serpent_encrypt(msg, key); pt = None
            info = "SPN 32 tours, marge de sécurité maximale"
        elif algo == "rc6":
            from tp2_symetrique.nist_finalists.rc6_demo import rc6_encrypt, rc6_decrypt
            ct = rc6_encrypt(msg, key); pt = rc6_decrypt(ct, key)
            info = "Rotations dépendantes des données, 20 tours"
        elif algo == "mars":
            from tp2_symetrique.nist_finalists.mars_demo import mars_encrypt
            ct = mars_encrypt(msg, key); pt = None
            info = "Structure hétérogène 3 phases, IBM"
        t_enc = time.perf_counter() - t0
        return jsonify({"ciphertext": ct.hex()[:60] + "...", "correct": pt == msg if pt else "N/A (chiffrement seul)", "time_ms": round(t_enc * 1000, 1), "info": info, "algo": algo.upper()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP3 — ElGamal + ECC + Hybride
# ═══════════════════════════════════════════════════

@app.route("/api/tp3/elgamal", methods=["POST"])
def api_elgamal():
    try:
        from tp3_asymetrique.elgamal import elgamal_generer_cles, elgamal_chiffrer, elgamal_dechiffrer
        data = request.json
        M = int(data.get("message_int", 42))
        cle = elgamal_generer_cles()
        C1, C2 = elgamal_chiffrer(M, cle)
        D = elgamal_dechiffrer(C1, C2, cle)
        C1b, C2b = elgamal_chiffrer(M, cle)
        return jsonify({"M": M, "C1": hex(C1)[:20] + "...", "C2": hex(C2)[:20] + "...", "decrypted": D, "correct": D == M, "non_deterministic": (C1, C2) != (C1b, C2b)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp3/ecc", methods=["POST"])
def api_ecc():
    try:
        from tp3_asymetrique.ecc import demo_ecdh, demo_ecies
        data = request.json
        action = data.get("action", "ecdh")
        if action == "ecdh":
            res = demo_ecdh()
            return jsonify(res)
        elif action == "ecies":
            res = demo_ecies()
            return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp3/hybrid", methods=["POST"])
def api_hybrid():
    try:
        from tp3_asymetrique.hybrid_rsa_aes import generer_paire_rsa, chiffrement_hybride, dechiffrement_hybride
        data = request.json
        msg = data.get("message", "Message hybride RSA+AES-GCM").encode()
        priv, pub = generer_paire_rsa(2048)
        t0 = time.perf_counter()
        paquet = chiffrement_hybride(msg, pub)
        t_enc = time.perf_counter() - t0
        t0 = time.perf_counter()
        pt = dechiffrement_hybride(paquet, priv)
        t_dec = time.perf_counter() - t0
        return jsonify({"nonce": paquet['nonce'].hex(), "tag": paquet['tag'].hex(), "ciphertext": paquet['message_chiffre'].hex()[:40] + "...", "total_size": paquet['taille_totale'], "decrypted": pt.decode(), "correct": pt == msg, "enc_ms": round(t_enc * 1000, 2), "dec_ms": round(t_dec * 1000, 2)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP4 — MD5 Collision
# ═══════════════════════════════════════════════════

@app.route("/api/tp4/md5_collision", methods=["POST"])
def api_md5_collision():
    try:
        from tp4_hachage.md5_demo import collision_md5_connue, effet_avalanche_md5
        col = collision_md5_connue()
        av = effet_avalanche_md5(b"test message")
        return jsonify({"collision": col, "avalanche": av})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════
#  API TP5 — ElGamal Sign + DSA
# ═══════════════════════════════════════════════════

@app.route("/api/tp5/elgamal_sign", methods=["POST"])
def api_elgamal_sign():
    try:
        from tp5_signatures.elgamal_sign import generer_cles, signer, verifier
        data = request.json
        msg = data.get("message", "Document ElGamal").encode()
        cle = generer_cles()
        r, s = signer(msg, cle)
        valid = verifier(msg, r, s, cle)
        falsified = not verifier(msg + b"X", r, s, cle)
        return jsonify({"r": hex(r)[:30] + "...", "s": hex(s)[:30] + "...", "valid": valid, "falsification_detected": falsified})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tp5/dsa", methods=["POST"])
def api_dsa():
    try:
        from tp5_signatures.dsa_ecdsa import dsa_generer_cles, dsa_signer, dsa_verifier
        data = request.json
        msg = data.get("message", "Document DSA").encode()
        priv, pub = dsa_generer_cles(2048)
        sig = dsa_signer(msg, priv)
        valid = dsa_verifier(msg, sig, pub)
        falsified = not dsa_verifier(msg + b"X", sig, pub)
        return jsonify({"signature": sig.hex()[:60] + "...", "valid": valid, "falsification_detected": falsified, "sig_size": len(sig), "algo": "DSA-2048"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  🔐 CryptoLab — Interface Graphique")
    print("  Ouvrir : http://localhost:5000")
    print("=" * 50 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
