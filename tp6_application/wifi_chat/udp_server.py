"""
TP6 - WiFi Chat : Serveur UDP INTERACTIF avec AES-256-GCM
Écoute les messages ET permet d'en envoyer (bidirectionnel)
"""
import socket, os, json, hashlib, threading, sys, datetime
from Crypto.Cipher import AES

PORT = 9999
CLE_PARTAGEE = hashlib.sha256(b"CryptoLab_WiFi_Chat_2024").digest()


def chiffrer_udp(message: str, cle: bytes = CLE_PARTAGEE) -> bytes:
    """Chiffre un message avec AES-256-GCM pour envoi UDP."""
    nonce = os.urandom(12)
    cipher = AES.new(cle, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    paquet = {'n': nonce.hex(), 't': tag.hex(), 'c': ct.hex()}
    return json.dumps(paquet).encode()


def dechiffrer_udp(data: bytes, cle: bytes = CLE_PARTAGEE) -> str:
    """Déchiffre un paquet UDP AES-256-GCM."""
    paquet = json.loads(data.decode())
    nonce = bytes.fromhex(paquet['n'])
    tag = bytes.fromhex(paquet['t'])
    ct = bytes.fromhex(paquet['c'])
    cipher = AES.new(cle, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode('utf-8')


def thread_ecoute(sock):
    """Thread qui écoute les messages entrants."""
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            heure = datetime.datetime.now().strftime("%H:%M:%S")
            try:
                msg = dechiffrer_udp(data)
                paquet = json.loads(data.decode())
                print(f"\r  📩 [{heure}] {addr[0]} → {msg}")
                print(f"     Nonce: {paquet['n'][:16]}... | Tag: {paquet['t'][:16]}... | ✅ GCM OK")
                print(f"  📤 Vous > ", end='', flush=True)
            except Exception as e:
                print(f"\r  ⚠️  [{addr[0]}] Déchiffrement échoué: {e}")
                print(f"  📤 Vous > ", end='', flush=True)
        except OSError:
            break


def serveur_chat():
    """Serveur UDP bidirectionnel — écoute ET envoie."""
    target = sys.argv[1] if len(sys.argv) > 1 else None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", PORT))

    print(f"\n  📡 Chat UDP chiffré AES-256-GCM")
    print(f"  🔑 Clé partagée : {CLE_PARTAGEE.hex()[:32]}...")
    print(f"  📡 Écoute sur le port {PORT}")
    if target:
        print(f"  📤 Envoi vers : {target}")
    else:
        print(f"  📤 Envoi vers : 127.0.0.1 (localhost)")
        print(f"     Pour envoyer ailleurs : python udp_server.py <IP_DESTINATION>")
    print(f"  ℹ️  Tapez vos messages ci-dessous (Ctrl+C pour quitter)\n")

    # Lancer le thread d'écoute
    t = threading.Thread(target=thread_ecoute, args=(sock,), daemon=True)
    t.start()

    dest = target or "127.0.0.1"
    try:
        while True:
            msg = input("  📤 Vous > ")
            if msg.strip():
                paquet = chiffrer_udp(msg)
                sock.sendto(paquet, (dest, PORT))
                heure = datetime.datetime.now().strftime("%H:%M:%S")
                p = json.loads(paquet.decode())
                print(f"     [{heure}] Envoyé ({len(paquet)} octets chiffrés)")
                print(f"     Nonce: {p['n'][:16]}... | Tag: {p['t'][:16]}...")
    except (KeyboardInterrupt, EOFError):
        print("\n  🛑 Chat terminé.")
    finally:
        sock.close()


if __name__ == "__main__":
    print("=" * 60)
    print("  TP6 — Chat WiFi UDP Chiffré (AES-256-GCM)")
    print("=" * 60)
    serveur_chat()
