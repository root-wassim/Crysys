"""
TP6 - WiFi Chat : Client UDP INTERACTIF avec AES-256-GCM
L'utilisateur tape des messages qui sont chiffrés et envoyés en temps réel
"""
import socket, os, json, hashlib, sys, datetime
from Crypto.Cipher import AES

PORT = 9999
CLE_PARTAGEE = hashlib.sha256(b"CryptoLab_WiFi_Chat_2024").digest()


def chiffrer_udp(message: str, cle: bytes = CLE_PARTAGEE) -> bytes:
    nonce = os.urandom(12)
    cipher = AES.new(cle, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return json.dumps({'n': nonce.hex(), 't': tag.hex(), 'c': ct.hex()}).encode()


def client_chat(host: str):
    """Client UDP interactif — l'utilisateur tape les messages."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if host == "255.255.255.255":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print(f"\n  📤 Client UDP → {host}:{PORT}")
    print(f"  🔑 Clé AES-256 : {CLE_PARTAGEE.hex()[:32]}...")
    print(f"  🔒 Chiffrement : AES-256-GCM (nonce unique par message)")
    print(f"\n  Tapez vos messages (Ctrl+C pour quitter) :\n")

    try:
        while True:
            msg = input("  📤 Vous > ")
            if not msg.strip():
                continue
            paquet = chiffrer_udp(msg)
            sock.sendto(paquet, (host, PORT))
            heure = datetime.datetime.now().strftime("%H:%M:%S")
            p = json.loads(paquet.decode())
            print(f"     [{heure}] ✅ Envoyé ({len(paquet)} octets)")
            print(f"     Clair   : \"{msg}\"")
            print(f"     Chiffré : {p['c'][:40]}...")
            print(f"     Nonce   : {p['n']}")
            print(f"     Tag GCM : {p['t']}\n")
    except (KeyboardInterrupt, EOFError):
        print("\n  🛑 Client arrêté.")
    finally:
        sock.close()


if __name__ == "__main__":
    print("=" * 60)
    print("  TP6 — Client UDP Chat Chiffré")
    print("=" * 60)
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    client_chat(host)
