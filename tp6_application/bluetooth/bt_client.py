"""
TP6 - Bluetooth : Client sécurisé (Windows compatible)
Se connecte au serveur BT via TCP et envoie des messages chiffrés AES-256-GCM
"""
import os, sys, hashlib, json, socket, argparse
from Crypto.Cipher import AES


def chiffrer_message_bt(message: str, cle_partagee: bytes) -> dict:
    """Chiffre un message avec AES-GCM."""
    nonce = os.urandom(12)
    cipher = AES.new(cle_partagee, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return {'nonce': nonce.hex(), 'tag': tag.hex(), 'ct': ct.hex()}


def dechiffrer_message_bt(paquet: dict, cle_partagee: bytes) -> str:
    """Déchiffre un message AES-GCM."""
    nonce = bytes.fromhex(paquet['nonce'])
    tag = bytes.fromhex(paquet['tag'])
    ct = bytes.fromhex(paquet['ct'])
    cipher = AES.new(cle_partagee, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode('utf-8')


def simuler_appairage() -> bytes:
    """Simule l'appairage Bluetooth (échange de clé via PIN)."""
    pin = "1234"
    return hashlib.sha256(f"BT_PAIRING_{pin}".encode()).digest()


def client_windows(host: str, port: int = 9800):
    """Client TCP simulant le transport Bluetooth RFCOMM."""
    cle = simuler_appairage()
    print(f"\n  [BT-CLIENT] Clé partagée : {cle.hex()[:32]}...")
    print(f"  [BT-CLIENT] Connexion à {host}:{port}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print(f"  [BT-CLIENT] ✅ Connecté !")
        print(f"  [BT-CLIENT] Tapez un message (ou 'quit') :\n")
        
        while True:
            msg = input("  > ")
            if msg.lower() == 'quit':
                break
            
            # Chiffrer et envoyer
            paquet = chiffrer_message_bt(msg, cle)
            data = json.dumps(paquet).encode()
            sock.sendall(len(data).to_bytes(4, 'big') + data)
            print(f"  📤 Envoyé (chiffré) : {paquet['ct'][:30]}...")
            
            # Recevoir la réponse
            length_data = sock.recv(4)
            if length_data:
                msg_len = int.from_bytes(length_data, 'big')
                resp_data = b''
                while len(resp_data) < msg_len:
                    chunk = sock.recv(min(4096, msg_len - len(resp_data)))
                    if not chunk:
                        break
                    resp_data += chunk
                resp = json.loads(resp_data.decode())
                resp_msg = dechiffrer_message_bt(resp, cle)
                print(f"  📥 Réponse : {resp_msg}")
                print(f"  ✅ Tag GCM vérifié\n")
    except ConnectionRefusedError:
        print(f"  ❌ Impossible de se connecter à {host}:{port}")
        print(f"     Vérifiez que le serveur est lancé.")
    except KeyboardInterrupt:
        print("\n  [BT-CLIENT] Déconnexion")
    finally:
        sock.close()


def demo():
    parser = argparse.ArgumentParser(description="Client Bluetooth chiffré")
    parser.add_argument('host', nargs='?', default='127.0.0.1', help='IP du serveur (défaut: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=9800, help='Port TCP (défaut: 9800)')
    args = parser.parse_args()

    print("=" * 60)
    print("  TP6 - Client Bluetooth Chiffré (Windows)")
    print("=" * 60)
    client_windows(args.host, args.port)


if __name__ == "__main__":
    demo()
