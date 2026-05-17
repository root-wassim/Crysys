"""
TP6 - Bluetooth : Serveur sécurisé (Windows compatible)
Communication chiffrée AES-256-GCM via sockets TCP (transport BT simulé)
Mode --simulate pour démonstration sans matériel
"""
import os, sys, hashlib, json, socket, threading, argparse
from Crypto.Cipher import AES


def chiffrer_message_bt(message: str, cle_partagee: bytes) -> dict:
    """Chiffre un message pour transmission Bluetooth avec AES-GCM."""
    nonce = os.urandom(12)
    cipher = AES.new(cle_partagee, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return {'nonce': nonce.hex(), 'tag': tag.hex(), 'ct': ct.hex()}


def dechiffrer_message_bt(paquet: dict, cle_partagee: bytes) -> str:
    """Déchiffre un message Bluetooth."""
    nonce = bytes.fromhex(paquet['nonce'])
    tag = bytes.fromhex(paquet['tag'])
    ct = bytes.fromhex(paquet['ct'])
    cipher = AES.new(cle_partagee, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode('utf-8')


def simuler_appairage() -> bytes:
    """Simule l'appairage Bluetooth (échange de clé via PIN)."""
    pin = "1234"
    cle = hashlib.sha256(f"BT_PAIRING_{pin}".encode()).digest()
    return cle


# ═══════════════════════════════════════════════════
#  Mode Windows : serveur TCP (transport simulant BT)
# ═══════════════════════════════════════════════════

def serveur_windows(host='0.0.0.0', port=9800):
    """
    Serveur TCP sur Windows simulant le transport Bluetooth RFCOMM.
    Chaque message est chiffré/déchiffré avec AES-256-GCM.
    """
    cle = simuler_appairage()
    print(f"\n  [BT-WIN] Clé partagée (PIN 1234) : {cle.hex()[:32]}...")
    
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(2)
    print(f"  [BT-WIN] Serveur en écoute sur {host}:{port}")
    print(f"  [BT-WIN] En attente de connexions...")

    def handle_client(conn, addr):
        print(f"\n  [BT-WIN] Connexion de {addr[0]}:{addr[1]}")
        try:
            while True:
                length_data = conn.recv(4)
                if not length_data or len(length_data) < 4:
                    break
                msg_len = int.from_bytes(length_data, 'big')
                data = b''
                while len(data) < msg_len:
                    chunk = conn.recv(min(4096, msg_len - len(data)))
                    if not chunk:
                        break
                    data += chunk
                
                paquet = json.loads(data.decode())
                msg = dechiffrer_message_bt(paquet, cle)
                print(f"  [BT-WIN] Reçu (chiffré) : {paquet['ct'][:30]}...")
                print(f"  [BT-WIN] Déchiffré      : {msg}")
                print(f"  [BT-WIN] Tag GCM vérifié ✅")
                
                # Répondre
                reponse = chiffrer_message_bt(f"ECHO: {msg}", cle)
                resp_data = json.dumps(reponse).encode()
                conn.sendall(len(resp_data).to_bytes(4, 'big') + resp_data)
        except Exception as e:
            print(f"  [BT-WIN] Erreur : {e}")
        finally:
            conn.close()
            print(f"  [BT-WIN] Déconnexion de {addr[0]}")

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n  [BT-WIN] Serveur arrêté")
    finally:
        srv.close()


# ═══════════════════════════════════════════════════
#  Mode simulation (sans réseau)
# ═══════════════════════════════════════════════════

def serveur_bluetooth_simulation():
    """Simulation complète sans matériel ni réseau."""
    cle = simuler_appairage()
    print(f"\n  === Bluetooth AES-GCM — Mode Simulation ===")
    print(f"  🔑 Clé partagée (pré-échangée) : {cle.hex()[:32]}...\n")
    
    messages = [
        "Bonjour depuis Bluetooth !",
        "Message confidentiel via BT",
        "Test intégrité AES-GCM",
    ]
    for msg in messages:
        paquet = chiffrer_message_bt(msg, cle)
        decrypte = dechiffrer_message_bt(paquet, cle)
        print(f"  📤 Message clair  : {msg}")
        print(f"  🔒 Chiffré (hex)  : {paquet['ct'][:30]}...")
        print(f"  🏷️  Tag GCM       : {paquet['tag']}")
        print(f"  📥 Déchiffré      : {decrypte}")
        print(f"  ✅ Intégrité OK   : {decrypte == msg}\n")

    # Démo : modification détectée
    print("  --- Test de falsification ---")
    paquet = chiffrer_message_bt("Message intègre", cle)
    paquet_falsifie = dict(paquet)
    ct_bytes = bytearray.fromhex(paquet_falsifie['ct'])
    ct_bytes[0] ^= 0xFF  # modifier 1 octet
    paquet_falsifie['ct'] = ct_bytes.hex()
    try:
        dechiffrer_message_bt(paquet_falsifie, cle)
        print("  ❌ Falsification NON détectée (bug !)")
    except Exception:
        print("  ✅ Falsification DÉTECTÉE — GCM refuse le message modifié !")


def demo():
    parser = argparse.ArgumentParser(description="Serveur Bluetooth chiffré")
    parser.add_argument('--simulate', action='store_true', help='Mode simulation sans réseau')
    parser.add_argument('--port', type=int, default=9800, help='Port TCP (défaut: 9800)')
    args = parser.parse_args()

    print("=" * 60)
    print("  TP6 - Serveur Bluetooth Chiffré (Windows)")
    print("=" * 60)

    if args.simulate:
        serveur_bluetooth_simulation()
    else:
        print("\n  Mode réseau TCP (simulant transport Bluetooth RFCOMM)")
        print("  Pour le mode simulation : python bt_server.py --simulate")
        serveur_windows(port=args.port)


if __name__ == "__main__":
    demo()
