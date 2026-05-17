"""
TP6 - TCP/TLS : Client sécurisé INTERACTIF
L'utilisateur tape ses messages en temps réel, tout est chiffré par TLS
"""
import socket, ssl, sys, datetime
from pathlib import Path

CERT_DIR = Path(__file__).parent / "certs"
PORT = 9443


def client_tls(host: str, port: int = PORT):
    """Client TLS interactif — l'utilisateur tape les messages."""
    cert_file = CERT_DIR / "server.crt"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cert_file.exists():
        ctx.load_verify_locations(str(cert_file))
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        print("  ⚠️  Certificat serveur non trouvé — mode non-vérifié")

    print(f"  🔌 Connexion TLS à {host}:{port}...")
    with socket.create_connection((host, port)) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname="localhost") as tls:
            cipher = tls.cipher()
            print(f"  ✅ Connexion TLS établie !")
            print(f"  🔒 Protocole : {tls.version()}")
            print(f"  🔐 Cipher    : {cipher[0] if cipher else 'N/A'}")
            cert = tls.getpeercert()
            if cert:
                cn = dict(x[0] for x in cert.get('subject', []))
                print(f"  📜 Serveur   : {cn.get('commonName', 'N/A')}")
            print(f"\n  Tapez vos messages (ou 'quit' pour quitter) :\n")

            try:
                while True:
                    msg = input("  📤 Vous > ")
                    if msg.lower().strip() == 'quit':
                        break
                    if not msg.strip():
                        continue
                    # Envoyer le message (chiffré par TLS automatiquement)
                    tls.sendall(msg.encode())
                    heure = datetime.datetime.now().strftime("%H:%M:%S")
                    print(f"     [{heure}] Envoyé ({len(msg)} octets, chiffré TLS)")
                    # Recevoir la réponse
                    try:
                        tls.settimeout(3.0)
                        reponse = tls.recv(4096).decode('utf-8', errors='replace')
                        if reponse:
                            print(f"  📩 Serveur > {reponse}\n")
                    except socket.timeout:
                        print(f"     (pas de réponse)\n")
            except (KeyboardInterrupt, EOFError):
                pass
    print("\n  🔌 Déconnecté.")


if __name__ == "__main__":
    print("=" * 60)
    print("  TP6 — Client TCP/TLS Sécurisé")
    print("=" * 60)
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    try:
        client_tls(host, port)
    except ConnectionRefusedError:
        print(f"\n  ❌ Connexion refusée — le serveur n'est pas lancé.")
        print(f"     → Lancez d'abord : python server.py")
    except Exception as e:
        print(f"\n  ❌ Erreur : {e}")
