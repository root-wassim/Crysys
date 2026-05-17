"""
TP6 - TCP/TLS : Serveur sécurisé INTERACTIF
Serveur TCP/TLS multi-clients avec chat en temps réel
L'utilisateur voit les messages reçus et peut répondre
"""
import socket, ssl, os, sys, threading, datetime, ipaddress
from pathlib import Path

CERT_DIR = Path(__file__).parent / "certs"
PORT = 9443
clients = {}  # {conn: addr}
cle_serveur = None


def generer_certificat(cert_dir: Path = CERT_DIR):
    """Génère un certificat X.509 auto-signé."""
    cert_dir.mkdir(exist_ok=True)
    cert_file = cert_dir / "server.crt"
    key_file = cert_dir / "server.key"
    if cert_file.exists() and key_file.exists():
        return str(cert_file), str(key_file)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoLab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CryptoLab-Server"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]), critical=False)
            .sign(key, hashes.SHA256(), default_backend()))
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  🔐 Certificat généré : {cert_file}")
    return str(cert_file), str(key_file)


def handle_client(conn, addr, tls_info):
    """Gère un client connecté — reçoit ses messages en boucle."""
    nom = f"{addr[0]}:{addr[1]}"
    clients[conn] = addr
    print(f"\n  ✅ [{nom}] Connecté — Cipher: {tls_info}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            msg = data.decode('utf-8', errors='replace').strip()
            heure = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"  📩 [{heure}] {nom} → {msg}")
            # Echo automatique
            reponse = f"[SERVEUR {heure}] Reçu: {msg}"
            conn.sendall(reponse.encode())
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        clients.pop(conn, None)
        try:
            conn.close()
        except:
            pass
        print(f"  ❌ [{nom}] Déconnecté")


def serveur_tls():
    """Serveur TLS interactif multi-clients."""
    cert_file, key_file = generer_certificat()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    sock.listen(10)
    tls_sock = ctx.wrap_socket(sock, server_side=True)

    print(f"\n  🔌 Serveur TLS en écoute sur 0.0.0.0:{PORT}")
    print(f"  📜 Certificat : {cert_file}")
    print(f"  🔒 TLS activé — en attente de connexions...")
    print(f"  ℹ️  Ctrl+C pour arrêter\n")

    tls_sock.settimeout(1.0)
    try:
        while True:
            try:
                conn, addr = tls_sock.accept()
                cipher = conn.cipher()
                info = f"{cipher[0]}" if cipher else "inconnu"
                threading.Thread(target=handle_client, args=(conn, addr, info), daemon=True).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print(f"\n  🛑 Serveur arrêté. {len(clients)} client(s) déconnecté(s).")
    finally:
        tls_sock.close()


if __name__ == "__main__":
    print("=" * 60)
    print("  TP6 — Serveur TCP/TLS Sécurisé")
    print("=" * 60)
    serveur_tls()
