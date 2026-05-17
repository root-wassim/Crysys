"""
TP6 - Vote Électronique : Client de vote INTERACTIF
L'utilisateur se connecte, récupère la clé publique, et vote manuellement
"""
import socket, json, sys

try:
    from phe import paillier
    HAS_PAILLIER = True
except ImportError:
    HAS_PAILLIER = False

PORT = 9500


def obtenir_cle_publique(host: str, port: int = PORT):
    """Récupère la clé publique Paillier du serveur."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(json.dumps({'type': 'get_pubkey'}).encode())
    data = json.loads(sock.recv(8192).decode())
    sock.close()
    n = int(data['n'])
    return paillier.PaillierPublicKey(n)


def envoyer_vote(host: str, vote: int, pub, port: int = PORT):
    """Chiffre et envoie le vote."""
    v_enc = pub.encrypt(vote)
    payload = {
        'type': 'vote',
        'vote': {
            'ciphertext': str(v_enc.ciphertext()),
            'exponent': v_enc.exponent,
        }
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(json.dumps(payload).encode())
    reponse = json.loads(sock.recv(4096).decode())
    sock.close()
    return reponse, v_enc


def demander_resultats(host: str, port: int = PORT) -> dict:
    """Demande les résultats du vote."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(json.dumps({'type': 'resultat'}).encode())
    data = json.loads(sock.recv(8192).decode())
    sock.close()
    return data


def client_vote(host: str):
    """Client de vote interactif."""
    print(f"\n  🔌 Connexion au serveur {host}:{PORT}...")
    try:
        pub = obtenir_cle_publique(host)
    except ConnectionRefusedError:
        print(f"  ❌ Serveur non accessible — lancez d'abord :")
        print(f"     python vote_server.py")
        return
    
    print(f"  ✅ Clé publique Paillier reçue")
    print(f"     n = {str(pub.n)[:30]}...\n")

    print(f"  Commandes :")
    print(f"    1 = voter OUI    0 = voter NON")
    print(f"    r = voir résultats    q = quitter\n")

    try:
        while True:
            choix = input("  🗳️  Votre action > ").strip().lower()

            if choix == '1' or choix == 'oui':
                vote = 1
            elif choix == '0' or choix == 'non':
                vote = 0
            elif choix == 'r' or choix == 'resultat':
                res = demander_resultats(host)
                if 'erreur' in res:
                    print(f"  ⚠️  {res['erreur']}")
                else:
                    print(f"\n  📊 Résultats actuels :")
                    print(f"     Votants : {res['nb_votants']}")
                    print(f"     OUI : {res['oui']} | NON : {res['non']}")
                    print(f"     {res['pourcentage_oui']}% OUI\n")
                continue
            elif choix == 'q' or choix == 'quit':
                break
            else:
                print("  → 1=OUI, 0=NON, r=résultats, q=quitter")
                continue

            # Chiffrer et envoyer le vote
            print(f"  ⏳ Chiffrement du vote ({choix})...")
            rep, v_enc = envoyer_vote(host, vote, pub)
            ct_str = str(v_enc.ciphertext())
            print(f"  🔒 Vote chiffré : {ct_str[:40]}...")
            print(f"     Taille du chiffré : {len(ct_str)} chiffres")
            print(f"  📤 Envoyé au serveur : {rep.get('status', 'erreur')}")
            print(f"  🔒 Le serveur NE PEUT PAS déchiffrer ce vote individuel !\n")

    except (KeyboardInterrupt, EOFError):
        pass
    print("\n  👋 Déconnecté.")


if __name__ == "__main__":
    print("=" * 60)
    print("  TP6 — Client de Vote Électronique (Paillier)")
    print("=" * 60)
    if not HAS_PAILLIER:
        print("\n  ❌ pip install phe")
        sys.exit(1)
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    client_vote(host)
