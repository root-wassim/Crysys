"""
TP6 - Vote Électronique : Serveur de vote INTERACTIF
Reçoit les votes chiffrés Paillier des clients et attend le dépouillement manuel
"""
import socket, json, threading, sys

try:
    from phe import paillier
    HAS_PAILLIER = True
except ImportError:
    HAS_PAILLIER = False

PORT = 9500


class ServeurVote:
    def __init__(self, host="0.0.0.0", port=PORT):
        self.host = host
        self.port = port
        self.votes_chiffres = []
        self.pub = None
        self.priv = None
        self.lock = threading.Lock()

    def initialiser_election(self, n_bits=1024):
        """Génère les clés Paillier."""
        self.pub, self.priv = paillier.generate_paillier_keypair(n_length=n_bits)
        self.votes_chiffres = []
        return True

    def cle_publique_json(self) -> str:
        return json.dumps({'n': str(self.pub.n)})

    def recevoir_vote(self, vote_json: str):
        data = json.loads(vote_json)
        ct = int(data['ciphertext'])
        exponent = int(data['exponent'])
        vote_enc = paillier.EncryptedNumber(self.pub, ct, exponent)
        with self.lock:
            self.votes_chiffres.append(vote_enc)

    def depouiller(self) -> dict:
        with self.lock:
            if not self.votes_chiffres:
                return {'erreur': 'Aucun vote reçu'}
            total_chiffre = self.votes_chiffres[0]
            for v in self.votes_chiffres[1:]:
                total_chiffre = total_chiffre + v
            total = self.priv.decrypt(total_chiffre)
            nb = len(self.votes_chiffres)
        return {
            'nb_votants': nb,
            'oui': total,
            'non': nb - total,
            'pourcentage_oui': round(total / nb * 100, 1),
        }

    def _traiter_client(self, conn, addr):
        try:
            data = conn.recv(8192).decode()
            req = json.loads(data)
            if req.get('type') == 'get_pubkey':
                conn.sendall(self.cle_publique_json().encode())
                print(f"  📤 Clé publique envoyée à {addr[0]}")
            elif req.get('type') == 'vote':
                self.recevoir_vote(json.dumps(req['vote']))
                conn.sendall(b'{"status":"ok"}')
                with self.lock:
                    n = len(self.votes_chiffres)
                print(f"  🗳️  Vote reçu de {addr[0]} — Total: {n} vote(s)")
            elif req.get('type') == 'resultat':
                res = self.depouiller()
                conn.sendall(json.dumps(res).encode())
        except Exception as e:
            print(f"  ⚠️  Erreur ({addr[0]}): {e}")
        finally:
            conn.close()

    def demarrer_serveur(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(50)
        sock.settimeout(1.0)

        print(f"\n  🔌 Serveur de vote en écoute sur {self.host}:{self.port}")
        print(f"  🔑 Clé publique Paillier prête")
        print(f"  📊 Tapez 'r' pour dépouiller, 'q' pour quitter\n")

        # Thread d'écoute réseau
        def accepter():
            while self._actif:
                try:
                    conn, addr = sock.accept()
                    threading.Thread(target=self._traiter_client,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        self._actif = True
        t = threading.Thread(target=accepter, daemon=True)
        t.start()

        # Boucle interactive pour le serveur
        try:
            while True:
                cmd = input("  [serveur] > ").strip().lower()
                if cmd == 'r' or cmd == 'depouiller':
                    res = self.depouiller()
                    if 'erreur' in res:
                        print(f"  ⚠️  {res['erreur']}")
                    else:
                        print(f"\n  {'='*40}")
                        print(f"  📊 RÉSULTATS DU VOTE")
                        print(f"  {'='*40}")
                        print(f"  Votants : {res['nb_votants']}")
                        print(f"  ✅ OUI  : {res['oui']} ({res['pourcentage_oui']}%)")
                        print(f"  ❌ NON  : {res['non']} ({100 - res['pourcentage_oui']:.1f}%)")
                        print(f"  🔒 Votes individuels déchiffrés : JAMAIS")
                        print(f"  {'='*40}\n")
                elif cmd == 'q' or cmd == 'quit':
                    break
                elif cmd == 's' or cmd == 'status':
                    with self.lock:
                        print(f"  📊 Votes reçus : {len(self.votes_chiffres)}")
                else:
                    print("  Commandes: r=dépouiller, s=status, q=quitter")
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self._actif = False
            sock.close()
            print("\n  🛑 Serveur arrêté.")


if __name__ == "__main__":
    print("=" * 60)
    print("  TP6 — Serveur de Vote Électronique (Paillier)")
    print("=" * 60)
    if not HAS_PAILLIER:
        print("\n  ❌ pip install phe")
        sys.exit(1)
    srv = ServeurVote()
    print("\n  ⏳ Génération des clés Paillier (1024 bits)...")
    srv.initialiser_election()
    print(f"  ✅ Clés générées — n = {str(srv.pub.n)[:30]}...")
    srv.demarrer_serveur()
