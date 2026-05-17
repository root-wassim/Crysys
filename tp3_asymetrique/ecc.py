"""
TP3 - Exercice 3.4 : Cryptographie sur Courbes Elliptiques (ECC)
Arithmétique sur y²=x³+7 mod p, ECDH P-256, ECIES simplifié
"""

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ─────────────────────────────────────────────
#  Arithmétique sur courbe y²=x³+7 mod p (pédagogique)
# ─────────────────────────────────────────────

P_PETIT = 97       # module petit pour démonstration
A_COURBE = 0       # y² = x³ + 7 → a=0, b=7
B_COURBE = 7

POINT_INFINI = None  # point à l'infini (élément neutre)


def est_sur_courbe(P: tuple, p: int = P_PETIT) -> bool:
    """Vérifie que le point P est sur la courbe y² ≡ x³+7 mod p."""
    if P is POINT_INFINI:
        return True
    x, y = P
    return (y * y - x * x * x - B_COURBE) % p == 0


def inverser_mod(a: int, p: int) -> int:
    """Inverse modulaire via l'algorithme d'Euclide étendu."""
    if a == 0:
        raise ZeroDivisionError("Pas d'inverse de 0")
    return pow(a, p - 2, p)  # valide car p est premier


def additionner_points(P: tuple, Q: tuple, p: int = P_PETIT) -> tuple:
    """
    Addition de deux points sur la courbe elliptique.
    Loi de groupe : corde et tangente.
    """
    if P is POINT_INFINI:
        return Q
    if Q is POINT_INFINI:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P = -Q → résultat = point à l'infini
    if x1 == x2 and (y1 + y2) % p == 0:
        return POINT_INFINI

    if P == Q:
        # Doublement : pente = (3x² + a) / (2y)
        if y1 == 0:
            return POINT_INFINI
        num = (3 * x1 * x1 + A_COURBE) % p
        den = (2 * y1) % p
    else:
        # Addition : pente = (y2 - y1) / (x2 - x1)
        num = (y2 - y1) % p
        den = (x2 - x1) % p

    pente = (num * inverser_mod(den, p)) % p
    x3 = (pente * pente - x1 - x2) % p
    y3 = (pente * (x1 - x3) - y1) % p

    return (x3, y3)


def multiplier_scalaire(k: int, P: tuple, p: int = P_PETIT) -> tuple:
    """
    Multiplication scalaire : k·P via l'algorithme double-and-add.
    C'est l'opération de base de l'ECC. ECDLP : retrouver k depuis k·P est difficile.
    """
    resultat = POINT_INFINI
    courant = P
    while k > 0:
        if k & 1:  # bit de poids faible
            resultat = additionner_points(resultat, courant, p)
        courant = additionner_points(courant, courant, p)  # doublement
        k >>= 1
    return resultat


def trouver_point_generateur(p: int = P_PETIT) -> tuple:
    """Trouve un point générateur sur y²=x³+7 mod p (petit module)."""
    for x in range(1, p):
        rhs = (x * x * x + B_COURBE) % p
        # Cherche y tel que y² ≡ rhs mod p
        for y in range(1, p):
            if (y * y) % p == rhs:
                G = (x, y)
                if est_sur_courbe(G, p):
                    return G
    raise ValueError("Aucun générateur trouvé")


def demo_arithmetique_courbe():
    """Vérifie les propriétés du groupe sur y²=x³+7 mod 97."""
    p = P_PETIT
    G = trouver_point_generateur(p)
    print(f"  Courbe y²=x³+7 mod {p}")
    print(f"  Point générateur G = {G}")
    print(f"  G sur la courbe : {est_sur_courbe(G, p)}")

    # Associativité : (P+Q)+R = P+(Q+R)
    P = G
    Q = multiplier_scalaire(3, G, p)
    R = multiplier_scalaire(5, G, p)
    gauche = additionner_points(additionner_points(P, Q, p), R, p)
    droite = additionner_points(P, additionner_points(Q, R, p), p)
    print(f"  Associativité (P+Q)+R == P+(Q+R) : {gauche == droite}")

    # Commutativité
    PQ = additionner_points(P, Q, p)
    QP = additionner_points(Q, P, p)
    print(f"  Commutativité P+Q == Q+P : {PQ == QP}")

    # Multiplication scalaire
    k = 7
    kG = multiplier_scalaire(k, G, p)
    print(f"  7·G = {kG}")
    print(f"  7·G sur la courbe : {est_sur_courbe(kG, p)}")

    # Point à l'infini : P + (-P) = O
    neg_G = (G[0], (-G[1]) % p)
    zero = additionner_points(G, neg_G, p)
    print(f"  G + (-G) = {zero} (point à l'infini)")

    return G


# ─────────────────────────────────────────────
#  ECDH sur P-256 (via cryptography)
# ─────────────────────────────────────────────

def ecdh_p256() -> dict:
    """
    Échange ECDH sur la courbe P-256 (secp256r1).
    Dérive une clé AES-256 via SHA-256 depuis le secret partagé.
    """
    # Alice
    cle_priv_alice = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cle_pub_alice = cle_priv_alice.public_key()

    # Bob
    cle_priv_bob = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cle_pub_bob = cle_priv_bob.public_key()

    # Secret partagé ECDH (côté Alice)
    secret_alice = cle_priv_alice.exchange(ec.ECDH(), cle_pub_bob)

    # Secret partagé ECDH (côté Bob)
    secret_bob = cle_priv_bob.exchange(ec.ECDH(), cle_pub_alice)

    # Dérivation de clé AES-256
    cle_aes_alice = hashlib.sha256(secret_alice).digest()
    cle_aes_bob = hashlib.sha256(secret_bob).digest()

    return {
        'secrets_identiques': secret_alice == secret_bob,
        'cle_aes_hex': cle_aes_alice.hex(),
        'cle_aes_identique': cle_aes_alice == cle_aes_bob,
        'taille_secret_octets': len(secret_alice),
        'courbe': 'P-256 (secp256r1)',
    }


# ─────────────────────────────────────────────
#  ECIES simplifié (Chiffrement hybride ECDH + AES)
# ─────────────────────────────────────────────

def ecies_chiffrer(message: bytes, cle_publique_destinataire) -> dict:
    """
    ECIES (Elliptic Curve Integrated Encryption Scheme) simplifié.
    
    Algorithme :
    1. Génère une paire éphémère (e_priv, e_pub)
    2. Calcule le secret ECDH avec la clé publique du destinataire
    3. Dérive une clé AES-256 via SHA-256
    4. Chiffre le message avec AES-256-GCM
    5. Envoie (e_pub, iv, tag, message_chiffre)
    """
    # Clé éphémère
    e_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    e_pub = e_priv.public_key()

    # Secret ECDH
    secret = e_priv.exchange(ec.ECDH(), cle_publique_destinataire)

    # Dérivation de clé AES-256 et IV
    cle_aes = hashlib.sha256(secret).digest()
    iv = os.urandom(12)  # GCM utilise un nonce de 96 bits

    # Chiffrement AES-256-GCM
    cipher = Cipher(algorithms.AES(cle_aes), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    chiffre = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag

    # Sérialisation de la clé publique éphémère
    e_pub_bytes = e_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    return {
        'e_pub_bytes': e_pub_bytes,
        'iv': iv,
        'tag': tag,
        'message_chiffre': chiffre,
    }


def ecies_dechiffrer(paquet: dict, cle_privee_destinataire) -> bytes:
    """
    Déchiffrement ECIES.
    1. Récupère la clé publique éphémère
    2. Calcule le secret ECDH
    3. Dérive la clé AES, déchiffre et vérifie le tag GCM
    """
    # Reconstruction de la clé publique éphémère
    e_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), paquet['e_pub_bytes']
    )

    # Secret ECDH
    secret = cle_privee_destinataire.exchange(ec.ECDH(), e_pub)
    cle_aes = hashlib.sha256(secret).digest()

    # Déchiffrement AES-256-GCM
    cipher = Cipher(
        algorithms.AES(cle_aes),
        modes.GCM(paquet['iv'], paquet['tag']),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(paquet['message_chiffre']) + decryptor.finalize()


def demo():
    print("=" * 60)
    print("  TP3 - ECC (Courbes Elliptiques)")
    print("=" * 60)

    # Arithmétique pédagogique
    print("\n--- Arithmétique sur y²=x³+7 mod 97 ---")
    G = demo_arithmetique_courbe()

    # ECDH P-256
    print("\n--- ECDH sur P-256 ---")
    res = ecdh_p256()
    print(f"Courbe              : {res['courbe']}")
    print(f"Secrets identiques  : {res['secrets_identiques']}")
    print(f"Clés AES identiques : {res['cle_aes_identique']}")
    print(f"Clé AES (Alice)     : {res['cle_aes_hex'][:32]}...")
    print(f"Taille secret DH    : {res['taille_secret_octets']} octets")

    # ECIES
    print("\n--- ECIES simplifié (ECDH + AES-256-GCM) ---")
    cle_priv_bob = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cle_pub_bob = cle_priv_bob.public_key()

    message = b"Message confidentiel chiffre avec ECIES sur P-256"
    print(f"Message : {message}")

    paquet = ecies_chiffrer(message, cle_pub_bob)
    print(f"Chiffré (hex) : {paquet['message_chiffre'].hex()[:32]}...")
    print(f"Tag GCM : {paquet['tag'].hex()}")

    recupere = ecies_dechiffrer(paquet, cle_priv_bob)
    print(f"Déchiffré : {recupere}")
    print(f"Intégrité : {'OK' if recupere == message else 'ERREUR'}")

    print("\n  Note : ECC-256 offre une sécurité équivalente à RSA-3072 (NIST SP 800-57)")
    print("  Avantage : clés et chiffrés beaucoup plus petits.")


if __name__ == "__main__":
    demo()
