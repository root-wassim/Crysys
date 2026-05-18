"""
TP5 - Exercice 5.2 : Signature ElGamal
Signature, vérification, importance du nonce aléatoire
"""
import random, hashlib


# Premier sûr
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
G = 2


def hash_message(msg: bytes) -> int:
    """Hash le message en entier mod p-1."""
    return int(hashlib.sha256(msg).hexdigest(), 16) % (P - 1)


def generer_cles() -> dict:
    x = random.randrange(2, P - 1)
    y = pow(G, x, P)
    return {'x': x, 'y': y, 'p': P, 'g': G}


def signer(message: bytes, cle: dict) -> tuple[int, int]:
    """
    Signature ElGamal.
    1. Choisit k aléatoire, copremier avec p-1
    2. r = g^k mod p
    3. s = (H(m) - x·r) · k^(-1) mod (p-1)
    """
    p, g, x = cle['p'], cle['g'], cle['x']
    h = hash_message(message)
    while True:
        k = random.randrange(2, p - 1)
        from math import gcd
        if gcd(k, p - 1) != 1:
            continue
        r = pow(g, k, p)
        k_inv = pow(k, -1, p - 1)
        s = ((h - x * r) * k_inv) % (p - 1)
        if s != 0:
            return r, s


def verifier(message: bytes, r: int, s: int, cle: dict) -> bool:
    """
    Vérification : g^H(m) ≡ y^r · r^s mod p
    """
    p, g, y = cle['p'], cle['g'], cle['y']
    if not (0 < r < p):
        return False
    h = hash_message(message)
    gauche = pow(g, h, p)
    droite = (pow(y, r, p) * pow(r, s, p)) % p
    return gauche == droite


def demo_nonce_reutilise(cle: dict) -> dict:
    """
    Démontre la vulnérabilité de réutilisation du nonce k.
    Si le même k est utilisé pour deux messages différents,
    on peut retrouver la clé privée x.
    """
    p, g, x = cle['p'], cle['g'], cle['x']
    m1 = b"Premier message"
    m2 = b"Second message"
    h1 = hash_message(m1)
    h2 = hash_message(m2)
    # Même k (ERREUR DE SÉCURITÉ)
    from math import gcd
    while True:
        k = random.randrange(2, p - 1)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s1 = ((h1 - x * r) * k_inv) % (p - 1)
    s2 = ((h2 - x * r) * k_inv) % (p - 1)
    # Attaque : s1 - s2 = (h1 - h2) * k^(-1) mod (p-1)
    ds = (s1 - s2) % (p - 1)
    dh = (h1 - h2) % (p - 1)
    if gcd(ds, p - 1) == 1:
        k_retrouve = (dh * pow(ds, -1, p - 1)) % (p - 1)
        x_retrouve = ((h1 - k_retrouve * s1) * pow(r, -1, p - 1)) % (p - 1) if gcd(r, p-1) == 1 else None
    else:
        k_retrouve = None
        x_retrouve = None
    return {
        'meme_r': True,
        'k_original': k,
        'k_retrouve': k_retrouve,
        'k_correct': k_retrouve == k if k_retrouve else False,
        'cle_privee_compromise': x_retrouve == x if x_retrouve else False,
    }


def demo():
    print("=" * 60)
    print("  TP5 - Signature ElGamal")
    print("=" * 60)
    cle = generer_cles()
    msg = b"Document a signer avec ElGamal"
    r, s = signer(msg, cle)
    print(f"\nMessage : {msg}")
    print(f"r (tronqué) : {hex(r)[:20]}...")
    print(f"s (tronqué) : {hex(s)[:20]}...")
    print(f"Valide : {verifier(msg, r, s, cle)}")
    # Falsification
    print("\n--- Falsification ---")
    msg_faux = b"Document FALSIFIE"
    print(f"  Message falsifié valide ? {verifier(msg_faux, r, s, cle)}")
    # Nonce réutilisé
    print("\n--- Vulnérabilité nonce réutilisé ---")
    nonce_res = demo_nonce_reutilise(cle)
    print(f"  Même r (nonce réutilisé) : {nonce_res['meme_r']}")
    print(f"  k retrouvé : {nonce_res['k_correct']}")
    print(f"  Clé privée compromise : {nonce_res['cle_privee_compromise']}")
    print("\n  → JAMAIS réutiliser le nonce k ! (cf. hack PlayStation 3)")


if __name__ == "__main__":
    demo()
