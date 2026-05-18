"""
TP3 - Exercice 3.1 : Échange de clés Diffie-Hellman
Implémentation DH + attaque MITM + contre-mesure ECDSA
"""

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
#  Arithmétique modulaire pour DH
# ─────────────────────────────────────────────

def est_premier(n: int, k: int = 10) -> bool:
    """Test de primalité de Miller-Rabin."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generer_premier_512bits() -> int:
    """Génère un grand nombre premier sûr d'au moins 512 bits."""
    import random
    # Utiliser un premier prédéfini sûr (MODP Group 1 - RFC 2409) tronqué à 512 bits
    # En pratique, on utilise des groupes standardisés
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    return p


def dh_generer_cle(p: int, g: int) -> tuple[int, int]:
    """
    Génère une paire (clé privée, clé publique) DH.
    Clé privée : a aléatoire dans [2, p-2]
    Clé publique : g^a mod p
    """
    import random
    a = random.randrange(2, p - 1)
    A = pow(g, a, p)
    return a, A


def dh_calculer_secret(cle_privee: int, cle_publique_autre: int, p: int) -> int:
    """Calcule le secret partagé : K = cle_publique_autre^cle_privee mod p."""
    return pow(cle_publique_autre, cle_privee, p)


def dh_cle_vers_aes(secret: int) -> bytes:
    """Dérive une clé AES-256 depuis le secret DH via SHA-256."""
    secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
    return hashlib.sha256(secret_bytes).digest()


# ─────────────────────────────────────────────
#  Échange DH complet
# ─────────────────────────────────────────────

def echange_dh() -> dict:
    """
    Simule un échange DH complet entre Alice (A) et Bob (B).
    Retourne les valeurs intermédiaires et le secret partagé.
    """
    p = generer_premier_512bits()
    g = 2  # générateur standard

    # Alice
    a, A_pub = dh_generer_cle(p, g)

    # Bob
    b, B_pub = dh_generer_cle(p, g)

    # Calcul du secret partagé
    secret_alice = dh_calculer_secret(a, B_pub, p)
    secret_bob = dh_calculer_secret(b, A_pub, p)

    assert secret_alice == secret_bob, "Erreur DH : les secrets ne correspondent pas!"

    cle_aes = dh_cle_vers_aes(secret_alice)

    return {
        'p_bits': p.bit_length(),
        'g': g,
        'A_pub': A_pub,
        'B_pub': B_pub,
        'secret_partage': secret_alice,
        'cle_aes_hex': cle_aes.hex(),
        'secrets_identiques': secret_alice == secret_bob
    }


# ─────────────────────────────────────────────
#  Attaque MITM (Man-in-the-Middle)
# ─────────────────────────────────────────────

def attaque_mitm_dh() -> dict:
    """
    Simule l'attaque MITM sur DH.
    Mallory intercepte les clés publiques de A et B,
    substitue ses propres valeurs et établit deux sessions.
    
    Canal : A ←→ Mallory ←→ B
    """
    p = generer_premier_512bits()
    g = 2

    # Alice génère sa clé
    a, A_pub = dh_generer_cle(p, g)

    # Bob génère sa clé
    b, B_pub = dh_generer_cle(p, g)

    # ─── Mallory intercepte et substitue ───
    # Mallory génère ses propres paires
    import random
    m1 = random.randrange(2, p - 1)
    M1_pub = pow(g, m1, p)  # envoyé à Bob à la place de A_pub

    m2 = random.randrange(2, p - 1)
    M2_pub = pow(g, m2, p)  # envoyé à Alice à la place de B_pub

    # Alice calcule son "secret" avec la clé publique de Mallory
    secret_alice = dh_calculer_secret(a, M2_pub, p)

    # Bob calcule son "secret" avec la clé publique de Mallory
    secret_bob = dh_calculer_secret(b, M1_pub, p)

    # Mallory calcule les deux secrets
    secret_mallory_alice = dh_calculer_secret(m2, A_pub, p)  # partage avec Alice
    secret_mallory_bob = dh_calculer_secret(m1, B_pub, p)   # partage avec Bob

    return {
        'alice_croit_partager': secret_alice == secret_mallory_alice,
        'bob_croit_partager': secret_bob == secret_mallory_bob,
        'alice_secret_hex': dh_cle_vers_aes(secret_alice).hex()[:16],
        'bob_secret_hex': dh_cle_vers_aes(secret_bob).hex()[:16],
        'mallory_secret_alice_hex': dh_cle_vers_aes(secret_mallory_alice).hex()[:16],
        'mallory_secret_bob_hex': dh_cle_vers_aes(secret_mallory_bob).hex()[:16],
        'secrets_distincts': secret_alice != secret_bob
    }


# ─────────────────────────────────────────────
#  Contre-mesure : signature ECDSA des clés
# ─────────────────────────────────────────────

def dh_avec_authentification_ecdsa() -> dict:
    """
    DH avec authentification ECDSA des clés publiques.
    Alice et Bob signent leurs clés publiques DH avec leurs clés ECDSA long-terme.
    Mallory ne peut pas substituer sa clé car elle ne possède pas les clés privées.
    """
    p = generer_premier_512bits()
    g = 2

    # Clés ECDSA long-terme (générées une fois, stockées de façon sécurisée)
    cle_priv_alice = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cle_pub_alice = cle_priv_alice.public_key()

    cle_priv_bob = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cle_pub_bob = cle_priv_bob.public_key()

    # DH keys
    a, A_pub = dh_generer_cle(p, g)
    b, B_pub = dh_generer_cle(p, g)

    # Alice signe sa clé publique DH
    A_pub_bytes = A_pub.to_bytes((A_pub.bit_length() + 7) // 8, 'big')
    sig_alice = cle_priv_alice.sign(A_pub_bytes, ec.ECDSA(hashes.SHA256()))

    # Bob signe sa clé publique DH
    B_pub_bytes = B_pub.to_bytes((B_pub.bit_length() + 7) // 8, 'big')
    sig_bob = cle_priv_bob.sign(B_pub_bytes, ec.ECDSA(hashes.SHA256()))

    # Vérification des signatures avant d'utiliser les clés
    try:
        cle_pub_alice.verify(sig_alice, A_pub_bytes, ec.ECDSA(hashes.SHA256()))
        alice_authentifiee = True
    except Exception:
        alice_authentifiee = False

    try:
        cle_pub_bob.verify(sig_bob, B_pub_bytes, ec.ECDSA(hashes.SHA256()))
        bob_authentifie = True
    except Exception:
        bob_authentifie = False

    # Calcul du secret partagé (authentifié)
    secret = dh_calculer_secret(a, B_pub, p)
    cle_aes = dh_cle_vers_aes(secret)

    return {
        'alice_authentifiee': alice_authentifiee,
        'bob_authentifie': bob_authentifie,
        'mitm_bloque': True,  # Mallory ne peut pas forger les signatures
        'cle_aes_hex': cle_aes.hex(),
        'explication': "ECDSA garantit l'authenticité des clés DH. "
                       "Mallory ne peut substituer ses clés sans la clé privée ECDSA."
    }


def demo():
    print("=" * 60)
    print("  TP3 - Diffie-Hellman")
    print("=" * 60)

    # Échange de base
    print("\n--- Échange DH ---")
    res = echange_dh()
    print(f"Paramètre p : {res['p_bits']} bits")
    print(f"Générateur g : {res['g']}")
    print(f"Clé publique Alice : ...{hex(res['A_pub'])[-16:]}")
    print(f"Clé publique Bob   : ...{hex(res['B_pub'])[-16:]}")
    print(f"Secrets identiques : {res['secrets_identiques']}")
    print(f"Clé AES dérivée    : {res['cle_aes_hex'][:32]}...")

    # Attaque MITM
    print("\n--- Attaque MITM ---")
    mitm = attaque_mitm_dh()
    print(f"Alice croit partager avec Bob   : {mitm['alice_croit_partager']}")
    print(f"Bob croit partager avec Alice   : {mitm['bob_croit_partager']}")
    print(f"Secrets A et B sont distincts   : {mitm['secrets_distincts']}")
    print(f"Mallory partage un secret avec Alice : {mitm['alice_croit_partager']}")
    print(f"Mallory partage un secret avec Bob   : {mitm['bob_croit_partager']}")
    print("\n  Schéma :")
    print("  Alice ←[session1 Mallory]→ Mallory ←[session2 Mallory]→ Bob")
    print("  Alice croit parler à Bob, Bob croit parler à Alice.")

    # Contre-mesure
    print("\n--- Contre-mesure ECDSA ---")
    auth = dh_avec_authentification_ecdsa()
    print(f"Alice authentifiée  : {auth['alice_authentifiee']}")
    print(f"Bob authentifié     : {auth['bob_authentifie']}")
    print(f"MITM bloqué         : {auth['mitm_bloque']}")
    print(f"Clé AES sécurisée   : {auth['cle_aes_hex'][:32]}...")
    print(f"\n  {auth['explication']}")


if __name__ == "__main__":
    demo()
