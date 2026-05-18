"""
TP3 - Exercice 3.1b : Attaque Man-in-the-Middle sur DH
Module dédié — simulation complète + contre-mesures
"""
import os, random, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Premier sûr de 512 bits (MODP Group 1)
P_DH = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
G_DH = 2


def dh_paire(p=P_DH, g=G_DH):
    """Génère (clé_privée, clé_publique) DH."""
    x = random.randrange(2, p - 1)
    return x, pow(g, x, p)


def dh_secret(priv, pub_autre, p=P_DH):
    """Calcule le secret partagé."""
    return pow(pub_autre, priv, p)


def deriver_cle(secret: int) -> bytes:
    return hashlib.sha256(secret.to_bytes((secret.bit_length()+7)//8, 'big')).digest()


def simulation_mitm() -> dict:
    """
    Simule l'attaque MITM sur Diffie-Hellman.

    Alice ←→ Mallory ←→ Bob
    Mallory intercepte et substitue les clés publiques.
    """
    # Alice et Bob génèrent leurs clés
    a, A = dh_paire()
    b, B = dh_paire()
    # Mallory génère deux paires
    m1, M1 = dh_paire()  # envoyé à Bob (substitue A)
    m2, M2 = dh_paire()  # envoyé à Alice (substitue B)
    # Alice calcule son "secret" avec M2 (croit que c'est Bob)
    s_alice = dh_secret(a, M2)
    # Bob calcule son "secret" avec M1 (croit que c'est Alice)
    s_bob = dh_secret(b, M1)
    # Mallory calcule les deux secrets
    s_mallory_alice = dh_secret(m2, A)
    s_mallory_bob = dh_secret(m1, B)

    return {
        'alice_mallory_match': s_alice == s_mallory_alice,
        'bob_mallory_match': s_bob == s_mallory_bob,
        'alice_bob_different': s_alice != s_bob,
        'cle_alice': deriver_cle(s_alice).hex()[:16],
        'cle_bob': deriver_cle(s_bob).hex()[:16],
        'cle_mallory_a': deriver_cle(s_mallory_alice).hex()[:16],
        'cle_mallory_b': deriver_cle(s_mallory_bob).hex()[:16],
    }


def simulation_mitm_avec_signature() -> dict:
    """DH authentifié avec ECDSA (contre-mesure au MITM)."""
    # Clés ECDSA long-terme
    sk_alice = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pk_alice = sk_alice.public_key()
    sk_bob = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pk_bob = sk_bob.public_key()
    # DH
    a, A = dh_paire()
    b, B = dh_paire()
    # Alice signe A
    A_bytes = A.to_bytes((A.bit_length()+7)//8, 'big')
    sig_a = sk_alice.sign(A_bytes, ec.ECDSA(hashes.SHA256()))
    # Bob signe B
    B_bytes = B.to_bytes((B.bit_length()+7)//8, 'big')
    sig_b = sk_bob.sign(B_bytes, ec.ECDSA(hashes.SHA256()))
    # Vérifications
    try:
        pk_alice.verify(sig_a, A_bytes, ec.ECDSA(hashes.SHA256()))
        auth_a = True
    except Exception:
        auth_a = False
    try:
        pk_bob.verify(sig_b, B_bytes, ec.ECDSA(hashes.SHA256()))
        auth_b = True
    except Exception:
        auth_b = False
    # Secret
    s = dh_secret(a, B)
    return {
        'alice_authentifiee': auth_a,
        'bob_authentifie': auth_b,
        'mitm_impossible': auth_a and auth_b,
        'cle_partagee': deriver_cle(s).hex()[:32],
    }


def demo():
    print("=" * 60)
    print("  TP3 - Attaque MITM sur Diffie-Hellman")
    print("=" * 60)
    print("\n--- Échange DH normal ---")
    a, A = dh_paire()
    b, B = dh_paire()
    s1, s2 = dh_secret(a, B), dh_secret(b, A)
    print(f"Secrets identiques : {s1 == s2}")
    print("\n--- Attaque MITM ---")
    mitm = simulation_mitm()
    print(f"Alice-Mallory partagent un secret : {mitm['alice_mallory_match']}")
    print(f"Bob-Mallory partagent un secret   : {mitm['bob_mallory_match']}")
    print(f"Alice et Bob ont des secrets DIFFERENTS : {mitm['alice_bob_different']}")
    print(f"\n  Clé Alice         : {mitm['cle_alice']}...")
    print(f"  Clé Mallory→Alice : {mitm['cle_mallory_a']}...")
    print(f"  Clé Bob           : {mitm['cle_bob']}...")
    print(f"  Clé Mallory→Bob   : {mitm['cle_mallory_b']}...")
    print("\n--- Contre-mesure : DH + ECDSA ---")
    auth = simulation_mitm_avec_signature()
    print(f"Alice authentifiée : {auth['alice_authentifiee']}")
    print(f"Bob authentifié    : {auth['bob_authentifie']}")
    print(f"MITM bloqué        : {auth['mitm_impossible']}")


if __name__ == "__main__":
    demo()
