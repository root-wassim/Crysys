"""
TP5 - Exercice 5.3 : DSA et ECDSA
Signatures DSA (FIPS 186) et ECDSA (courbes elliptiques)
"""
import os, time
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ─── DSA ──────────────────────────────────────────────────

def dsa_generer_cles(bits: int = 2048):
    priv = dsa.generate_private_key(bits, default_backend())
    return priv, priv.public_key()


def dsa_signer(message: bytes, cle_privee) -> bytes:
    return cle_privee.sign(message, hashes.SHA256())


def dsa_verifier(message: bytes, signature: bytes, cle_publique) -> bool:
    try:
        cle_publique.verify(signature, message, hashes.SHA256())
        return True
    except Exception:
        return False


# ─── ECDSA ────────────────────────────────────────────────

def ecdsa_generer_cles(courbe=None):
    if courbe is None:
        courbe = ec.SECP256R1()
    priv = ec.generate_private_key(courbe, default_backend())
    return priv, priv.public_key()


def ecdsa_signer(message: bytes, cle_privee) -> bytes:
    return cle_privee.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verifier(message: bytes, signature: bytes, cle_publique) -> bool:
    try:
        cle_publique.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ─── Comparaison ──────────────────────────────────────────

def benchmark_signatures() -> dict:
    """Compare DSA-2048 vs ECDSA-P256 vs ECDSA-P384."""
    msg = b"Message pour benchmark des signatures numeriques"
    resultats = {}

    # DSA-2048
    priv, pub = dsa_generer_cles(2048)
    t0 = time.perf_counter()
    sig = dsa_signer(msg, priv)
    t_sign = time.perf_counter() - t0
    t0 = time.perf_counter()
    dsa_verifier(msg, sig, pub)
    t_verif = time.perf_counter() - t0
    resultats['DSA-2048'] = {
        'signature_ms': t_sign * 1000,
        'verification_ms': t_verif * 1000,
        'taille_signature': len(sig),
    }

    # ECDSA P-256
    priv, pub = ecdsa_generer_cles(ec.SECP256R1())
    t0 = time.perf_counter()
    sig = ecdsa_signer(msg, priv)
    t_sign = time.perf_counter() - t0
    t0 = time.perf_counter()
    ecdsa_verifier(msg, sig, pub)
    t_verif = time.perf_counter() - t0
    resultats['ECDSA-P256'] = {
        'signature_ms': t_sign * 1000,
        'verification_ms': t_verif * 1000,
        'taille_signature': len(sig),
    }

    # ECDSA P-384
    priv, pub = ecdsa_generer_cles(ec.SECP384R1())
    t0 = time.perf_counter()
    sig = ecdsa_signer(msg, priv)
    t_sign = time.perf_counter() - t0
    t0 = time.perf_counter()
    ecdsa_verifier(msg, sig, pub)
    t_verif = time.perf_counter() - t0
    resultats['ECDSA-P384'] = {
        'signature_ms': t_sign * 1000,
        'verification_ms': t_verif * 1000,
        'taille_signature': len(sig),
    }

    return resultats


def demo():
    print("=" * 60)
    print("  TP5 - DSA et ECDSA")
    print("=" * 60)

    msg = b"Document officiel signe numeriquement"

    # DSA
    print("\n--- DSA-2048 ---")
    priv_dsa, pub_dsa = dsa_generer_cles()
    sig_dsa = dsa_signer(msg, priv_dsa)
    print(f"  Signature ({len(sig_dsa)} octets) : {sig_dsa.hex()[:40]}...")
    print(f"  Valide : {dsa_verifier(msg, sig_dsa, pub_dsa)}")
    print(f"  Falsification détectée : {not dsa_verifier(msg + b'X', sig_dsa, pub_dsa)}")

    # ECDSA
    print("\n--- ECDSA P-256 ---")
    priv_ec, pub_ec = ecdsa_generer_cles()
    sig_ec = ecdsa_signer(msg, priv_ec)
    print(f"  Signature ({len(sig_ec)} octets) : {sig_ec.hex()[:40]}...")
    print(f"  Valide : {ecdsa_verifier(msg, sig_ec, pub_ec)}")
    print(f"  Falsification détectée : {not ecdsa_verifier(msg + b'X', sig_ec, pub_ec)}")

    # Benchmark
    print("\n--- Benchmark comparatif ---")
    bench = benchmark_signatures()
    for nom, r in bench.items():
        print(f"  {nom:15s}: sign={r['signature_ms']:.2f}ms | "
              f"verif={r['verification_ms']:.2f}ms | taille={r['taille_signature']}B")

    print("\n--- Comparaison ---")
    print("  ECDSA-P256 offre une sécurité ≈ RSA-3072 / DSA-3072")
    print("  mais avec des signatures et clés ~10x plus petites.")
    print("  → ECDSA est préféré pour les applications modernes.")


if __name__ == "__main__":
    demo()
