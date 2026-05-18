"""
TP5 - Exercice 5.1 : RSA-PSS (Probabilistic Signature Scheme)
Signature, vérification, résistance à la falsification
"""
import os, time
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generer_paire(bits: int = 2048):
    priv = rsa.generate_private_key(65537, bits, default_backend())
    return priv, priv.public_key()


def signer_rsa_pss(message: bytes, cle_privee) -> bytes:
    """Signe un message avec RSA-PSS + SHA-256."""
    return cle_privee.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verifier_rsa_pss(message: bytes, signature: bytes, cle_publique) -> bool:
    """Vérifie une signature RSA-PSS."""
    try:
        cle_publique.verify(
            signature, message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def test_non_determinisme(message: bytes, cle_privee, cle_publique) -> dict:
    """PSS est probabiliste : deux signatures du même message diffèrent."""
    sig1 = signer_rsa_pss(message, cle_privee)
    sig2 = signer_rsa_pss(message, cle_privee)
    return {
        'signatures_differentes': sig1 != sig2,
        'sig1_valide': verifier_rsa_pss(message, sig1, cle_publique),
        'sig2_valide': verifier_rsa_pss(message, sig2, cle_publique),
    }


def test_falsification(message: bytes, cle_privee, cle_publique) -> dict:
    """Tente de falsifier un message signé."""
    sig = signer_rsa_pss(message, cle_privee)
    msg_falsifie = message + b" FALSIFIE"
    # Signature altérée
    sig_alteree = bytearray(sig)
    sig_alteree[0] ^= 0xFF
    sig_alteree = bytes(sig_alteree)
    return {
        'original_valide': verifier_rsa_pss(message, sig, cle_publique),
        'message_falsifie_detecte': not verifier_rsa_pss(msg_falsifie, sig, cle_publique),
        'signature_alteree_detectee': not verifier_rsa_pss(message, sig_alteree, cle_publique),
    }


def benchmark_rsa_pss() -> dict:
    """Benchmark signature/vérification pour RSA-1024/2048/4096."""
    msg = b"Message a signer pour benchmark" * 10
    resultats = {}
    for bits in [1024, 2048, 4096]:
        priv, pub = generer_paire(bits)
        t0 = time.perf_counter()
        sig = signer_rsa_pss(msg, priv)
        t_sign = time.perf_counter() - t0
        t0 = time.perf_counter()
        verifier_rsa_pss(msg, sig, pub)
        t_verif = time.perf_counter() - t0
        resultats[bits] = {
            'signature_ms': t_sign * 1000,
            'verification_ms': t_verif * 1000,
            'taille_signature': len(sig),
        }
    return resultats


def demo():
    print("=" * 60)
    print("  TP5 - RSA-PSS (Signature)")
    print("=" * 60)
    priv, pub = generer_paire(2048)
    msg = b"Document officiel a signer"
    sig = signer_rsa_pss(msg, priv)
    print(f"\nMessage   : {msg}")
    print(f"Signature : {sig.hex()[:40]}...")
    print(f"Valide    : {verifier_rsa_pss(msg, sig, pub)}")
    print("\n--- Non-déterminisme PSS ---")
    nd = test_non_determinisme(msg, priv, pub)
    print(f"  Signatures différentes : {nd['signatures_differentes']}")
    print(f"  Les deux valides       : {nd['sig1_valide'] and nd['sig2_valide']}")
    print("\n--- Résistance à la falsification ---")
    fals = test_falsification(msg, priv, pub)
    print(f"  Original valide           : {fals['original_valide']}")
    print(f"  Message falsifié détecté   : {fals['message_falsifie_detecte']}")
    print(f"  Signature altérée détectée : {fals['signature_alteree_detectee']}")
    print("\n--- Benchmark RSA-PSS ---")
    bench = benchmark_rsa_pss()
    for bits, r in bench.items():
        print(f"  RSA-{bits} : sign={r['signature_ms']:.1f}ms | "
              f"verif={r['verification_ms']:.2f}ms | taille={r['taille_signature']}B")


if __name__ == "__main__":
    demo()
