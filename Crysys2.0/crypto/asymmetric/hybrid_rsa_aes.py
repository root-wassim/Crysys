"""
TP3 - Exercice 3.2b : Chiffrement hybride RSA+AES
Module dédié avec benchmark et comparaison chiffrement pur RSA vs hybride
"""
import os, time
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def generer_paire_rsa(bits: int = 2048):
    """Génère une paire RSA."""
    priv = rsa.generate_private_key(65537, bits, default_backend())
    return priv, priv.public_key()


def chiffrement_hybride(message: bytes, cle_publique) -> dict:
    """
    1. Génère clé AES-256 aléatoire (session key)
    2. Chiffre le message avec AES-256-GCM (authentifié)
    3. Chiffre la clé AES avec RSA-OAEP
    """
    cle_aes = os.urandom(32)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(cle_aes), modes.GCM(nonce), default_backend())
    enc = cipher.encryptor()
    ct = enc.update(message) + enc.finalize()
    tag = enc.tag
    cle_chiffree = cle_publique.encrypt(
        cle_aes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        )
    )
    return {
        'cle_aes_chiffree': cle_chiffree,
        'nonce': nonce, 'tag': tag,
        'message_chiffre': ct,
        'taille_totale': len(cle_chiffree) + len(nonce) + len(tag) + len(ct)
    }


def dechiffrement_hybride(paquet: dict, cle_privee) -> bytes:
    """Déchiffrement hybride RSA+AES-GCM."""
    cle_aes = cle_privee.decrypt(
        paquet['cle_aes_chiffree'],
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        )
    )
    cipher = Cipher(
        algorithms.AES(cle_aes),
        modes.GCM(paquet['nonce'], paquet['tag']),
        default_backend()
    )
    dec = cipher.decryptor()
    return dec.update(paquet['message_chiffre']) + dec.finalize()


def benchmark_hybride(tailles_ko: list = None) -> dict:
    """Benchmark du chiffrement hybride pour différentes tailles."""
    if tailles_ko is None:
        tailles_ko = [1, 10, 100, 1024]
    priv, pub = generer_paire_rsa(2048)
    resultats = {}
    for taille in tailles_ko:
        data = os.urandom(taille * 1024)
        t0 = time.perf_counter()
        paquet = chiffrement_hybride(data, pub)
        t_enc = time.perf_counter() - t0
        t0 = time.perf_counter()
        _ = dechiffrement_hybride(paquet, priv)
        t_dec = time.perf_counter() - t0
        resultats[f"{taille}Ko"] = {
            'chiffrement_ms': t_enc * 1000,
            'dechiffrement_ms': t_dec * 1000,
            'overhead_octets': paquet['taille_totale'] - taille * 1024,
        }
    return resultats


def demo():
    print("=" * 60)
    print("  TP3 - Chiffrement Hybride RSA+AES")
    print("=" * 60)
    priv, pub = generer_paire_rsa(2048)
    msg = b"Ceci est un message confidentiel chiffre avec RSA+AES-GCM"
    print(f"\nMessage : {msg}")
    paquet = chiffrement_hybride(msg, pub)
    print(f"Clé AES chiffrée : {paquet['cle_aes_chiffree'].hex()[:32]}...")
    print(f"Nonce GCM : {paquet['nonce'].hex()}")
    print(f"Tag GCM : {paquet['tag'].hex()}")
    print(f"Taille totale : {paquet['taille_totale']} octets")
    recupere = dechiffrement_hybride(paquet, priv)
    print(f"Déchiffré : {recupere}")
    print(f"Intégrité : {recupere == msg}")
    print("\n--- Benchmark ---")
    bench = benchmark_hybride([1, 10, 100, 1024])
    for taille, r in bench.items():
        print(f"  {taille:>6s} : enc={r['chiffrement_ms']:.1f}ms | "
              f"dec={r['dechiffrement_ms']:.1f}ms | overhead={r['overhead_octets']} octets")
    print("\n--- Pourquoi hybride ? ---")
    print("  RSA est ~1000x plus lent qu'AES pour le bulk encryption.")
    print("  Hybride : RSA chiffre seulement la clé AES (32 octets),")
    print("  AES chiffre le message (arbitrairement grand).")
    print("  GCM fournit l'authentification (intégrité + confidentialité).")


if __name__ == "__main__":
    demo()
