"""
TP3 - Exercice 3.2 : RSA
Génération de clés, chiffrement hybride RSA+AES, padding OAEP
"""

import os
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# ─────────────────────────────────────────────
#  Génération de clés RSA
# ─────────────────────────────────────────────

def generer_paire_rsa(bits: int) -> tuple:
    """
    Génère une paire de clés RSA.
    bits : 512, 1024, 2048 (512 = démo pédagogique seulement, non sécurisé)
    Retourne (cle_privee, cle_publique)
    """
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    return cle_privee, cle_privee.public_key()


def exporter_cles(cle_privee, cle_publique) -> dict:
    """Exporte les clés en format PEM."""
    pem_priv = cle_privee.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_pub = cle_publique.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {'prive_pem': pem_priv.decode(), 'public_pem': pem_pub.decode()}


# ─────────────────────────────────────────────
#  Chiffrement RSA-OAEP
# ─────────────────────────────────────────────

def rsa_chiffrer_oaep(message: bytes, cle_publique) -> bytes:
    """
    Chiffre avec RSA-OAEP (recommandé en production).
    OAEP apporte de l'aléatoire → deux chiffrements du même message diffèrent.
    Limite la taille du message : max_len = key_size_bytes - 2*hash_len - 2
    Pour RSA-2048 avec SHA-256 : max = 256 - 64 - 2 = 190 octets
    """
    return cle_publique.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_dechiffrer_oaep(cryptogramme: bytes, cle_privee) -> bytes:
    """Déchiffre avec RSA-OAEP."""
    return cle_privee.decrypt(
        cryptogramme,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─────────────────────────────────────────────
#  Chiffrement hybride RSA + AES
# ─────────────────────────────────────────────

def chiffrement_hybride_rsa_aes(message: bytes, cle_publique_rsa) -> dict:
    """
    Chiffrement hybride :
    1. Génère une clé AES-256 aléatoire (session key)
    2. Chiffre le message avec AES-256-CBC
    3. Chiffre la clé AES avec RSA-OAEP
    Retourne le paquet complet {cle_aes_chiffree, iv, message_chiffre}
    """
    # Génération de la clé AES et IV
    cle_aes = os.urandom(32)  # AES-256
    iv = os.urandom(16)

    # Chiffrement AES
    cipher = Cipher(algorithms.AES(cle_aes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding PKCS7
    padder = PKCS7(128).padder()
    padded = padder.update(message) + padder.finalize()
    message_chiffre = encryptor.update(padded) + encryptor.finalize()

    # Chiffrement de la clé AES avec RSA-OAEP
    cle_aes_chiffree = rsa_chiffrer_oaep(cle_aes, cle_publique_rsa)

    return {
        'cle_aes_chiffree': cle_aes_chiffree,
        'iv': iv,
        'message_chiffre': message_chiffre,
        'taille_message_original': len(message),
        'taille_paquet_total': len(cle_aes_chiffree) + len(iv) + len(message_chiffre)
    }


def dechiffrement_hybride_rsa_aes(paquet: dict, cle_privee_rsa) -> bytes:
    """
    Déchiffrement hybride :
    1. Déchiffre la clé AES avec RSA
    2. Déchiffre le message avec AES
    """
    # Récupération de la clé AES
    cle_aes = rsa_dechiffrer_oaep(paquet['cle_aes_chiffree'], cle_privee_rsa)

    # Déchiffrement AES
    cipher = Cipher(
        algorithms.AES(cle_aes),
        modes.CBC(paquet['iv']),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(paquet['message_chiffre']) + decryptor.finalize()

    # Dé-padding
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def benchmark_rsa_tailles(message_32: bytes) -> dict:
    """
    Benchmark RSA-512/1024/2048 sur une chaîne de 32 octets.
    Compare les temps de génération de clé, chiffrement et déchiffrement.
    """
    resultats = {}
    for bits in [1024, 2048, 4096]:
        # Génération
        debut = time.perf_counter()
        priv, pub = generer_paire_rsa(bits)
        t_gen = time.perf_counter() - debut

        # Chiffrement
        debut = time.perf_counter()
        chiffre = rsa_chiffrer_oaep(message_32, pub)
        t_chiff = time.perf_counter() - debut

        # Déchiffrement
        debut = time.perf_counter()
        _ = rsa_dechiffrer_oaep(chiffre, priv)
        t_dechiff = time.perf_counter() - debut

        resultats[bits] = {
            't_generation_ms': t_gen * 1000,
            't_chiffrement_ms': t_chiff * 1000,
            't_dechiffrement_ms': t_dechiff * 1000,
            'taille_chiffre_octets': len(chiffre)
        }
    return resultats


def demo():
    print("=" * 60)
    print("  TP3 - RSA")
    print("=" * 60)

    # Test multi-tailles
    message_32 = os.urandom(32)
    print("\n--- Génération et chiffrement RSA-1024/2048/4096 ---")
    bench = benchmark_rsa_tailles(message_32)
    for bits, r in bench.items():
        print(f"\n  RSA-{bits} :")
        print(f"    Génération clé    : {r['t_generation_ms']:.0f} ms")
        print(f"    Chiffrement       : {r['t_chiffrement_ms']:.2f} ms")
        print(f"    Déchiffrement     : {r['t_dechiffrement_ms']:.2f} ms")
        print(f"    Taille chiffré    : {r['taille_chiffre_octets']} octets")

    # Chiffrement hybride RSA-2048 + AES-256
    print("\n--- Chiffrement hybride RSA-2048 + AES-256 ---")
    priv_2048, pub_2048 = generer_paire_rsa(2048)

    # Fichier simulé de 1 Mo
    fichier_1mo = os.urandom(1024 * 1024)

    debut = time.perf_counter()
    paquet = chiffrement_hybride_rsa_aes(fichier_1mo, pub_2048)
    t_total = time.perf_counter() - debut

    debut2 = time.perf_counter()
    recupere = dechiffrement_hybride_rsa_aes(paquet, priv_2048)
    t_dechiffre = time.perf_counter() - debut2

    print(f"  Fichier original  : {len(fichier_1mo):,} octets")
    print(f"  Paquet total      : {paquet['taille_paquet_total']:,} octets")
    print(f"  Chiffrement hybride : {t_total*1000:.1f} ms")
    print(f"  Déchiffrement     : {t_dechiffre*1000:.1f} ms")
    print(f"  Intégrité vérifiée : {recupere == fichier_1mo}")

    # Export des clés
    print("\n--- Export des clés PEM ---")
    pem = exporter_cles(priv_2048, pub_2048)
    pem_path = str(Path(__file__).parent.parent / "outputs" / "rsa_public.pem")
    with open(pem_path, "w") as f:
        f.write(pem['public_pem'])
    print(f"  Clé publique exportée : {pem_path}")

    # Réponse aux questions théoriques
    print("\n--- Questions théoriques ---")
    print("Q: Pourquoi RSA ne peut pas chiffrer un message arbitrairement grand ?")
    print("R: RSA opère sur des entiers mod n. La taille maximale du message est")
    print("   bornée par la taille du module. Pour RSA-2048 avec OAEP-SHA256 :")
    print("   max = 256 - 2*32 - 2 = 190 octets.")
    print()
    print("Q: Que apporte OAEP vs RSA textbook ?")
    print("R: RSA textbook est déterministe (même M → même C) et malléable")
    print("   (C1·C2 = chiffrement de M1·M2). OAEP ajoute un masque aléatoire")
    print("   (randomization) qui rend le schéma IND-CCA2 sécurisé.")


if __name__ == "__main__":
    demo()
