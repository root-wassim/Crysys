"""
TP4 - Exercices 4.1/4.2/4.3 : Fonctions de Hachage
MD5 (via hashlib), SHA-256 from scratch, SHA-512, HMAC, benchmarks
"""

import hashlib
import hmac
import os
import time
import struct
import math
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


# ─────────────────────────────────────────────
#  TP4.1 : MD5 via hashlib
# ─────────────────────────────────────────────

def md5_demo() -> dict:
    """
    Calcule MD5 sur 5 messages différents et vérifie la taille de sortie.
    """
    messages = {
        'vide': b'',
        '1 octet': b'\x42',
        '1 Ko': os.urandom(1024),
        '1 Mo': os.urandom(1024 * 1024),
        'texte': b'Cryptographie Appliquee - MD5'
    }

    resultats = {}
    for nom, msg in messages.items():
        h = hashlib.md5(msg).hexdigest()
        resultats[nom] = {
            'hash': h,
            'longueur_bits': len(h) * 4,
            'toujours_128_bits': len(h) == 32
        }
    return resultats


def effet_avalanche(message: bytes, algo: str = 'sha256') -> dict:
    """
    Modifie 1 bit du message et mesure le taux de bits différents dans le hash.
    Doit être ≈ 50%.
    """
    h_orig = hashlib.new(algo, message).digest()

    # Flip du bit 0 du premier octet
    message_modifie = bytes([message[0] ^ 0x01]) + message[1:] if message else b'\x00'
    h_modifie = hashlib.new(algo, message_modifie).digest()

    bits_diff = sum(bin(a ^ b).count('1') for a, b in zip(h_orig, h_modifie))
    bits_total = len(h_orig) * 8
    taux = bits_diff / bits_total * 100

    return {
        'algo': algo,
        'hash_orig': h_orig.hex(),
        'hash_modifie': h_modifie.hex(),
        'bits_differents': bits_diff,
        'bits_total': bits_total,
        'taux_pct': taux,
        'avalanche_ok': 40 <= taux <= 60
    }


# ─────────────────────────────────────────────
#  TP4.2 : SHA-256 implémenté from scratch
# ─────────────────────────────────────────────

# Constantes SHA-256 : premiers 32 bits des racines carrées des 8 premiers premiers
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Constantes SHA-256 : premiers 32 bits des racines cubiques des 64 premiers premiers
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

MASQUE32 = 0xFFFFFFFF


def rotr(x: int, n: int) -> int:
    """Rotation droite de n bits sur 32 bits."""
    return ((x >> n) | (x << (32 - n))) & MASQUE32


def sha256_padding(message: bytes) -> bytes:
    """
    Padding Merkle-Damgård pour SHA-256.
    Ajoute : 1 bit '1', des '0', puis la longueur sur 64 bits.
    Le message padé a une longueur multiple de 512 bits (64 octets).
    """
    L = len(message) * 8  # longueur en bits
    message += b'\x80'    # bit '1' suivi de '0'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('>Q', L)  # longueur sur 64 bits big-endian
    return message


def sha256_impl(message: bytes) -> str:
    """
    Implémentation complète de SHA-256 from scratch.
    Compatible avec hashlib.sha256().
    """
    # Padding
    msg = sha256_padding(message)

    # État initial
    H = H_INIT[:]

    # Traitement des blocs de 512 bits
    for i in range(0, len(msg), 64):
        bloc = msg[i:i + 64]

        # Expansion du message : 16 mots → 64 mots
        W = list(struct.unpack('>16I', bloc))
        for j in range(16, 64):
            s0 = rotr(W[j-15], 7) ^ rotr(W[j-15], 18) ^ (W[j-15] >> 3)
            s1 = rotr(W[j-2], 17) ^ rotr(W[j-2], 19) ^ (W[j-2] >> 10)
            W.append((W[j-16] + s0 + W[j-7] + s1) & MASQUE32)

        # Initialisation des variables de travail
        a, b, c, d, e, f, g, h = H

        # 64 tours de compression
        for j in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e & MASQUE32) & g)
            temp1 = (h + S1 + ch + K[j] + W[j]) & MASQUE32

            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & MASQUE32

            h, g, f, e = g, f, e, (d + temp1) & MASQUE32
            d, c, b, a = c, b, a, (temp1 + temp2) & MASQUE32

        # Mise à jour de l'état
        H = [(H[i] + v) & MASQUE32 for i, v in enumerate([a, b, c, d, e, f, g, h])]

    return ''.join(f'{v:08x}' for v in H)


def valider_sha256_impl() -> bool:
    """Valide l'implémentation SHA-256 contre hashlib sur 10 vecteurs."""
    vecteurs = [
        b'',
        b'abc',
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        b'The quick brown fox jumps over the lazy dog',
        b'Cryptographie appliquee',
        os.urandom(64),
        os.urandom(128),
        os.urandom(256),
        os.urandom(1024),
        b'\x00' * 55,  # test du padding
    ]

    tous_corrects = True
    for i, v in enumerate(vecteurs):
        notre = sha256_impl(v)
        ref = hashlib.sha256(v).hexdigest()
        correct = notre == ref
        if not correct:
            print(f"  ERREUR vecteur {i}: {notre} != {ref}")
            tous_corrects = False

    return tous_corrects


# ─────────────────────────────────────────────
#  TP4.3 : SHA-512 et benchmark
# ─────────────────────────────────────────────

def benchmark_hachage(taille_mo: float = 100.0) -> dict:
    """Benchmark MD5, SHA-256, SHA-512 sur taille_mo Mo."""
    donnees = os.urandom(int(taille_mo * 1024 * 1024))
    resultats = {}

    for algo in ['md5', 'sha256', 'sha512']:
        debut = time.perf_counter()
        hashlib.new(algo, donnees).hexdigest()
        duree = time.perf_counter() - debut
        resultats[algo] = {
            'duree_s': duree,
            'debit_mos': taille_mo / duree,
            'taille_sortie_bits': {'md5': 128, 'sha256': 256, 'sha512': 512}[algo]
        }

    # Graphique
    noms = ['MD5', 'SHA-256', 'SHA-512']
    debits = [resultats[a]['debit_mos'] for a in ['md5', 'sha256', 'sha512']]
    couleurs = ['#e74c3c', '#3498db', '#2ecc71']

    fig, ax = plt.subplots(figsize=(8, 5))
    barres = ax.bar(noms, debits, color=couleurs, alpha=0.85, width=0.5)
    ax.bar_label(barres, [f'{d:.0f} Mo/s' for d in debits], padding=3, fontsize=11)
    ax.set_ylabel("Débit (Mo/s)")
    ax.set_title(f"Benchmark des fonctions de hachage — {taille_mo:.0f} Mo")
    plt.tight_layout()
    chemin = str(Path(__file__).parent.parent / "outputs" / "hachage_benchmark.png")
    plt.savefig(chemin, dpi=120)
    plt.close()

    return resultats


def hmac_demo():
    """Démontre HMAC-SHA256 pour l'authentification de message."""
    cle = os.urandom(32)
    message = b"Message a authentifier"

    tag = hmac.new(cle, message, hashlib.sha256).hexdigest()

    # Vérification
    tag_verif = hmac.new(cle, message, hashlib.sha256).hexdigest()
    valide = hmac.compare_digest(tag, tag_verif)

    # Tentative de falsification
    message_falsifie = b"Message falsifie"
    tag_faux = hmac.new(cle, message_falsifie, hashlib.sha256).hexdigest()
    faux_detecte = not hmac.compare_digest(tag, tag_faux)

    return {
        'tag_hex': tag,
        'verification_ok': valide,
        'falsification_detectee': faux_detecte
    }


def demo():
    print("=" * 60)
    print("  TP4 - Fonctions de Hachage Cryptographique")
    print("=" * 60)

    # MD5
    print("\n--- MD5 ---")
    resultats_md5 = md5_demo()
    for nom, r in resultats_md5.items():
        print(f"  {nom:12s}: {r['hash'][:20]}... ({r['longueur_bits']} bits ✓)")

    # Effet avalanche
    print("\n--- Effet Avalanche ---")
    for algo in ['md5', 'sha256', 'sha512']:
        msg = b"test message avalanche"
        res = effet_avalanche(msg, algo)
        print(f"  {algo:8s}: {res['taux_pct']:.1f}% bits différents "
              f"({'OK' if res['avalanche_ok'] else 'PROBLEME'})")

    # SHA-256 from scratch
    print("\n--- SHA-256 from scratch ---")
    debut = time.perf_counter()
    valide = valider_sha256_impl()
    duree = time.perf_counter() - debut
    print(f"  Validation sur 10 vecteurs : {'TOUS CORRECTS ✓' if valide else 'ERREURS !'}")
    print(f"  Temps de validation : {duree*1000:.0f} ms")
    print(f"  SHA-256('abc') = {sha256_impl(b'abc')}")

    # HMAC
    print("\n--- HMAC-SHA256 ---")
    hmac_res = hmac_demo()
    print(f"  Tag : {hmac_res['tag_hex'][:32]}...")
    print(f"  Vérification OK    : {hmac_res['verification_ok']}")
    print(f"  Falsification détectée : {hmac_res['falsification_detectee']}")

    # Benchmark (réduit pour la démo)
    print("\n--- Benchmark (10 Mo) ---")
    bench = benchmark_hachage(10.0)
    for algo, r in bench.items():
        print(f"  {algo:8s}: {r['debit_mos']:6.0f} Mo/s | sortie {r['taille_sortie_bits']} bits")
    chemin = str(Path(__file__).parent.parent / "outputs" / "hachage_benchmark.png")
    print(f"  Graphique : {chemin}")

    print("\n  → SHA-512 est souvent plus rapide que SHA-256 sur les CPU 64 bits")
    print("    car ses opérations internes sont sur 64 bits.")


if __name__ == "__main__":
    demo()
