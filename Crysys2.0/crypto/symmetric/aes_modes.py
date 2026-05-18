"""
TP2 - Exercice 2.3 : AES (Advanced Encryption Standard)
Modes ECB/CBC/CTR, effet avalanche, nonce-reuse, benchmark AES-128/192/256
"""

import os
import time
import numpy as np
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


BLOCK_SIZE = 16  # AES : 128 bits


# ─────────────────────────────────────────────
#  Fonctions de chiffrement par mode
# ─────────────────────────────────────────────

def aes_ecb_chiffrer(message: bytes, cle: bytes) -> bytes:
    cipher = AES.new(cle, AES.MODE_ECB)
    return cipher.encrypt(pad(message, BLOCK_SIZE))


def aes_ecb_dechiffrer(cryptogramme: bytes, cle: bytes) -> bytes:
    cipher = AES.new(cle, AES.MODE_ECB)
    return unpad(cipher.decrypt(cryptogramme), BLOCK_SIZE)


def aes_cbc_chiffrer(message: bytes, cle: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(cle, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(message, BLOCK_SIZE)), iv


def aes_cbc_dechiffrer(cryptogramme: bytes, cle: bytes, iv: bytes) -> bytes:
    cipher = AES.new(cle, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(cryptogramme), BLOCK_SIZE)


def aes_ctr_chiffrer(message: bytes, cle: bytes, nonce: bytes = None) -> tuple[bytes, bytes]:
    """CTR mode : pas de padding nécessaire, nonce de 8 octets."""
    if nonce is None:
        nonce = os.urandom(8)
    cipher = AES.new(cle, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(message), nonce


def aes_ctr_dechiffrer(cryptogramme: bytes, cle: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(cle, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(cryptogramme)


# ─────────────────────────────────────────────
#  Visualisation modes sur image
# ─────────────────────────────────────────────

def comparer_modes_image(taille: int = 64) -> str:
    """Chiffre une image avec ECB, CBC, CTR et compare visuellement."""
    # Image avec motifs géométriques
    image = np.zeros((taille, taille), dtype=np.uint8)
    for i in range(taille):
        for j in range(taille):
            dist_centre = ((i - taille//2)**2 + (j - taille//2)**2) ** 0.5
            if dist_centre < taille // 4:
                image[i, j] = 220
            elif (i // 8 + j // 8) % 2 == 0:
                image[i, j] = 120

    image_bytes = image.tobytes()
    cle_128 = os.urandom(16)
    cle_256 = os.urandom(32)

    # ECB-128
    n = len(image_bytes)
    padded = pad(image_bytes, BLOCK_SIZE)
    ecb = AES.new(cle_128, AES.MODE_ECB).encrypt(padded)[:n]

    # CBC-256
    cbc, _ = aes_cbc_chiffrer(image_bytes, cle_256)
    cbc = cbc[:n]

    # CTR-256
    ctr, _ = aes_ctr_chiffrer(image_bytes, cle_256)

    fig, axes = plt.subplots(1, 4, figsize=(14, 4))
    for ax, data, title in zip(axes,
        [image, ecb, cbc, ctr],
        ["Originale", "AES-128-ECB\n(motifs visibles!)", "AES-256-CBC", "AES-256-CTR"]):
        arr = np.frombuffer(data, dtype=np.uint8)[:n]
        axes_img = ax.imshow(arr.reshape(taille, taille), cmap='gray', vmin=0, vmax=255)
        ax.set_title(title, fontsize=10)
        ax.axis('off')

    plt.suptitle("Comparaison AES : ECB vs CBC vs CTR", fontweight='bold')
    plt.tight_layout()
    chemin = str(Path(__file__).parent.parent / "outputs" / "aes_modes_image.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


# ─────────────────────────────────────────────
#  Effet avalanche CBC
# ─────────────────────────────────────────────

def effet_avalanche_cbc(message: bytes, cle: bytes) -> str:
    """
    Modifie 1 bit de l'IV et mesure la propagation bloc par bloc.
    Retourne le chemin du graphique.
    """
    iv_original = os.urandom(BLOCK_SIZE)
    # Flip du bit 0 du premier octet
    iv_modifie = bytes([iv_original[0] ^ 0x01]) + iv_original[1:]

    chiffre_orig, _ = aes_cbc_chiffrer(message, cle, iv_original)
    chiffre_mod, _ = aes_cbc_chiffrer(message, cle, iv_modifie)

    nb_blocs = min(len(chiffre_orig), len(chiffre_mod)) // BLOCK_SIZE
    taux_par_bloc = []
    for b in range(nb_blocs):
        bloc_o = chiffre_orig[b*BLOCK_SIZE:(b+1)*BLOCK_SIZE]
        bloc_m = chiffre_mod[b*BLOCK_SIZE:(b+1)*BLOCK_SIZE]
        bits_diff = sum(bin(a ^ b).count('1') for a, b in zip(bloc_o, bloc_m))
        taux_par_bloc.append(bits_diff / (BLOCK_SIZE * 8) * 100)

    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(range(1, nb_blocs + 1), taux_par_bloc, color='steelblue', alpha=0.8)
    ax.axhline(50, color='red', linestyle='--', label='50% (attendu)')
    ax.set_xlabel("Numéro de bloc")
    ax.set_ylabel("% de bits différents")
    ax.set_title("Effet avalanche AES-CBC : modification de 1 bit du IV")
    ax.legend()
    plt.tight_layout()
    chemin = str(Path(__file__).parent.parent / "outputs" / "aes_avalanche_cbc.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


# ─────────────────────────────────────────────
#  Vulnérabilité nonce-reuse CTR
# ─────────────────────────────────────────────

def vulnerabilite_nonce_reuse_ctr(m1: bytes, m2: bytes, cle: bytes) -> dict:
    """
    Démontre la vulnérabilité nonce-reuse en CTR.
    Avec le même nonce : C1 = M1⊕KS, C2 = M2⊕KS
    → C1⊕C2 = M1⊕M2 (identique à l'OTP avec réutilisation)
    """
    nonce_fixe = os.urandom(8)  # ERREUR : réutilisation du même nonce
    c1, _ = aes_ctr_chiffrer(m1, cle, nonce_fixe)
    c2, _ = aes_ctr_chiffrer(m2, cle, nonce_fixe)

    xor_c1_c2 = bytes(a ^ b for a, b in zip(c1, c2))
    xor_m1_m2 = bytes(a ^ b for a, b in zip(m1, m2))

    return {
        'xor_chiffres': xor_c1_c2.hex(),
        'xor_clairs': xor_m1_m2.hex(),
        'egal': xor_c1_c2 == xor_m1_m2
    }


# ─────────────────────────────────────────────
#  Benchmark AES-128/192/256
# ─────────────────────────────────────────────

def benchmark_aes(taille_mo: float = 10.0) -> dict:
    """Benchmark AES-128 vs AES-192 vs AES-256 en mode CBC."""
    donnees = os.urandom(int(taille_mo * 1024 * 1024))
    resultats = {}

    for bits in [128, 192, 256]:
        octets = bits // 8
        cle = os.urandom(octets)
        iv = os.urandom(BLOCK_SIZE)

        # Chiffrement
        debut = time.perf_counter()
        cipher = AES.new(cle, AES.MODE_CBC, iv=iv)
        chiffre = cipher.encrypt(pad(donnees, BLOCK_SIZE))
        t_chiffre = time.perf_counter() - debut

        # Déchiffrement
        debut = time.perf_counter()
        cipher2 = AES.new(cle, AES.MODE_CBC, iv=iv)
        _ = unpad(cipher2.decrypt(chiffre), BLOCK_SIZE)
        t_dechiffre = time.perf_counter() - debut

        resultats[bits] = {
            'tours': {128: 10, 192: 12, 256: 14}[bits],
            'chiffrement_mos': taille_mo / t_chiffre,
            'dechiffrement_mos': taille_mo / t_dechiffre,
        }

    # Graphique
    noms = [f"AES-{b}" for b in [128, 192, 256]]
    debits_chiffre = [resultats[b]['chiffrement_mos'] for b in [128, 192, 256]]
    debits_dechiffre = [resultats[b]['dechiffrement_mos'] for b in [128, 192, 256]]

    x = np.arange(3)
    width = 0.35
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - width/2, debits_chiffre, width, label='Chiffrement', color='steelblue', alpha=0.8)
    ax.bar(x + width/2, debits_dechiffre, width, label='Déchiffrement', color='coral', alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(noms)
    ax.set_ylabel("Débit (Mo/s)")
    ax.set_title(f"Benchmark AES — {taille_mo} Mo, mode CBC")
    ax.legend()
    plt.tight_layout()
    plt.savefig(str(Path(__file__).parent.parent / "outputs" / "aes_benchmark.png"), dpi=120)
    plt.close()

    return resultats


def demo():
    print("=" * 60)
    print("  TP2 - AES : Advanced Encryption Standard")
    print("=" * 60)

    cle_128 = os.urandom(16)
    cle_256 = os.urandom(32)
    message = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC" * 4

    # ECB, CBC, CTR de base
    print("\n--- Modes ECB / CBC / CTR ---")
    ecb_c = aes_ecb_chiffrer(message, cle_128)
    ecb_d = aes_ecb_dechiffrer(ecb_c, cle_128)
    print(f"AES-128-ECB déchiffrement : {'OK' if ecb_d == message else 'ERREUR'}")

    cbc_c, iv = aes_cbc_chiffrer(message, cle_256)
    cbc_d = aes_cbc_dechiffrer(cbc_c, cle_256, iv)
    print(f"AES-256-CBC déchiffrement : {'OK' if cbc_d == message else 'ERREUR'}")

    ctr_c, nonce = aes_ctr_chiffrer(message, cle_256)
    ctr_d = aes_ctr_dechiffrer(ctr_c, cle_256, nonce)
    print(f"AES-256-CTR déchiffrement : {'OK' if ctr_d == message else 'ERREUR'}")

    # Visualisation modes sur image
    print("\n--- Comparaison modes sur image ---")
    chemin = comparer_modes_image()
    print(f"Image sauvegardée : {chemin}")

    # Effet avalanche
    print("\n--- Effet avalanche CBC ---")
    chemin_aval = effet_avalanche_cbc(message * 4, cle_256)
    print(f"Graphique : {chemin_aval}")

    # Nonce-reuse CTR
    print("\n--- Vulnérabilité nonce-reuse CTR ---")
    m1 = b"MESSAGESECRETUN1"
    m2 = b"MESSAGESECRETDEU"
    res = vulnerabilite_nonce_reuse_ctr(m1, m2, cle_128)
    print(f"C1⊕C2 == M1⊕M2 : {res['egal']}")
    print(f"XOR chiffrés : {res['xor_chiffres']}")
    print(f"XOR clairs   : {res['xor_clairs']}")

    # Benchmark
    print("\n--- Benchmark AES-128/192/256 (10 Mo) ---")
    bench = benchmark_aes(10.0)
    for bits, r in bench.items():
        print(f"AES-{bits} ({r['tours']} tours) : chiffrement={r['chiffrement_mos']:.0f} Mo/s | "
              f"déchiffrement={r['dechiffrement_mos']:.0f} Mo/s")


if __name__ == "__main__":
    demo()
