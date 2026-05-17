"""
TP2 - Exercice 2.2 : DES et Triple-DES
Modes ECB/CBC, visualisation de la faiblesse ECB, benchmark
"""

import os
import time
import struct
from pathlib import Path
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


BLOCK_SIZE = 8  # DES : blocs de 64 bits (8 octets)


def des_ecb_chiffrer(message: bytes, cle: bytes) -> bytes:
    """Chiffrement DES en mode ECB avec padding PKCS7."""
    cipher = DES.new(cle, DES.MODE_ECB)
    return cipher.encrypt(pad(message, BLOCK_SIZE))


def des_ecb_dechiffrer(cryptogramme: bytes, cle: bytes) -> bytes:
    """Déchiffrement DES ECB."""
    cipher = DES.new(cle, DES.MODE_ECB)
    return unpad(cipher.decrypt(cryptogramme), BLOCK_SIZE)


def des_cbc_chiffrer(message: bytes, cle: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """Chiffrement DES en mode CBC. Génère IV aléatoire si non fourni."""
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    cipher = DES.new(cle, DES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(message, BLOCK_SIZE)), iv


def des_cbc_dechiffrer(cryptogramme: bytes, cle: bytes, iv: bytes) -> bytes:
    """Déchiffrement DES CBC."""
    cipher = DES.new(cle, DES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(cryptogramme), BLOCK_SIZE)


def triple_des_cbc_chiffrer(message: bytes, cle_24: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """Chiffrement Triple-DES CBC (clé de 24 octets)."""
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    cipher = DES3.new(cle_24, DES3.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(message, BLOCK_SIZE)), iv


def triple_des_cbc_dechiffrer(cryptogramme: bytes, cle_24: bytes, iv: bytes) -> bytes:
    """Déchiffrement Triple-DES CBC."""
    cipher = DES3.new(cle_24, DES3.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(cryptogramme), BLOCK_SIZE)


def visualiser_faiblesse_ecb(taille_image: int = 64) -> str:
    """
    Génère une image test, la chiffre en DES-ECB et DES-CBC,
    et visualise que les motifs restent visibles en ECB.
    Retourne le chemin de l'image sauvegardée.
    """
    # Génération d'une image avec motifs clairs (damier)
    image = np.zeros((taille_image, taille_image), dtype=np.uint8)
    for i in range(taille_image):
        for j in range(taille_image):
            if (i // 8 + j // 8) % 2 == 0:
                image[i, j] = 200
            else:
                image[i, j] = 50

    image_bytes = image.tobytes()
    cle = b"DES_KEY!"  # 8 octets
    iv = os.urandom(BLOCK_SIZE)

    # DES-ECB (sans padding car taille multiple de 8)
    cipher_ecb = DES.new(cle, DES.MODE_ECB)
    # Chiffrer octet par octet n'est pas efficace, on chiffre par blocs
    n = len(image_bytes)
    padded = pad(image_bytes, BLOCK_SIZE)
    chiffre_ecb = cipher_ecb.encrypt(padded)[:n]

    # DES-CBC
    chiffre_cbc, _ = des_cbc_chiffrer(image_bytes, cle, iv)
    chiffre_cbc = chiffre_cbc[:n]

    # Reshape pour affichage
    img_chiffree_ecb = np.frombuffer(chiffre_ecb, dtype=np.uint8).reshape(taille_image, taille_image)
    img_chiffree_cbc = np.frombuffer(chiffre_cbc, dtype=np.uint8).reshape(taille_image, taille_image)

    # Visualisation
    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    axes[0].imshow(image, cmap='gray', vmin=0, vmax=255)
    axes[0].set_title("Image originale")
    axes[0].axis('off')

    axes[1].imshow(img_chiffree_ecb, cmap='gray', vmin=0, vmax=255)
    axes[1].set_title("DES-ECB\n(motifs visibles !)")
    axes[1].axis('off')

    axes[2].imshow(img_chiffree_cbc, cmap='gray', vmin=0, vmax=255)
    axes[2].set_title("DES-CBC\n(motifs masqués)")
    axes[2].axis('off')

    plt.suptitle("Faiblesse du mode ECB : les motifs restent visibles", fontweight='bold')
    plt.tight_layout()
    chemin = str(Path(__file__).parent.parent / "outputs" / "des_ecb_cbc_comparaison.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


def benchmark_des_vs_3des(taille_mo: float = 1.0) -> dict:
    """
    Benchmark DES vs 3DES sur taille_mo Mo de données.
    Retourne les débits en Mo/s.
    """
    donnees = os.urandom(int(taille_mo * 1024 * 1024))
    cle_des = os.urandom(8)
    cle_3des = os.urandom(24)
    iv = os.urandom(8)

    # DES-CBC
    debut = time.perf_counter()
    cipher = DES.new(cle_des, DES.MODE_CBC, iv=iv)
    _ = cipher.encrypt(pad(donnees, BLOCK_SIZE))
    duree_des = time.perf_counter() - debut

    # 3DES-CBC
    debut = time.perf_counter()
    cipher3 = DES3.new(cle_3des, DES3.MODE_CBC, iv=iv)
    _ = cipher3.encrypt(pad(donnees, BLOCK_SIZE))
    duree_3des = time.perf_counter() - debut

    return {
        'taille_mo': taille_mo,
        'des_secondes': duree_des,
        'des_debit_mos': taille_mo / duree_des,
        '3des_secondes': duree_3des,
        '3des_debit_mos': taille_mo / duree_3des,
        'ratio_lenteur': duree_3des / duree_des
    }


def demo():
    print("=" * 60)
    print("  TP2 - DES et Triple-DES")
    print("=" * 60)

    cle = b"DESKEY!!"  # 8 octets exactement
    message = b"A" * 128  # 128 octets
    iv = os.urandom(BLOCK_SIZE)

    # ECB
    print("\n--- DES-ECB ---")
    chiffre_ecb = des_ecb_chiffrer(message, cle)
    dechiffre_ecb = des_ecb_dechiffrer(chiffre_ecb, cle)
    print(f"Message (128 octets de 'A') → Chiffré (hex) : {chiffre_ecb[:32].hex()}...")
    print(f"Déchiffrement correct : {dechiffre_ecb == message}")

    # CBC
    print("\n--- DES-CBC ---")
    chiffre_cbc, iv_utilise = des_cbc_chiffrer(message, cle, iv)
    dechiffre_cbc = des_cbc_dechiffrer(chiffre_cbc, cle, iv_utilise)
    print(f"Chiffré (hex) : {chiffre_cbc[:32].hex()}...")
    print(f"Déchiffrement correct : {dechiffre_cbc == message}")

    # Comparaison ECB vs CBC sur des blocs identiques
    print("\n--- Comparaison ECB vs CBC (blocs identiques) ---")
    msg_blocs = b"IDENTIQUE" * 8  # blocs répétés
    msg_padded = pad(msg_blocs, BLOCK_SIZE)
    ecb_chiffre = des_ecb_chiffrer(msg_blocs, cle)
    cbc_chiffre, _ = des_cbc_chiffrer(msg_blocs, cle)
    print(f"ECB : blocs identiques → {len(set(ecb_chiffre[i:i+8] for i in range(0,len(ecb_chiffre),8)))} blocs chiffrés distincts")
    print(f"CBC : blocs identiques → {len(set(cbc_chiffre[i:i+8] for i in range(0,len(cbc_chiffre),8)))} blocs chiffrés distincts")

    # 3DES
    print("\n--- Triple-DES-CBC ---")
    cle_3des = os.urandom(24)
    chiffre_3des, iv_3des = triple_des_cbc_chiffrer(message, cle_3des)
    dechiffre_3des = triple_des_cbc_dechiffrer(chiffre_3des, cle_3des, iv_3des)
    print(f"3DES déchiffrement correct : {dechiffre_3des == message}")

    # Visualisation ECB
    print("\n--- Visualisation faiblesse ECB ---")
    chemin = visualiser_faiblesse_ecb()
    print(f"Image sauvegardée : {chemin}")

    # Benchmark
    print("\n--- Benchmark DES vs 3DES (1 Mo) ---")
    bench = benchmark_des_vs_3des(1.0)
    print(f"DES  : {bench['des_debit_mos']:.1f} Mo/s  ({bench['des_secondes']*1000:.1f} ms)")
    print(f"3DES : {bench['3des_debit_mos']:.1f} Mo/s  ({bench['3des_secondes']*1000:.1f} ms)")
    print(f"3DES est {bench['ratio_lenteur']:.1f}x plus lent que DES")


if __name__ == "__main__":
    demo()
