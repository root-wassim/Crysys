"""
TP2 - Exercice 2.1 : RC4 (chiffrement par flot)
Implémentation KSA + PRGA + vulnérabilité WEP + biais statistiques
"""

import os
import struct
from collections import Counter
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def ksa(cle: bytes) -> list[int]:
    """
    Key Scheduling Algorithm (KSA).
    Initialise et permute le tableau S de 256 octets selon la clé.
    """
    S = list(range(256))
    j = 0
    n = len(cle)
    for i in range(256):
        j = (j + S[i] + cle[i % n]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def prga(S: list[int], longueur: int) -> bytes:
    """
    Pseudo-Random Generation Algorithm (PRGA).
    Génère le keystream de 'longueur' octets à partir de S.
    """
    S = S.copy()
    i = j = 0
    keystream = []
    for _ in range(longueur):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def rc4_chiffrer(message: bytes, cle: bytes) -> bytes:
    """Chiffre/déchiffre un message avec RC4 (XOR avec keystream)."""
    S = ksa(cle)
    keystream = prga(S, len(message))
    return bytes(m ^ k for m, k in zip(message, keystream))


def rc4_dechiffrer(cryptogramme: bytes, cle: bytes) -> bytes:
    """RC4 est symétrique (XOR) : déchiffrement = chiffrement."""
    return rc4_chiffrer(cryptogramme, cle)


def vulnerabilite_wep(cle_secrete: bytes, nb_paquets: int = 1000) -> dict:
    """
    Vulnérabilité WEP : les IV faibles (3 premiers octets commençant par
    0xAA, 0x00..0xFF) corrèlent le premier octet du keystream avec la clé.
    
    Simule la collecte de paquets WEP et tente de retrouver le premier octet
    de la clé secrète via l'attaque FMS (Fluhrer, Mantin, Shamir).
    
    Retourne un dict avec les statistiques de l'attaque.
    """
    print(f"  Simulation WEP : {nb_paquets} paquets avec IV faibles...")
    votes = Counter()

    for i in range(min(nb_paquets, 256)):
        # IV faible type WEP : (0xAA, 0x00..0xFF, 0x03)
        # Structure de la clé WEP : IV + clé secrète
        iv = bytes([0xAA, i, 0x03])
        cle_wep = iv + cle_secrete

        S = ksa(cle_wep)
        keystream = prga(S, 1)

        # Selon l'attaque FMS : si S[1]=N+3 après KSA,
        # le 1er octet du keystream révèle K[3] = ks[0] XOR S[0] XOR S[S[0]+S[1]]
        # Simplification : compter les votes pour chaque valeur de K[0]
        vote = (keystream[0] ^ S[0] ^ S[S[0]]) % 256
        votes[vote] += 1

    octet_predit = votes.most_common(1)[0][0]
    return {
        'votes': dict(votes.most_common(10)),
        'octet_predit': octet_predit,
        'octet_reel': cle_secrete[0],
        'succes': octet_predit == cle_secrete[0]
    }


def biais_rc4(nb_keystreams: int = 5000) -> bytes:
    """
    Biais statistique RC4 : le 2e octet du keystream est biaisé vers 0.
    Génère nb_keystreams pour des clés aléatoires et histogramme.
    Retourne le chemin de l'image générée.
    """
    print(f"  Génération de {nb_keystreams} keystreams...")
    compte_octet2 = Counter()

    for _ in range(nb_keystreams):
        cle = os.urandom(16)
        S = ksa(cle)
        ks = prga(S, 2)
        compte_octet2[ks[1]] += 1

    # Graphique
    valeurs = list(range(256))
    counts = [compte_octet2.get(v, 0) for v in valeurs]
    attendu = nb_keystreams / 256

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(valeurs, counts, color='steelblue', alpha=0.7, width=1)
    ax.axhline(attendu, color='red', linestyle='--', linewidth=1.5, label=f'Attendu ({attendu:.0f})')
    ax.bar(0, compte_octet2[0], color='red', alpha=0.9, width=1, label=f'Valeur 0 : {compte_octet2[0]} (biais !)')
    ax.set_xlabel("Valeur du 2e octet du keystream")
    ax.set_ylabel("Fréquence")
    ax.set_title(f"RC4 Bias — Biais du 2e octet sur {nb_keystreams} keystreams")
    ax.legend()
    plt.tight_layout()
    chemin = str(Path(__file__).parent.parent / "outputs" / "rc4_biais.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


def demo():
    print("=" * 60)
    print("  TP2 - RC4 (chiffrement par flot)")
    print("=" * 60)

    # Chiffrement/déchiffrement de base
    cle = b"SecretKey128bits"
    message = b"Cryptographie appliquee - RC4 stream cipher"
    print(f"\nClé     : {cle}")
    print(f"Message : {message}")

    chiffre = rc4_chiffrer(message, cle)
    print(f"Chiffré : {chiffre.hex()}")

    dechiffre = rc4_dechiffrer(chiffre, cle)
    print(f"Déchiffré : {dechiffre}")
    assert dechiffre == message
    print("✓ RC4 déchiffrement correct")

    # Vulnérabilité WEP
    print("\n--- Vulnérabilité WEP (attaque FMS simplifiée) ---")
    cle_secrete = b"\x42\x17\xAB\xCC"
    resultat = vulnerabilite_wep(cle_secrete, nb_paquets=500)
    print(f"  Octet clé réel    : {hex(resultat['octet_reel'])}")
    print(f"  Octet prédit      : {hex(resultat['octet_predit'])}")
    print(f"  Succès            : {resultat['succes']}")
    print(f"  Top votes : {list(resultat['votes'].items())[:5]}")

    # Biais statistique
    print("\n--- Biais statistique (RC4 2e octet) ---")
    chemin_img = biais_rc4(nb_keystreams=3000)
    print(f"  Graphique sauvegardé : {chemin_img}")
    print("  Le 2e octet est biaisé vers 0 → banni dans TLS 1.3 (RFC 7465)")


if __name__ == "__main__":
    demo()
