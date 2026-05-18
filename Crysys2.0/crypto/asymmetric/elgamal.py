"""
TP3 - Exercice 3.3 : Chiffrement ElGamal
Génération clés, chiffrement, malléabilité, comparaison RSA
"""

import os
import random
import hashlib
import time


# ─────────────────────────────────────────────
#  Arithmétique pour ElGamal
# ─────────────────────────────────────────────

# Premier sûr de 512 bits (standardisé, p = 2q+1 avec q premier)
P_512 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16
)

G_512 = 2  # générateur


def elgamal_generer_cles(p: int = P_512, g: int = G_512) -> dict:
    """
    Génère une paire de clés ElGamal.
    Clé privée x : aléatoire dans [2, p-2]
    Clé publique y : g^x mod p
    """
    x = random.randrange(2, p - 1)
    y = pow(g, x, p)
    return {
        'p': p,
        'g': g,
        'x': x,    # clé privée
        'y': y,    # clé publique
    }


def elgamal_chiffrer(M: int, cle_publique: dict) -> tuple[int, int]:
    """
    Chiffre un entier M < p.
    Choisit k aléatoire, retourne (C1, C2) = (g^k, M * y^k) mod p.
    Non-déterministe : deux chiffrements du même M donnent des résultats différents.
    """
    p, g, y = cle_publique['p'], cle_publique['g'], cle_publique['y']
    if M >= p:
        raise ValueError(f"Message M doit être < p ({p.bit_length()} bits)")
    k = random.randrange(2, p - 1)
    C1 = pow(g, k, p)
    C2 = (M * pow(y, k, p)) % p
    return C1, C2


def elgamal_dechiffrer(C1: int, C2: int, cle: dict) -> int:
    """
    Déchiffre (C1, C2).
    M = C2 * (C1^x)^(-1) mod p
    """
    p, x = cle['p'], cle['x']
    s = pow(C1, x, p)              # secret partagé = g^(kx)
    s_inv = pow(s, p - 2, p)       # inverse modulaire via petit théorème de Fermat
    M = (C2 * s_inv) % p
    return M


def demonstrer_non_determinisme(M: int, cle: dict) -> dict:
    """Montre que deux chiffrements du même message donnent des résultats différents."""
    C1a, C2a = elgamal_chiffrer(M, cle)
    C1b, C2b = elgamal_chiffrer(M, cle)

    D_a = elgamal_dechiffrer(C1a, C2a, cle)
    D_b = elgamal_dechiffrer(C1b, C2b, cle)

    return {
        'message': M,
        'chiffrement_1': (C1a % 10**10, C2a % 10**10),  # tronqués pour affichage
        'chiffrement_2': (C1b % 10**10, C2b % 10**10),
        'differents': (C1a, C2a) != (C1b, C2b),
        'dechiffrement_1': D_a,
        'dechiffrement_2': D_b,
        'correct': D_a == M and D_b == M
    }


def attaque_malleabilite(M: int, cle: dict) -> dict:
    """
    Malléabilité ElGamal : forger E(2M) à partir de E(M) sans connaître M ni x.
    
    Si E(M) = (C1, C2) = (g^k, M·y^k mod p)
    Alors E(2M) = (C1, 2·C2 mod p)
    Car : déchiffrement de (C1, 2C2) = 2C2 / C1^x = 2M·y^k / g^(kx) = 2M
    """
    p = cle['p']
    C1, C2 = elgamal_chiffrer(M, cle)

    # Forger E(2M) sans connaître M
    C1_forge = C1
    C2_forge = (2 * C2) % p

    # Vérification
    M_original = elgamal_dechiffrer(C1, C2, cle)
    M_forge_dechiffre = elgamal_dechiffrer(C1_forge, C2_forge, cle)

    return {
        'message_original': M_original,
        'message_forge': M_forge_dechiffre,
        'relation_respectee': M_forge_dechiffre == (2 * M) % p,
        'sans_connaitre_x': True
    }


def comparer_tailles_rsa_elgamal() -> dict:
    """
    Compare les tailles de clé et de chiffrés RSA-2048 vs ElGamal-2048.
    RSA-2048 : chiffré = 256 octets (2048 bits)
    ElGamal-2048 : chiffré = 2 * 256 = 512 octets (C1 + C2)
    """
    bits_module = P_512.bit_length()

    rsa_chiffre_octets = bits_module // 8
    elgamal_chiffre_octets = 2 * (bits_module // 8)  # C1 et C2

    return {
        'module_bits': bits_module,
        'rsa_chiffre_octets': rsa_chiffre_octets,
        'elgamal_chiffre_octets': elgamal_chiffre_octets,
        'ratio_taille': elgamal_chiffre_octets / rsa_chiffre_octets,
        'implication': (
            f"ElGamal produit un chiffré 2× plus grand que RSA "
            f"({elgamal_chiffre_octets} vs {rsa_chiffre_octets} octets). "
            "Cela double les besoins en bande passante et stockage."
        )
    }


def demo():
    print("=" * 60)
    print("  TP3 - Chiffrement ElGamal")
    print("=" * 60)

    # Génération de clés
    print("\n--- Génération de clés ---")
    debut = time.perf_counter()
    cle = elgamal_generer_cles()
    print(f"Clé générée en {(time.perf_counter()-debut)*1000:.0f} ms")
    print(f"Module p     : {cle['p'].bit_length()} bits")
    print(f"Générateur g : {cle['g']}")
    print(f"Clé publique y (tronquée) : {hex(cle['y'])[:20]}...")

    # Chiffrement/déchiffrement basique
    print("\n--- Chiffrement / Déchiffrement ---")
    M = 12345
    C1, C2 = elgamal_chiffrer(M, cle)
    M_dechiffre = elgamal_dechiffrer(C1, C2, cle)
    print(f"M original   : {M}")
    print(f"C1 (tronqué) : {hex(C1)[:20]}...")
    print(f"C2 (tronqué) : {hex(C2)[:20]}...")
    print(f"D(E(M))      : {M_dechiffre}")
    print(f"Correct      : {M_dechiffre == M}")

    # Non-déterminisme
    print("\n--- Non-déterminisme ---")
    nd = demonstrer_non_determinisme(M, cle)
    print(f"Chiffrement 1 (C1,C2) : ({nd['chiffrement_1'][0]}, {nd['chiffrement_1'][1]})")
    print(f"Chiffrement 2 (C1,C2) : ({nd['chiffrement_2'][0]}, {nd['chiffrement_2'][1]})")
    print(f"Chiffrés différents   : {nd['differents']}")
    print(f"Déchiffrements corrects : {nd['correct']}")

    # Malléabilité
    print("\n--- Malléabilité ---")
    mal = attaque_malleabilite(M, cle)
    print(f"M original          : {mal['message_original']}")
    print(f"Message forgé 2M    : {mal['message_forge']}")
    print(f"E(M) → E(2M) réussi : {mal['relation_respectee']}")
    print("Sans connaître M ni x : OUI → dangereux pour confidentialité")

    # Comparaison RSA vs ElGamal
    print("\n--- Comparaison tailles RSA vs ElGamal ---")
    comp = comparer_tailles_rsa_elgamal()
    print(f"Module : {comp['module_bits']} bits")
    print(f"RSA    : {comp['rsa_chiffre_octets']} octets par chiffré")
    print(f"ElGamal: {comp['elgamal_chiffre_octets']} octets par chiffré (C1+C2)")
    print(f"Ratio  : {comp['ratio_taille']:.0f}× plus grand")
    print(f"\n  → {comp['implication']}")


if __name__ == "__main__":
    demo()
