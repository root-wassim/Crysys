"""
TP1 - Exercice 1.3 : Chiffre de Hill
Implémentation 2×2 et 3×3 + attaque à clair connu
"""

import numpy as np
from math import gcd


def pgcd_etendu(a: int, b: int) -> tuple[int, int, int]:
    """Algorithme d'Euclide étendu : retourne (gcd, x, y) tels que ax+by=gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = pgcd_etendu(b % a, a)
    return g, y1 - (b // a) * x1, x1


def inverse_modulaire(a: int, m: int) -> int:
    """Calcule l'inverse modulaire de a mod m. Lève ValueError si inexistant."""
    g, x, _ = pgcd_etendu(a % m, m)
    if g != 1:
        raise ValueError(f"Pas d'inverse modulaire pour {a} mod {m} (gcd={g})")
    return x % m


def determinant_mod(matrice: list[list[int]], mod: int) -> int:
    """Calcule le déterminant d'une matrice carrée mod m (taille 2 ou 3)."""
    n = len(matrice)
    if n == 2:
        det = (matrice[0][0] * matrice[1][1] - matrice[0][1] * matrice[1][0]) % mod
    elif n == 3:
        a = matrice
        det = (
            a[0][0] * (a[1][1] * a[2][2] - a[1][2] * a[2][1])
            - a[0][1] * (a[1][0] * a[2][2] - a[1][2] * a[2][0])
            + a[0][2] * (a[1][0] * a[2][1] - a[1][1] * a[2][0])
        ) % mod
    else:
        raise ValueError("Seules les matrices 2×2 et 3×3 sont supportées.")
    return det % mod


def matrice_adjointe_mod(matrice: list[list[int]], mod: int) -> list[list[int]]:
    """Calcule la matrice adjointe (transposée des cofacteurs) mod m."""
    n = len(matrice)
    a = matrice
    if n == 2:
        adj = [
            [a[1][1] % mod, (-a[0][1]) % mod],
            [(-a[1][0]) % mod, a[0][0] % mod]
        ]
    elif n == 3:
        adj = [[0] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                # Sous-matrice 2×2 en supprimant ligne i et colonne j
                sous = [
                    [a[r][c] for c in range(3) if c != j]
                    for r in range(3) if r != i
                ]
                cofacteur = ((-1) ** (i + j)) * (
                    sous[0][0] * sous[1][1] - sous[0][1] * sous[1][0]
                )
                adj[j][i] = cofacteur % mod  # transposée
    else:
        raise ValueError("Taille non supportée.")
    return adj


def inverse_matrice_mod(matrice: list[list[int]], mod: int) -> list[list[int]]:
    """
    Calcule l'inverse d'une matrice mod m.
    K^(-1) = det^(-1) * adj(K) mod m
    """
    det = determinant_mod(matrice, mod)
    det_inv = inverse_modulaire(det, mod)
    adj = matrice_adjointe_mod(matrice, mod)
    n = len(matrice)
    inv = [[(det_inv * adj[i][j]) % mod for j in range(n)] for i in range(n)]
    return inv


def valider_matrice_cle(matrice: list[list[int]], mod: int = 26) -> bool:
    """Vérifie que la matrice est inversible mod 26 (det inversible)."""
    det = determinant_mod(matrice, mod)
    return gcd(det, mod) == 1


def texte_en_vecteurs(texte: str, taille_bloc: int) -> list[list[int]]:
    """Convertit un texte en liste de vecteurs colonnes de taille taille_bloc."""
    lettres = [ord(c) - ord('A') for c in texte.upper() if c.isalpha()]
    # Padding avec 'X' si nécessaire
    while len(lettres) % taille_bloc != 0:
        lettres.append(ord('X') - ord('A'))
    vecteurs = [lettres[i:i + taille_bloc] for i in range(0, len(lettres), taille_bloc)]
    return vecteurs


def vecteurs_en_texte(vecteurs: list[list[int]]) -> str:
    """Convertit des vecteurs en texte."""
    return ''.join(chr(v + ord('A')) for bloc in vecteurs for v in bloc)


def multiplier_matrice_vecteur(matrice: list[list[int]], vecteur: list[int], mod: int) -> list[int]:
    """Calcule matrice × vecteur mod m."""
    n = len(matrice)
    return [sum(matrice[i][j] * vecteur[j] for j in range(n)) % mod for i in range(n)]


def chiffrer_hill(texte: str, matrice_cle: list[list[int]], mod: int = 26) -> str:
    """Chiffre un texte avec la matrice clé Hill."""
    if not valider_matrice_cle(matrice_cle, mod):
        raise ValueError("Matrice clé non inversible mod 26 !")
    taille = len(matrice_cle)
    vecteurs = texte_en_vecteurs(texte, taille)
    chiffres = [multiplier_matrice_vecteur(matrice_cle, v, mod) for v in vecteurs]
    return vecteurs_en_texte(chiffres)


def dechiffrer_hill(cryptogramme: str, matrice_cle: list[list[int]], mod: int = 26) -> str:
    """Déchiffre un cryptogramme Hill."""
    inv_cle = inverse_matrice_mod(matrice_cle, mod)
    taille = len(matrice_cle)
    vecteurs = texte_en_vecteurs(cryptogramme, taille)
    clairs = [multiplier_matrice_vecteur(inv_cle, v, mod) for v in vecteurs]
    return vecteurs_en_texte(clairs)


def attaque_clair_connu_hill(clairs: list[str], chiffres: list[str], taille: int = 2) -> list[list[int]]:
    """
    Attaque à clair connu sur Hill.
    Avec n paires (clair, chiffré) : C = K × P  →  K = C × P^(-1) mod 26
    Nécessite n = taille paires linéairement indépendantes.
    """
    # Construire les matrices P (clairs en colonnes) et C (chiffrés en colonnes)
    P = []
    C = []
    for i in range(min(taille, len(clairs))):
        p_vec = [ord(c) - ord('A') for c in clairs[i].upper() if c.isalpha()][:taille]
        c_vec = [ord(c) - ord('A') for c in chiffres[i].upper() if c.isalpha()][:taille]
        P.append(p_vec)
        C.append(c_vec)

    # P et C sont des matrices taille×taille
    # K = C × P^(-1) mod 26
    # On traite P comme une matrice ligne → transposer pour avoir colonnes
    P_T = [[P[j][i] for j in range(taille)] for i in range(taille)]
    C_T = [[C[j][i] for j in range(taille)] for i in range(taille)]

    if not valider_matrice_cle(P_T, 26):
        raise ValueError("Les clairs choisis ne forment pas une matrice inversible. Choisir d'autres paires.")

    inv_P = inverse_matrice_mod(P_T, 26)

    # K = C_T × inv_P mod 26
    K = [[0] * taille for _ in range(taille)]
    for i in range(taille):
        for j in range(taille):
            K[i][j] = sum(C_T[i][k] * inv_P[k][j] for k in range(taille)) % 26

    return K


def demo():
    print("=" * 60)
    print("  TP1 - Chiffre de Hill")
    print("=" * 60)

    # Clé 2×2 valide
    K2 = [[3, 3], [2, 5]]
    print(f"\nClé 2×2 : {K2}")
    print(f"Valide  : {valider_matrice_cle(K2)}")
    print(f"det mod 26 = {determinant_mod(K2, 26)}")

    message = "CRYPTOGRAPHIE"
    chiffre = chiffrer_hill(message, K2)
    dechiffre = dechiffrer_hill(chiffre, K2)
    print(f"\nMessage  : {message}")
    print(f"Chiffré  : {chiffre}")
    print(f"Déchiffré: {dechiffre}")

    # Clé 3×3
    K3 = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
    print(f"\nClé 3×3 valide : {valider_matrice_cle(K3)}")
    chiffre3 = chiffrer_hill(message, K3)
    dechiffre3 = dechiffrer_hill(chiffre3, K3)
    print(f"Chiffré  : {chiffre3}")
    print(f"Déchiffré: {dechiffre3}")

    # Attaque à clair connu
    print("\n--- Attaque à clair connu (2×2) ---")
    paires_clairs = ["HE", "LL"]
    paires_chiffres = [chiffrer_hill(p, K2) for p in paires_clairs]
    print(f"Clairs  : {paires_clairs}")
    print(f"Chiffrés: {paires_chiffres}")

    K_trouve = attaque_clair_connu_hill(paires_clairs, paires_chiffres, taille=2)
    print(f"Clé retrouvée : {K_trouve}")
    print(f"Clé originale : {K2}")
    print(f"Succès        : {K_trouve == K2}")

    print("\n--- Question ---")
    print("Hill est vulnérable au clair connu car C = K·P → K = C·P⁻¹.")
    print("Avec n blocs connus (n = taille matrice), on résout directement.")
    print("Même pour de grandes matrices, n paires suffisent → complexité O(n³).")


if __name__ == "__main__":
    demo()
