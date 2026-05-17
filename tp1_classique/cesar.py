"""
TP1 - Exercice 1.1 : Chiffre de César
Implémentation, force brute et analyse de fréquences (IC)
"""

import string
from collections import Counter

# Mots français courants pour la détection automatique
MOTS_FRANCAIS = {
    "le", "la", "les", "de", "des", "un", "une", "et", "est", "en",
    "du", "au", "aux", "il", "elle", "on", "nous", "vous", "ils", "elles",
    "que", "qui", "par", "sur", "dans", "avec", "pour", "pas", "plus",
    "ce", "se", "sa", "son", "ses", "mon", "ma", "mes", "ton", "ta",
    "je", "tu", "ne", "ou", "si", "mais", "donc", "car", "ni", "or"
}

# Fréquences des lettres en français (%)
FREQ_FRANCAIS = {
    'A': 8.11, 'B': 0.81, 'C': 3.38, 'D': 4.28, 'E': 17.22, 'F': 1.14,
    'G': 1.19, 'H': 0.74, 'I': 7.24, 'J': 0.18, 'K': 0.02, 'L': 5.89,
    'M': 2.72, 'N': 7.15, 'O': 5.14, 'P': 2.49, 'Q': 0.65, 'R': 6.53,
    'S': 7.91, 'T': 7.11, 'U': 5.75, 'V': 1.38, 'W': 0.02, 'X': 0.43,
    'Y': 0.27, 'Z': 0.05
}

IC_FRANCAIS = 0.0746  # Indice de coïncidence théorique du français


def chiffrer_cesar(texte: str, k: int) -> str:
    """Chiffre un texte avec le décalage k, ignore espaces et casse."""
    k = k % 26
    resultat = []
    for ch in texte.upper():
        if ch in string.ascii_uppercase:
            resultat.append(chr((ord(ch) - ord('A') + k) % 26 + ord('A')))
        elif ch == ' ':
            pass  # on ignore les espaces
        # les autres caractères sont ignorés
    return ''.join(resultat)


def dechiffrer_cesar(cryptogramme: str, k: int) -> str:
    """Déchiffre un cryptogramme César avec le décalage k."""
    return chiffrer_cesar(cryptogramme, 26 - k)


def attaque_force_brute(cryptogramme: str) -> dict:
    """
    Teste les 26 clés possibles.
    Retourne un dict {k: (texte_clair, score)} trié par score décroissant.
    """
    resultats = {}
    for k in range(26):
        clair = dechiffrer_cesar(cryptogramme, k)
        score = _score_francais(clair)
        resultats[k] = (clair, score)

    # Tri par score décroissant
    return dict(sorted(resultats.items(), key=lambda x: x[1][1], reverse=True))


def _score_francais(texte: str) -> float:
    """
    Score un texte selon sa ressemblance avec le français.
    Combine détection de mots courants + correspondance de fréquences.
    """
    mots = texte.lower().split()
    score_mots = sum(1 for m in mots if m in MOTS_FRANCAIS) / max(len(mots), 1)

    # Score de fréquence de lettres
    lettres = [c for c in texte.upper() if c in string.ascii_uppercase]
    if not lettres:
        return 0.0
    freq_obs = Counter(lettres)
    total = len(lettres)
    score_freq = 0.0
    for lettre, freq_th in FREQ_FRANCAIS.items():
        obs = freq_obs.get(lettre, 0) / total * 100
        score_freq -= abs(obs - freq_th)  # pénalité si écart

    return score_mots * 10 + score_freq


def indice_coincidence(texte: str) -> float:
    """
    Calcule l'indice de coïncidence (IC) d'un texte.
    IC = Σ n_i*(n_i-1) / N*(N-1)
    IC français ≈ 0.074 | IC texte aléatoire ≈ 0.038
    """
    lettres = [c for c in texte.upper() if c in string.ascii_uppercase]
    N = len(lettres)
    if N <= 1:
        return 0.0
    freq = Counter(lettres)
    ic = sum(n * (n - 1) for n in freq.values()) / (N * (N - 1))
    return ic


def attaque_par_ic(cryptogramme: str) -> int:
    """
    Détermine la clé César via l'IC sans force brute.
    Principe : pour le bon k, les fréquences correspondent au français.
    Retourne le k le plus probable.
    """
    lettres = [c for c in cryptogramme.upper() if c in string.ascii_uppercase]
    if not lettres:
        return 0

    freq_obs = Counter(lettres)
    total = len(lettres)

    meilleur_k = 0
    meilleur_score = float('inf')

    for k in range(26):
        score = 0.0
        for lettre in string.ascii_uppercase:
            lettre_orig = chr((ord(lettre) - ord('A') - k) % 26 + ord('A'))
            freq_attendue = FREQ_FRANCAIS.get(lettre_orig, 0) / 100
            freq_observee = freq_obs.get(lettre, 0) / total
            score += abs(freq_attendue - freq_observee)
        if score < meilleur_score:
            meilleur_score = score
            meilleur_k = k

    return meilleur_k


def demo():
    print("=" * 60)
    print("  TP1 - Chiffre de César")
    print("=" * 60)

    message = "le chiffrement de cesar est une technique classique"
    k = 13  # ROT13

    print(f"\nMessage original : {message}")
    print(f"Clé k = {k}")

    cryptogramme = chiffrer_cesar(message, k)
    print(f"Cryptogramme    : {cryptogramme}")

    dechiffre = dechiffrer_cesar(cryptogramme, k)
    print(f"Déchiffré       : {dechiffre}")

    # Indice de coïncidence
    ic = indice_coincidence(cryptogramme)
    print(f"\nIC du cryptogramme : {ic:.4f}  (français ≈ {IC_FRANCAIS})")

    # Attaque par IC
    k_trouve_ic = attaque_par_ic(cryptogramme)
    print(f"Clé trouvée par IC : {k_trouve_ic}  (attendu : {k})")

    # Force brute
    print("\n--- Force brute (top 5) ---")
    resultats = attaque_force_brute(cryptogramme)
    for i, (cle, (texte, score)) in enumerate(resultats.items()):
        print(f"  k={cle:2d} | score={score:6.2f} | {texte[:40]}")
        if i >= 4:
            break


if __name__ == "__main__":
    demo()
