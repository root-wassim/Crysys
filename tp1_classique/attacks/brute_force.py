"""
TP1 - Attacks : Brute Force générique
Force brute sur chiffres mono-alphabétiques (César, substitution simple)
"""

import sys
import os
import string
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tp1_classique.cesar import (
    dechiffrer_cesar, indice_coincidence,
    FREQ_FRANCAIS, IC_FRANCAIS
)


# ─── Heuristiques de scoring ──────────────────────────────

MOTS_FRANCAIS = {
    "le", "la", "les", "de", "des", "un", "une", "et", "est", "en",
    "du", "au", "aux", "il", "elle", "on", "nous", "vous", "ils",
    "que", "qui", "par", "sur", "dans", "avec", "pour", "pas", "plus",
    "ce", "se", "sa", "son", "ses", "mon", "ma", "je", "tu", "ne",
    "ou", "si", "mais", "donc", "car", "ni", "or", "tout", "bien",
}

MOTS_ANGLAIS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "any",
    "can", "her", "was", "one", "our", "out", "day", "get", "has",
    "him", "his", "how", "its", "may", "new", "now", "old", "see",
    "two", "way", "who", "did", "its", "let", "put", "say", "she",
    "too", "use", "with", "have", "this", "that", "from", "they",
}

FREQ_ANGLAIS = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
    'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
    'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
    'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
    'Y': 1.97, 'Z': 0.07
}


def score_francais(texte: str) -> float:
    """Score de ressemblance avec du français (mots + fréquences)."""
    mots = texte.lower().split()
    score_mots = sum(2 for m in mots if m in MOTS_FRANCAIS) / max(len(mots), 1)
    lettres = [c for c in texte.upper() if c in string.ascii_uppercase]
    if not lettres:
        return 0.0
    freq_obs = Counter(lettres)
    total = len(lettres)
    score_freq = sum(
        -abs(freq_obs.get(l, 0) / total * 100 - freq_th)
        for l, freq_th in FREQ_FRANCAIS.items()
    )
    return score_mots * 10 + score_freq


def score_anglais(texte: str) -> float:
    """Score de ressemblance avec de l'anglais."""
    mots = texte.lower().split()
    score_mots = sum(2 for m in mots if m in MOTS_ANGLAIS) / max(len(mots), 1)
    lettres = [c for c in texte.upper() if c in string.ascii_uppercase]
    if not lettres:
        return 0.0
    freq_obs = Counter(lettres)
    total = len(lettres)
    score_freq = sum(
        -abs(freq_obs.get(l, 0) / total * 100 - freq_th)
        for l, freq_th in FREQ_ANGLAIS.items()
    )
    return score_mots * 10 + score_freq


# ─── Force brute César ────────────────────────────────────

def brute_force_cesar(cryptogramme: str, langue: str = 'fr') -> list[dict]:
    """
    Teste les 26 décalages possibles sur un cryptogramme César.

    Args :
        cryptogramme : texte chiffré
        langue : 'fr' (français) ou 'en' (anglais)

    Retourne :
        liste triée par score décroissant de {k, texte_clair, score, ic}
    """
    scorer = score_francais if langue == 'fr' else score_anglais
    resultats = []
    for k in range(26):
        clair = dechiffrer_cesar(cryptogramme, k)
        # Re-insérer des espaces approximatifs (chaque 5 lettres)
        clair_espaces = ' '.join(clair[i:i+5] for i in range(0, len(clair), 5))
        sc = scorer(clair_espaces)
        ic = indice_coincidence(clair)
        resultats.append({
            'k': k,
            'texte_clair': clair,
            'score': sc,
            'ic': ic,
        })
    return sorted(resultats, key=lambda x: x['score'], reverse=True)


# ─── Force brute substitution mono-alphabétique ──────────

def brute_force_frequences_cesar(cryptogramme: str, langue: str = 'fr') -> int:
    """
    Détermine la clé César par appariement de fréquences (sans force brute exhaustive).
    La lettre la plus fréquente dans le chiffré correspond à 'E' (fr) ou 'E' (en).

    Retourne la clé la plus probable.
    """
    lettres = [c for c in cryptogramme.upper() if c in string.ascii_uppercase]
    if not lettres:
        return 0
    freq = Counter(lettres)
    lettre_plus_freq = freq.most_common(1)[0][0]
    # En français et en anglais, 'E' est la lettre la plus fréquente
    k = (ord(lettre_plus_freq) - ord('E')) % 26
    return k


# ─── Force brute sur un alphabet de substitution ─────────

def force_brute_partielle(
    cryptogramme: str,
    substitution_partielle: dict[str, str],
    langue: str = 'fr'
) -> str:
    """
    Applique une substitution partielle connue et retourne le texte partiellement déchiffré.
    Les lettres non substituées sont affichées comme '_'.

    Args :
        cryptogramme : texte chiffré
        substitution_partielle : {lettre_chiffrée: lettre_claire, ...}

    Retourne le texte partiellement déchiffré.
    """
    resultat = []
    for c in cryptogramme.upper():
        if c in string.ascii_uppercase:
            resultat.append(substitution_partielle.get(c, '_'))
        else:
            resultat.append(c)
    return ''.join(resultat)


def demo():
    print("=" * 60)
    print("  TP1 - Attaque Force Brute")
    print("=" * 60)

    # Force brute César
    from tp1_classique.cesar import chiffrer_cesar
    message = "le chiffrement de cesar est une methode classique"
    k_secret = 7
    crypto = chiffrer_cesar(message, k_secret)

    print(f"\nCryptogramme : {crypto}")
    print(f"Clé secrète  : {k_secret}")

    print("\n--- Force brute (top 5) ---")
    resultats = brute_force_cesar(crypto)
    for r in resultats[:5]:
        print(f"  k={r['k']:2d} | IC={r['ic']:.4f} | score={r['score']:6.2f} | {r['texte_clair'][:40]}")
    print(f"\n  → Clé trouvée : {resultats[0]['k']}  (attendu : {k_secret})")

    # Appariement de fréquences
    k_freq = brute_force_frequences_cesar(crypto)
    print(f"\n  Clé par fréquences : {k_freq}")

    # Substitution partielle
    print("\n--- Substitution partielle ---")
    sub = {chr(ord('A') + (ord(c) - ord('A') + k_secret) % 26): c
           for c in 'ETAOIN'}
    partiel = force_brute_partielle(crypto, sub)
    print(f"  Déchiffrement partiel : {partiel[:40]}")


if __name__ == "__main__":
    demo()
