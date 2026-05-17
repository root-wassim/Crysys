"""
TP1 - Attacks : Test de Kasiski complet
Estimation de la longueur de clé Vigenère par trigrammes répétés
"""
import sys, os, string
from collections import Counter
from math import gcd
from functools import reduce

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def kasiski_trouver_repetitions(texte: str, n: int = 3) -> dict[str, list[int]]:
    """Trouve les n-grammes répétés et leurs positions."""
    texte = ''.join(c for c in texte.upper() if c in string.ascii_uppercase)
    grammes = {}
    for i in range(len(texte) - n + 1):
        g = texte[i:i+n]
        grammes.setdefault(g, []).append(i)
    return {g: pos for g, pos in grammes.items() if len(pos) > 1}


def kasiski_distances(repetitions: dict) -> list[int]:
    """Calcule les distances entre occurrences de n-grammes répétés."""
    distances = []
    for _, positions in repetitions.items():
        for i in range(1, len(positions)):
            distances.append(positions[i] - positions[i-1])
    return distances


def kasiski_facteurs(distances: list[int], max_k: int = 20) -> dict[int, int]:
    """Score les facteurs communs des distances → longueurs de clé candidates."""
    scores = Counter()
    for d in distances:
        for f in range(2, min(d + 1, max_k + 1)):
            if d % f == 0:
                scores[f] += 1
    # Bonus pour les GCDs entre paires
    for i in range(len(distances)):
        for j in range(i + 1, min(len(distances), i + 50)):
            g = gcd(distances[i], distances[j])
            if 2 <= g <= max_k:
                scores[g] += 1
    return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))


def kasiski_complet(cryptogramme: str, taille_gramme: int = 3, max_k: int = 20) -> dict:
    """
    Test de Kasiski complet.
    Retourne {
        'repetitions': n-grammes répétés,
        'distances': distances entre occurrences,
        'candidats': {longueur: score},
        'longueur_probable': meilleur candidat
    }
    """
    reps = kasiski_trouver_repetitions(cryptogramme, taille_gramme)
    dists = kasiski_distances(reps)
    if not dists:
        return {'repetitions': reps, 'distances': [], 'candidats': {}, 'longueur_probable': 1}
    candidats = kasiski_facteurs(dists, max_k)
    meilleur = list(candidats.keys())[0] if candidats else 1
    return {
        'repetitions': dict(list(reps.items())[:10]),
        'distances': dists[:20],
        'candidats': dict(list(candidats.items())[:10]),
        'longueur_probable': meilleur
    }


def demo():
    print("=" * 60)
    print("  TP1 - Test de Kasiski")
    print("=" * 60)
    from tp1_classique.vigenere import chiffrer_vigenere
    message = (
        "la cryptographie classique utilise des substitutions "
        "alphabetiques pour chiffrer les messages mais elle reste "
        "vulnerable aux attaques par analyse de langue"
    ) * 2
    cle = "CRYPTO"
    crypto = chiffrer_vigenere(message, cle)
    print(f"\nClé secrète : {cle} (longueur={len(cle)})")
    res = kasiski_complet(crypto)
    print(f"\nTrigrammes répétés : {len(res['repetitions'])}")
    print(f"Distances trouvées : {res['distances'][:10]}")
    print(f"\nCandidats (longueur → score) :")
    for k, s in list(res['candidats'].items())[:6]:
        marqueur = " ← !" if k == len(cle) else ""
        print(f"  k={k:2d} → score={s}{marqueur}")
    print(f"\nLongueur probable : {res['longueur_probable']}")


if __name__ == "__main__":
    demo()
