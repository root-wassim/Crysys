"""
TP1 - Attacks : Analyse de Fréquences
Calcul des fréquences, IC, graphiques comparatifs
"""
import sys, os, string
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from tp1_classique.cesar import FREQ_FRANCAIS, IC_FRANCAIS

OUTPUT_DIR = Path(__file__).parent.parent.parent / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def frequences_lettres(texte: str) -> dict[str, float]:
    """Fréquences (%) des lettres dans un texte."""
    lettres = [c for c in texte.upper() if c in string.ascii_uppercase]
    total = len(lettres)
    if total == 0:
        return {c: 0.0 for c in string.ascii_uppercase}
    freq = Counter(lettres)
    return {c: freq.get(c, 0) / total * 100 for c in string.ascii_uppercase}


def indice_coincidence_global(texte: str) -> float:
    """IC global d'un texte."""
    lettres = [c for c in texte.upper() if c in string.ascii_uppercase]
    N = len(lettres)
    if N <= 1:
        return 0.0
    freq = Counter(lettres)
    return sum(n * (n - 1) for n in freq.values()) / (N * (N - 1))


def ic_par_decalage(cryptogramme: str, k_max: int = 20) -> list[float]:
    """IC moyen des sous-séquences pour chaque longueur de clé k."""
    texte = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    ics = []
    for k in range(1, min(k_max + 1, len(texte) // 4 + 1)):
        ic_k = [indice_coincidence_global(texte[i::k]) for i in range(k)]
        ics.append(sum(ic_k) / len(ic_k) if ic_k else 0.0)
    return ics


def chi_carre(texte: str, freq_ref: dict = None) -> float:
    """Chi-carré entre fréquences du texte et la référence."""
    if freq_ref is None:
        freq_ref = FREQ_FRANCAIS
    freq_obs = frequences_lettres(texte)
    total = sum(1 for c in texte.upper() if c in string.ascii_uppercase)
    if total == 0:
        return float('inf')
    chi2 = 0.0
    for lettre in string.ascii_uppercase:
        observed = freq_obs[lettre] / 100 * total
        expected = freq_ref[lettre] / 100 * total
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


def graphique_frequences(texte: str, titre: str = "Fréquences") -> str:
    """Trace fréquences du texte vs français théorique."""
    freq_obs = frequences_lettres(texte)
    lettres = list(string.ascii_uppercase)
    obs = [freq_obs[c] for c in lettres]
    ref = [FREQ_FRANCAIS[c] for c in lettres]
    x = np.arange(26)
    width = 0.4
    fig, ax = plt.subplots(figsize=(14, 5))
    ax.bar(x - width/2, obs, width, label='Texte analysé', color='steelblue', alpha=0.8)
    ax.bar(x + width/2, ref, width, label='Français théorique', color='coral', alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(lettres)
    ax.set_xlabel("Lettre")
    ax.set_ylabel("Fréquence (%)")
    ax.set_title(titre)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    chemin = str(OUTPUT_DIR / "freq_analysis.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


def graphique_ic_vs_k(cryptogramme: str, k_max: int = 20) -> str:
    """IC moyen en fonction de la longueur de clé supposée."""
    ics = ic_par_decalage(cryptogramme, k_max)
    ks = list(range(1, len(ics) + 1))
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(ks, ics, 'o-', color='steelblue', linewidth=2, markersize=6)
    ax.axhline(IC_FRANCAIS, color='red', linestyle='--', label=f'IC français ({IC_FRANCAIS})')
    ax.axhline(0.0385, color='green', linestyle='--', label='IC aléatoire')
    ax.set_xlabel("Longueur de clé k")
    ax.set_ylabel("IC moyen")
    ax.set_title("Estimation longueur de clé par IC")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    chemin = str(OUTPUT_DIR / "ic_vs_k.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


def demo():
    print("=" * 60)
    print("  TP1 - Analyse de Fréquences")
    print("=" * 60)
    from tp1_classique.cesar import chiffrer_cesar
    texte = "la cryptographie est la science du secret"
    k = 7
    crypto = chiffrer_cesar(texte, k)
    print(f"\nIC texte clair  : {indice_coincidence_global(texte):.4f}")
    print(f"IC cryptogramme : {indice_coincidence_global(crypto):.4f}")
    print(f"χ² texte clair  : {chi_carre(texte):.2f}")
    freq = frequences_lettres(crypto)
    top5 = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]
    print("\nTop 5 lettres :")
    for l, p in top5:
        print(f"  '{l}' : {p:.2f}%")
    ch = graphique_frequences(crypto, f"César k={k}")
    print(f"\nGraphique : {ch}")


if __name__ == "__main__":
    demo()
