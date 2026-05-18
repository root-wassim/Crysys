"""
TP4 - Benchmark global des fonctions de hachage
MD5, SHA-256, SHA-512 — graphiques comparatifs
"""
import hashlib, os, time
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUTPUT_DIR = Path(__file__).parent.parent / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def benchmark_complet(taille_mo: float = 50.0) -> dict:
    """Benchmark MD5 / SHA-256 / SHA-512 sur taille_mo Mo."""
    data = os.urandom(int(taille_mo * 1024 * 1024))
    algos = ['md5', 'sha256', 'sha512']
    resultats = {}
    for algo in algos:
        t0 = time.perf_counter()
        hashlib.new(algo, data).hexdigest()
        duree = time.perf_counter() - t0
        resultats[algo] = {
            'duree_s': duree,
            'debit_mos': taille_mo / duree,
            'taille_sortie_bits': {'md5': 128, 'sha256': 256, 'sha512': 512}[algo],
        }
    return resultats


def graphique_benchmark(taille_mo: float = 50.0) -> str:
    """Génère le graphique de benchmark et retourne le chemin."""
    resultats = benchmark_complet(taille_mo)
    noms = ['MD5', 'SHA-256', 'SHA-512']
    debits = [resultats[a]['debit_mos'] for a in ['md5', 'sha256', 'sha512']]
    couleurs = ['#e74c3c', '#3498db', '#2ecc71']
    fig, ax = plt.subplots(figsize=(8, 5))
    barres = ax.bar(noms, debits, color=couleurs, alpha=0.85, width=0.5)
    ax.bar_label(barres, [f'{d:.0f} Mo/s' for d in debits], padding=3, fontsize=11)
    ax.set_ylabel("Débit (Mo/s)")
    ax.set_title(f"Benchmark fonctions de hachage — {taille_mo:.0f} Mo")
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    chemin = str(OUTPUT_DIR / "hachage_benchmark.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


def graphique_scalabilite() -> str:
    """Graphique du débit en fonction de la taille des données."""
    tailles = [0.1, 1, 5, 10, 50]
    algos = ['md5', 'sha256', 'sha512']
    couleurs = {'md5': '#e74c3c', 'sha256': '#3498db', 'sha512': '#2ecc71'}
    debits = {a: [] for a in algos}
    for t in tailles:
        data = os.urandom(int(t * 1024 * 1024))
        for algo in algos:
            t0 = time.perf_counter()
            hashlib.new(algo, data).hexdigest()
            duree = time.perf_counter() - t0
            debits[algo].append(t / duree)
    fig, ax = plt.subplots(figsize=(10, 5))
    for algo in algos:
        ax.plot(tailles, debits[algo], 'o-', label=algo.upper(),
                color=couleurs[algo], linewidth=2, markersize=6)
    ax.set_xlabel("Taille des données (Mo)")
    ax.set_ylabel("Débit (Mo/s)")
    ax.set_title("Scalabilité des fonctions de hachage")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    chemin = str(OUTPUT_DIR / "hachage_scalabilite.png")
    plt.savefig(chemin, dpi=120)
    plt.close()
    return chemin


def demo():
    print("=" * 60)
    print("  TP4 - Benchmark Hachage")
    print("=" * 60)
    print("\n--- Benchmark (10 Mo) ---")
    res = benchmark_complet(10.0)
    for algo, r in res.items():
        print(f"  {algo:8s}: {r['debit_mos']:6.0f} Mo/s | sortie {r['taille_sortie_bits']} bits")
    print("\n--- Graphiques ---")
    ch1 = graphique_benchmark(10.0)
    print(f"  Benchmark : {ch1}")
    ch2 = graphique_scalabilite()
    print(f"  Scalabilité : {ch2}")


if __name__ == "__main__":
    demo()
