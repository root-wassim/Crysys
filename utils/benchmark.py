"""
utils/benchmark.py — Utilitaires de mesure de performance
"""

import time
import functools
import statistics
from typing import Callable, Any


def timer(fn: Callable) -> Callable:
    """
    Décorateur qui mesure et affiche le temps d'exécution d'une fonction.

    Usage :
        @timer
        def ma_fonction():
            ...
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        debut = time.perf_counter()
        resultat = fn(*args, **kwargs)
        duree = time.perf_counter() - debut
        print(f"  [{fn.__name__}] : {duree * 1000:.3f} ms")
        return resultat
    return wrapper


def benchmark_func(fn: Callable, *args, n: int = 10, **kwargs) -> dict:
    """
    Exécute `fn(*args, **kwargs)` n fois et retourne les statistiques.

    Retourne :
        {
            'min_ms': float,
            'max_ms': float,
            'mean_ms': float,
            'median_ms': float,
            'stdev_ms': float,
            'n': int,
        }
    """
    durees = []
    for _ in range(n):
        debut = time.perf_counter()
        fn(*args, **kwargs)
        durees.append((time.perf_counter() - debut) * 1000)

    return {
        'min_ms': min(durees),
        'max_ms': max(durees),
        'mean_ms': statistics.mean(durees),
        'median_ms': statistics.median(durees),
        'stdev_ms': statistics.stdev(durees) if n > 1 else 0.0,
        'n': n,
    }


def benchmark_debit(fn: Callable, taille_octets: int, *args, n: int = 5, **kwargs) -> dict:
    """
    Mesure le débit en Mo/s pour une fonction de chiffrement/hachage.

    Args :
        fn : fonction à benchmarker
        taille_octets : taille des données traitées par appel
        n : nombre d'itérations

    Retourne :
        {
            'debit_mos': float,
            'duree_mean_ms': float,
            ...stats...
        }
    """
    stats = benchmark_func(fn, *args, n=n, **kwargs)
    taille_mo = taille_octets / (1024 * 1024)
    debit = taille_mo / (stats['mean_ms'] / 1000) if stats['mean_ms'] > 0 else 0
    stats['debit_mos'] = debit
    stats['taille_mo'] = taille_mo
    return stats


def comparer_algos(algos: dict, taille_octets: int = 1024 * 1024, n: int = 5) -> dict:
    """
    Compare plusieurs algorithmes.

    Args :
        algos : {'nom_algo': callable, ...}
        taille_octets : taille des données de test

    Retourne :
        {'nom_algo': {...stats...}, ...}
    """
    import os
    donnees = os.urandom(taille_octets)
    resultats = {}
    for nom, fn in algos.items():
        try:
            resultats[nom] = benchmark_debit(fn, taille_octets, donnees, n=n)
        except TypeError:
            # fn ne prend pas de données en argument direct
            resultats[nom] = benchmark_func(fn, n=n)
    return resultats
