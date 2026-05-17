"""
utils/logger.py — Logger coloré pour le projet cryptographie
"""

import sys
import time
from datetime import datetime


# Codes couleur ANSI
class Couleurs:
    RESET   = "\033[0m"
    GRAS    = "\033[1m"
    ROUGE   = "\033[91m"
    VERT    = "\033[92m"
    JAUNE   = "\033[93m"
    BLEU    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    BLANC   = "\033[97m"
    GRIS    = "\033[90m"


def _support_couleurs() -> bool:
    """Détecte si le terminal supporte les couleurs ANSI."""
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


COULEURS_ACTIVES = _support_couleurs()


def _formater(prefixe: str, couleur: str, message: str) -> str:
    heure = datetime.now().strftime("%H:%M:%S")
    if COULEURS_ACTIVES:
        return (
            f"{Couleurs.GRIS}[{heure}]{Couleurs.RESET} "
            f"{couleur}{Couleurs.GRAS}{prefixe}{Couleurs.RESET} "
            f"{message}"
        )
    return f"[{heure}] {prefixe} {message}"


def info(message: str) -> None:
    """Message informatif (bleu)."""
    print(_formater("INFO   ", Couleurs.BLEU, message))


def succes(message: str) -> None:
    """Message de succès (vert)."""
    print(_formater("OK ✓   ", Couleurs.VERT, message))


def avertissement(message: str) -> None:
    """Avertissement (jaune)."""
    print(_formater("WARN ⚠ ", Couleurs.JAUNE, message))


def erreur(message: str) -> None:
    """Erreur (rouge)."""
    print(_formater("ERREUR ✗", Couleurs.ROUGE, message), file=sys.stderr)


def debug(message: str) -> None:
    """Message de debug (gris)."""
    print(_formater("DEBUG  ", Couleurs.GRIS, message))


def titre(texte: str, largeur: int = 60) -> None:
    """Affiche un titre encadré."""
    if COULEURS_ACTIVES:
        print(f"\n{Couleurs.CYAN}{Couleurs.GRAS}{'═' * largeur}")
        print(f"  {texte}")
        print(f"{'═' * largeur}{Couleurs.RESET}\n")
    else:
        print(f"\n{'=' * largeur}\n  {texte}\n{'=' * largeur}\n")


def section(texte: str) -> None:
    """Affiche un titre de section."""
    if COULEURS_ACTIVES:
        print(f"\n{Couleurs.MAGENTA}{Couleurs.GRAS}--- {texte} ---{Couleurs.RESET}")
    else:
        print(f"\n--- {texte} ---")


class Chronometre:
    """Contexte pour mesurer un temps d'exécution."""

    def __init__(self, label: str = ""):
        self.label = label
        self._debut = None

    def __enter__(self):
        self._debut = time.perf_counter()
        return self

    def __exit__(self, *args):
        duree = time.perf_counter() - self._debut
        msg = f"{self.label} : {duree * 1000:.3f} ms" if self.label else f"{duree * 1000:.3f} ms"
        succes(msg)
        self.duree_ms = duree * 1000
