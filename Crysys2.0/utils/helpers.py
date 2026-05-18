"""
utils/helpers.py — Fonctions utilitaires partagées entre tous les TPs
"""

import os
import struct
import hashlib
import binascii
from pathlib import Path


# ─── Répertoire de sortie pour les graphiques / exports ───
OUTPUT_DIR = Path(__file__).parent.parent / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def output_path(filename: str) -> str:
    """Retourne le chemin absolu dans le dossier outputs/."""
    return str(OUTPUT_DIR / filename)


# ─── Conversions entier ↔ bytes ───────────────────────────

def int_to_bytes(n: int, length: int = None, byteorder: str = 'big') -> bytes:
    """Convertit un entier en bytes (big-endian par défaut)."""
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, byteorder)


def bytes_to_int(b: bytes, byteorder: str = 'big') -> int:
    """Convertit des bytes en entier."""
    return int.from_bytes(b, byteorder)


# ─── Affichage ────────────────────────────────────────────

def hex_dump(data: bytes, width: int = 16) -> str:
    """
    Affiche un dump hexadécimal formaté (style xxd).
    Exemple :
        00000000: 48 65 6c 6c 6f  Hello
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:08x}: {hex_part:<{width * 3}} {asc_part}")
    return '\n'.join(lines)


def bits_differents(a: bytes, b: bytes) -> tuple[int, float]:
    """
    Calcule le nombre de bits différents entre deux séquences (XOR bit à bit).
    Retourne (nb_bits_diff, pourcentage).
    """
    longueur = min(len(a), len(b))
    nb = sum(bin(x ^ y).count('1') for x, y in zip(a, b))
    total = longueur * 8
    return nb, (nb / total * 100) if total > 0 else 0.0


# ─── Arithmétique modulaire ───────────────────────────────

def pgcd(a: int, b: int) -> int:
    """PGCD via algorithme d'Euclide."""
    while b:
        a, b = b, a % b
    return a


def pgcd_etendu(a: int, b: int) -> tuple[int, int, int]:
    """Algorithme d'Euclide étendu : retourne (gcd, x, y) tel que ax + by = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = pgcd_etendu(b % a, a)
    return g, y1 - (b // a) * x1, x1


def inverse_mod(a: int, m: int) -> int:
    """Inverse modulaire de a mod m. Lève ValueError si inexistant."""
    g, x, _ = pgcd_etendu(a % m, m)
    if g != 1:
        raise ValueError(f"Pas d'inverse modulaire pour {a} mod {m}")
    return x % m


def puissance_mod(base: int, exp: int, mod: int) -> int:
    """Exponentiation rapide (équivalent à pow(base, exp, mod))."""
    return pow(base, exp, mod)


# ─── Test de primalité ────────────────────────────────────

def est_premier_miller_rabin(n: int, k: int = 20) -> bool:
    """Test de primalité probabiliste de Miller-Rabin."""
    if n < 2:
        return False
    if n in (2, 3, 5, 7):
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generer_premier(bits: int) -> int:
    """Génère un nombre premier aléatoire de `bits` bits."""
    import random
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # forcer le MSB et l'impair
        if est_premier_miller_rabin(n):
            return n


# ─── Dérivation de clé ────────────────────────────────────

def deriver_cle(secret: bytes, longueur: int = 32, info: bytes = b'') -> bytes:
    """Dérive une clé depuis un secret via SHA-256 (HKDF simplifié)."""
    h = hashlib.sha256(secret + info).digest()
    while len(h) < longueur:
        h += hashlib.sha256(h + info).digest()
    return h[:longueur]


# ─── Séparateurs visuels ─────────────────────────────────

def titre(texte: str, largeur: int = 60) -> str:
    """Retourne un titre formaté."""
    return f"\n{'=' * largeur}\n  {texte}\n{'=' * largeur}"


def section(texte: str) -> str:
    """Retourne un en-tête de section formaté."""
    return f"\n--- {texte} ---"
