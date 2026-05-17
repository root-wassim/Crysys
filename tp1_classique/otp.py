"""
TP1 - Exercice 1.4 : One-Time Pad (Vernam)
OTP XOR + vulnérabilité de réutilisation + crib dragging
"""

import os
import string
from collections import Counter


def generer_cle_otp(longueur: int) -> bytes:
    """Génère une clé OTP aléatoire cryptographiquement sûre."""
    return os.urandom(longueur)


def chiffrer_otp(message: bytes, cle: bytes) -> bytes:
    """
    Chiffre un message par XOR octet à octet avec la clé.
    Requiert len(cle) >= len(message).
    """
    if len(cle) < len(message):
        raise ValueError("La clé OTP doit être au moins aussi longue que le message !")
    return bytes(m ^ k for m, k in zip(message, cle))


def dechiffrer_otp(cryptogramme: bytes, cle: bytes) -> bytes:
    """Déchiffre un cryptogramme OTP (XOR est son propre inverse)."""
    return chiffrer_otp(cryptogramme, cle)


def vulnerabilite_reutilisation(m1: bytes, m2: bytes, cle: bytes) -> bytes:
    """
    Démontre la vulnérabilité de réutilisation de clé.
    C1 = M1 XOR K,  C2 = M2 XOR K
    C1 XOR C2 = M1 XOR M2  (la clé s'annule)
    Un attaquant obtient M1 XOR M2 sans connaître K.
    """
    c1 = chiffrer_otp(m1, cle)
    c2 = chiffrer_otp(m2, cle)
    xor_chiffres = bytes(a ^ b for a, b in zip(c1, c2))
    return c1, c2, xor_chiffres


def score_texte_anglais(data: bytes) -> float:
    """Score heuristique : caractères ASCII imprimables courants."""
    score = 0
    for b in data:
        if 32 <= b <= 126:
            score += 1
        if chr(b).lower() in 'etaoinshr ':
            score += 2
    return score


def crib_dragging(xor_m1_m2: bytes, crib: str) -> list[dict]:
    """
    Attaque « crib dragging » (tirage de bâillon).
    Principe : si on suppose qu'un mot (crib) apparaît dans M1,
    on XOR le crib à chaque position sur M1⊕M2 et on observe
    si le résultat ressemble à du texte lisible dans M2.

    Retourne la liste des positions candidates avec le texte récupéré de M2.
    """
    crib_bytes = crib.upper().encode('ascii')
    n_crib = len(crib_bytes)
    n_msg = len(xor_m1_m2)
    resultats = []

    for pos in range(n_msg - n_crib + 1):
        # Candidat pour M2[pos:pos+n_crib]
        m2_segment = bytes(xor_m1_m2[pos + i] ^ crib_bytes[i] for i in range(n_crib))
        score = score_texte_anglais(m2_segment)

        try:
            m2_txt = m2_segment.decode('ascii')
            if all(c in string.printable for c in m2_txt):
                resultats.append({
                    'position': pos,
                    'crib': crib,
                    'fragment_m2': m2_txt,
                    'score': score
                })
        except UnicodeDecodeError:
            pass

    return sorted(resultats, key=lambda x: x['score'], reverse=True)


def analyser_xor_frequences(xor_data: bytes) -> dict:
    """
    Analyse statistique de M1⊕M2.
    Les espaces (0x20) sont courants → XOR(espace, lettre) = lettre±32.
    Ce biais permet de récupérer des informations sur les lettres.
    """
    frequences = Counter(xor_data)
    analyse = {}

    for byte_val, count in frequences.most_common(10):
        # Hypothèse : l'un des octets est un espace (0x20)
        char_si_espace_m1 = chr(byte_val ^ 0x20) if 32 <= (byte_val ^ 0x20) <= 126 else '?'
        char_si_espace_m2 = chr(byte_val ^ 0x20) if 32 <= (byte_val ^ 0x20) <= 126 else '?'
        analyse[byte_val] = {
            'count': count,
            'hex': hex(byte_val),
            'si_espace_dans_m1_alors_m2': char_si_espace_m1,
            'si_espace_dans_m2_alors_m1': char_si_espace_m2,
        }
    return analyse


def demo():
    print("=" * 60)
    print("  TP1 - One-Time Pad (Vernam)")
    print("=" * 60)

    # Démonstration de base
    message = b"Cryptographie appliquee"
    cle = generer_cle_otp(len(message))

    print(f"\nMessage   : {message}")
    print(f"Clé (hex) : {cle.hex()}")

    cryptogramme = chiffrer_otp(message, cle)
    print(f"Chiffré   : {cryptogramme.hex()}")

    recupere = dechiffrer_otp(cryptogramme, cle)
    print(f"Déchiffré : {recupere}")
    assert recupere == message, "Erreur OTP !"
    print("✓ Restitution exacte vérifiée")

    # Vulnérabilité de réutilisation
    print("\n--- Vulnérabilité de réutilisation de clé ---")
    m1 = b"ATTACKATDAWN    "
    m2 = b"WEAREDISCOVERED "
    longueur = min(len(m1), len(m2))
    cle_reutilisee = generer_cle_otp(longueur)

    c1, c2, xor_c1_c2 = vulnerabilite_reutilisation(
        m1[:longueur], m2[:longueur], cle_reutilisee
    )

    print(f"M1        : {m1[:longueur]}")
    print(f"M2        : {m2[:longueur]}")
    print(f"C1 (hex)  : {c1.hex()}")
    print(f"C2 (hex)  : {c2.hex()}")
    print(f"C1⊕C2     : {xor_c1_c2.hex()}")

    # Vérification : C1⊕C2 = M1⊕M2
    xor_m1_m2 = bytes(a ^ b for a, b in zip(m1[:longueur], m2[:longueur]))
    print(f"M1⊕M2     : {xor_m1_m2.hex()}")
    assert xor_c1_c2 == xor_m1_m2, "Erreur : C1⊕C2 ≠ M1⊕M2 !"
    print("✓ C1⊕C2 = M1⊕M2 (la clé s'est annulée)")

    # Crib dragging
    print("\n--- Attaque Crib Dragging ---")
    candidats = crib_dragging(xor_c1_c2, "ATTACK")
    if candidats:
        for c in candidats[:3]:
            print(f"  pos={c['position']:2d} | crib='{c['crib']}' → M2≈'{c['fragment_m2']}' (score={c['score']})")
    else:
        print("  Aucune position candidate (essayer un autre crib)")

    # Obstacles OTP
    print("\n--- Obstacles pratiques de l'OTP ---")
    obstacles = [
        "1. Distribution sécurisée de la clé (aussi longue que le message)",
        "2. Génération vraiment aléatoire (PRNG insuffisant)",
        "3. Stockage sécurisé et destruction après usage",
        "4. Impossibilité de réutilisation → pas de session longue",
        "5. Scalabilité nulle (une clé par message, par destinataire)",
    ]
    for o in obstacles:
        print(f"  {o}")


if __name__ == "__main__":
    demo()
