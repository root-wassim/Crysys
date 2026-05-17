"""
TP1 - Exercice 1.2 : Chiffre de Vigenère
Implémentation + test de Kasiski + analyse par IC
"""

import string
from collections import Counter
from math import gcd
from functools import reduce
try:
    from tp1_classique.cesar import IC_FRANCAIS, FREQ_FRANCAIS
except ImportError:
    from cesar import IC_FRANCAIS, FREQ_FRANCAIS


def chiffrer_vigenere(texte: str, cle: str) -> str:
    """
    Chiffre un texte avec la clé Vigenère.
    La clé est un mot alphabétique. Espaces et casse ignorés.
    """
    cle = cle.upper()
    cle_pure = [c for c in cle if c in string.ascii_uppercase]
    if not cle_pure:
        raise ValueError("La clé doit contenir au moins une lettre.")

    lettres = [c for c in texte.upper() if c in string.ascii_uppercase]
    resultat = []
    for i, ch in enumerate(lettres):
        decalage = ord(cle_pure[i % len(cle_pure)]) - ord('A')
        resultat.append(chr((ord(ch) - ord('A') + decalage) % 26 + ord('A')))
    return ''.join(resultat)


def dechiffrer_vigenere(cryptogramme: str, cle: str) -> str:
    """Déchiffre un cryptogramme Vigenère."""
    cle = cle.upper()
    cle_pure = [c for c in cle if c in string.ascii_uppercase]
    lettres = [c for c in cryptogramme.upper() if c in string.ascii_uppercase]
    resultat = []
    for i, ch in enumerate(lettres):
        decalage = ord(cle_pure[i % len(cle_pure)]) - ord('A')
        resultat.append(chr((ord(ch) - ord('A') - decalage) % 26 + ord('A')))
    return ''.join(resultat)


def test_kasiski(cryptogramme: str, taille_gramme: int = 3) -> dict:
    """
    Test de Kasiski : cherche les trigrammes répétés et calcule
    les distances entre leurs occurrences pour estimer la longueur de clé.
    Retourne {longueur_probable: score}.
    """
    texte = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    distances = []

    # Trouver tous les n-grammes répétés
    grammes = {}
    for i in range(len(texte) - taille_gramme + 1):
        gramme = texte[i:i + taille_gramme]
        if gramme not in grammes:
            grammes[gramme] = []
        grammes[gramme].append(i)

    # Calculer les distances entre occurrences
    for gramme, positions in grammes.items():
        if len(positions) > 1:
            for i in range(1, len(positions)):
                dist = positions[i] - positions[i - 1]
                distances.append(dist)

    if not distances:
        return {}

    # Compter les GCDs entre distances → longueurs candidates
    scores = Counter()
    for i in range(len(distances)):
        for j in range(i + 1, len(distances)):
            g = gcd(distances[i], distances[j])
            if 2 <= g <= 20:
                scores[g] += 1

    # Inclure aussi les facteurs directs
    for d in distances:
        for f in range(2, min(d + 1, 20)):
            if d % f == 0:
                scores[f] += 1

    return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))


def ic_subsequence(texte: str, k: int, pos: int) -> float:
    """Calcule l'IC de la sous-séquence : texte[pos], texte[pos+k], texte[pos+2k]..."""
    try:
        from tp1_classique.cesar import indice_coincidence
    except ImportError:
        from cesar import indice_coincidence
    sous_seq = texte[pos::k]
    return indice_coincidence(sous_seq)


def trouver_longueur_cle_par_ic(cryptogramme: str, max_longueur: int = 20) -> int:
    """
    Estime la longueur de la clé par analyse des IC des sous-séquences.
    Pour la bonne longueur k, tous les IC ≈ IC_FRANCAIS.
    """
    texte = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    meilleur_k = 1
    meilleur_ic_moyen = 0.0

    for k in range(2, min(max_longueur + 1, len(texte) // 4)):
        ics = [ic_subsequence(texte, k, i) for i in range(k)]
        ic_moyen = sum(ics) / len(ics)
        if abs(ic_moyen - IC_FRANCAIS) < abs(meilleur_ic_moyen - IC_FRANCAIS):
            meilleur_ic_moyen = ic_moyen
            meilleur_k = k

    return meilleur_k


def trouver_lettre_cle(sous_seq: str) -> str:
    """
    Pour une sous-séquence (position fixe mod longueur_clé),
    trouve la lettre de la clé par analyse de fréquences.
    """
    lettres = [c for c in sous_seq.upper() if c in string.ascii_uppercase]
    if not lettres:
        return 'A'
    freq = Counter(lettres)
    total = len(lettres)

    meilleur_decalage = 0
    meilleur_score = float('inf')

    for decalage in range(26):
        score = 0.0
        for lettre in string.ascii_uppercase:
            lettre_orig = chr((ord(lettre) - ord('A') - decalage) % 26 + ord('A'))
            freq_attendue = FREQ_FRANCAIS.get(lettre_orig, 0) / 100
            freq_observee = freq.get(lettre, 0) / total
            score += abs(freq_attendue - freq_observee)
        if score < meilleur_score:
            meilleur_score = score
            meilleur_decalage = decalage

    return chr(meilleur_decalage + ord('A'))


def cryptanalyse_vigenere(cryptogramme: str) -> tuple[str, str]:
    """
    Cryptanalyse complète : Kasiski + IC → retrouve la clé et le clair.
    Retourne (cle_trouvee, texte_clair).
    """
    texte = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)

    # Étape 1 : estimer la longueur de la clé
    longueur = trouver_longueur_cle_par_ic(texte)

    # Étape 2 : pour chaque position mod longueur, trouver la lettre de clé
    cle = ''
    for i in range(longueur):
        sous_seq = texte[i::longueur]
        cle += trouver_lettre_cle(sous_seq)

    clair = dechiffrer_vigenere(texte, cle)
    return cle, clair


def demo():
    print("=" * 60)
    print("  TP1 - Chiffre de Vigenère")
    print("=" * 60)

    message = (
        "lacryptographieclassiqueutilisedessubstitutionsalphab"
        "etiquespourchiffrerlesmessagesmaisellerestevu"
        "lnerableauxattaquesparanalysedelangue"
    )
    cle = "CRYPTO"

    print(f"\nMessage  : {message[:60]}...")
    print(f"Clé      : {cle}")

    cryptogramme = chiffrer_vigenere(message, cle)
    print(f"Chiffré  : {cryptogramme[:60]}...")

    dechiffre = dechiffrer_vigenere(cryptogramme, cle)
    print(f"Déchiffré: {dechiffre[:60]}...")
    assert dechiffre == message.upper(), "Erreur de déchiffrement!"

    # Kasiski
    print("\n--- Test de Kasiski ---")
    scores_kasiski = test_kasiski(cryptogramme)
    print("Longueurs candidates (score) :")
    for longueur, score in list(scores_kasiski.items())[:6]:
        print(f"  longueur={longueur} → score={score}")

    # Cryptanalyse complète
    print("\n--- Cryptanalyse automatique ---")
    cle_trouvee, clair_trouve = cryptanalyse_vigenere(cryptogramme)
    print(f"Clé trouvée : {cle_trouvee}  (attendu : {cle})")
    print(f"Clair       : {clair_trouve[:60]}...")

    # Question théorique
    print("\n--- Question théorique ---")
    print("Plus la clé est longue, plus l'IC des sous-séquences")
    print("est difficile à distinguer d'un texte aléatoire.")
    print("Si |K| = |M|, Vigenère devient un OTP → sécurité parfaite.")


if __name__ == "__main__":
    demo()
