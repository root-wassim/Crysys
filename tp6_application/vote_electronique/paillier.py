"""
TP6 - Vote Électronique : Chiffrement homomorphe de Paillier
Les votes sont chiffrés et additionnés SANS les déchiffrer individuellement
"""
import os, json


def generer_cles_paillier(n_bits: int = 1024):
    """Génère une paire de clés Paillier via python-paillier."""
    from phe import paillier
    pub, priv = paillier.generate_paillier_keypair(n_length=n_bits)
    return pub, priv


def chiffrer_vote(vote: int, cle_publique) -> object:
    """Chiffre un vote (0 ou 1) avec Paillier."""
    return cle_publique.encrypt(vote)


def additionner_votes_chiffres(votes_chiffres: list) -> object:
    """
    Propriété homomorphe additive de Paillier :
    E(a) × E(b) mod n² = E(a + b)
    → On peut sommer les votes chiffrés sans les déchiffrer !
    """
    total = votes_chiffres[0]
    for v in votes_chiffres[1:]:
        total = total + v  # opérateur + surchargé par phe
    return total


def dechiffrer_total(total_chiffre, cle_privee) -> int:
    """Déchiffre le total des votes."""
    return cle_privee.decrypt(total_chiffre)


def demo_vote():
    """Simulation complète d'un vote électronique avec Paillier."""
    print("=" * 60)
    print("  TP6 - Vote Électronique (Paillier)")
    print("=" * 60)

    try:
        from phe import paillier
    except ImportError:
        print("\n  ERREUR : python-paillier non installé.")
        print("  → pip install python-paillier")
        return

    # Génération des clés (bureau de vote)
    print("\n--- Génération des clés ---")
    pub, priv = generer_cles_paillier(1024)
    print(f"  Clé publique n : {str(pub.n)[:40]}...")

    # Votes : 1 = OUI, 0 = NON
    votes_clairs = [1, 0, 1, 1, 0, 1, 1, 0, 1, 1]
    nb_votants = len(votes_clairs)
    total_attendu = sum(votes_clairs)

    print(f"\n--- Votes ({nb_votants} votants) ---")
    print(f"  Votes en clair (JAMAIS visibles en vrai) : {votes_clairs}")
    print(f"  Total attendu : {total_attendu} OUI / {nb_votants - total_attendu} NON")

    # Chiffrement des votes
    print("\n--- Chiffrement des votes ---")
    votes_chiffres = []
    for i, v in enumerate(votes_clairs):
        vc = chiffrer_vote(v, pub)
        votes_chiffres.append(vc)
        print(f"  Votant {i+1:2d} : vote={v} → chiffré={str(vc.ciphertext())[:20]}...")

    # Addition homomorphe (SANS déchiffrer les votes individuels)
    print("\n--- Addition homomorphe ---")
    total_chiffre = additionner_votes_chiffres(votes_chiffres)
    print(f"  Total chiffré : {str(total_chiffre.ciphertext())[:30]}...")

    # Vérification : les votes individuels n'ont JAMAIS été déchiffrés
    print("  ✓ Aucun vote individuel n'a été déchiffré !")

    # Déchiffrement du total uniquement
    print("\n--- Déchiffrement du résultat ---")
    total = dechiffrer_total(total_chiffre, priv)
    print(f"  Résultat : {total} OUI / {nb_votants - total} NON")
    print(f"  Correct  : {total == total_attendu}")

    # Propriétés de sécurité
    print("\n--- Propriétés de sécurité ---")
    print("  1. Confidentialité : chaque vote est chiffré individuellement")
    print("  2. Homomorphie    : E(v1) × E(v2) = E(v1 + v2) mod n²")
    print("  3. Le serveur additionne les chiffrés SANS voir les votes")
    print("  4. Seul le détenteur de la clé privée peut déchiffrer le TOTAL")
    print("  5. Non-déterministe : E(1) ≠ E(1) (aléa intégré)")

    # Vérification non-déterminisme
    v1 = chiffrer_vote(1, pub)
    v2 = chiffrer_vote(1, pub)
    print(f"\n  E(1) ≠ E(1) : {v1.ciphertext() != v2.ciphertext()}")
    print(f"  D(E(1)) == D(E(1)) : {priv.decrypt(v1) == priv.decrypt(v2)}")


if __name__ == "__main__":
    demo_vote()
