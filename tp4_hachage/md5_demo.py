"""
TP4 - Exercice 4.1 : MD5
Hachage, collisions connues, effet avalanche, vulnérabilités
"""
import hashlib, os, time


def md5_hash(data: bytes) -> str:
    """Calcule le hash MD5."""
    return hashlib.md5(data).hexdigest()


def md5_multi_messages() -> dict:
    """Calcule MD5 sur plusieurs messages et vérifie la taille constante."""
    messages = {
        'vide': b'',
        '1 octet': b'\x42',
        '1 Ko': os.urandom(1024),
        '1 Mo': os.urandom(1024 * 1024),
        'texte': b'Cryptographie Appliquee - MD5',
    }
    return {
        nom: {
            'hash': md5_hash(msg),
            'longueur_bits': 128,
            'toujours_128': len(md5_hash(msg)) == 32,
        }
        for nom, msg in messages.items()
    }


def effet_avalanche_md5(message: bytes) -> dict:
    """Flip 1 bit et mesure le % de bits différents dans le hash."""
    h1 = hashlib.md5(message).digest()
    msg_mod = bytes([message[0] ^ 0x01]) + message[1:] if message else b'\x00'
    h2 = hashlib.md5(msg_mod).digest()
    bits_diff = sum(bin(a ^ b).count('1') for a, b in zip(h1, h2))
    total = len(h1) * 8
    taux = bits_diff / total * 100
    return {
        'bits_differents': bits_diff,
        'bits_total': total,
        'taux_pct': taux,
        'avalanche_ok': 40 <= taux <= 60,
    }


def collision_md5_connue() -> dict:
    """
    Démontre une collision MD5 connue (Wang et Yu, 2004).
    Deux messages différents qui produisent le même hash MD5.
    """
    # Blocs de collision MD5 publiés par Wang et Yu
    m1 = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
    )
    m2 = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
    )
    h1 = hashlib.md5(m1).hexdigest()
    h2 = hashlib.md5(m2).hexdigest()
    return {
        'messages_differents': m1 != m2,
        'hash_m1': h1,
        'hash_m2': h2,
        'collision': h1 == h2,
        'nb_octets_differents': sum(a != b for a, b in zip(m1, m2)),
    }


def demo():
    print("=" * 60)
    print("  TP4 - MD5")
    print("=" * 60)
    print("\n--- Hash MD5 de plusieurs messages ---")
    for nom, r in md5_multi_messages().items():
        print(f"  {nom:12s}: {r['hash'][:20]}... ({r['longueur_bits']} bits)")
    print("\n--- Effet avalanche ---")
    av = effet_avalanche_md5(b"test message avalanche")
    print(f"  Bits différents : {av['bits_differents']}/{av['bits_total']} ({av['taux_pct']:.1f}%)")
    print("\n--- Collision MD5 (Wang & Yu, 2004) ---")
    col = collision_md5_connue()
    print(f"  Messages différents : {col['messages_differents']}")
    print(f"  Octets différents   : {col['nb_octets_differents']}")
    print(f"  Hash M1 : {col['hash_m1']}")
    print(f"  Hash M2 : {col['hash_m2']}")
    print(f"  COLLISION : {col['collision']} ← MD5 est CASSÉ !")
    print("\n  → MD5 ne doit JAMAIS être utilisé pour la sécurité.")
    print("    Usage résiduel : checksum de fichiers (non-adversarial).")


if __name__ == "__main__":
    demo()
