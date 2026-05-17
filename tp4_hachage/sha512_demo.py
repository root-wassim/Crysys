"""
TP4 - Exercice 4.3 : SHA-512 + HMAC
SHA-512 via hashlib, comparaison SHA-256/512, HMAC authentification
"""
import hashlib, hmac, os, time


def sha512_hash(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def comparer_sha256_sha512(message: bytes) -> dict:
    """Compare SHA-256 et SHA-512 sur le même message."""
    h256 = hashlib.sha256(message).hexdigest()
    h512 = hashlib.sha512(message).hexdigest()
    return {
        'sha256': h256,
        'sha512': h512,
        'sha256_bits': 256,
        'sha512_bits': 512,
        'sha256_hex_len': len(h256),
        'sha512_hex_len': len(h512),
    }


def effet_avalanche_sha512(message: bytes) -> dict:
    """Effet avalanche sur SHA-512."""
    h1 = hashlib.sha512(message).digest()
    msg_mod = bytes([message[0] ^ 0x01]) + message[1:] if message else b'\x00'
    h2 = hashlib.sha512(msg_mod).digest()
    bits_diff = sum(bin(a ^ b).count('1') for a, b in zip(h1, h2))
    total = len(h1) * 8
    return {
        'bits_differents': bits_diff,
        'bits_total': total,
        'taux_pct': bits_diff / total * 100,
    }


def hmac_sha256(cle: bytes, message: bytes) -> str:
    """Calcule HMAC-SHA256."""
    return hmac.new(cle, message, hashlib.sha256).hexdigest()


def hmac_sha512(cle: bytes, message: bytes) -> str:
    """Calcule HMAC-SHA512."""
    return hmac.new(cle, message, hashlib.sha512).hexdigest()


def hmac_verification_demo() -> dict:
    """Démontre l'authentification par HMAC."""
    cle = os.urandom(32)
    msg = b"Message a authentifier"
    tag = hmac_sha256(cle, msg)
    # Vérification correcte
    tag_verif = hmac_sha256(cle, msg)
    ok = hmac.compare_digest(tag, tag_verif)
    # Falsification
    msg_faux = b"Message falsifie!!!"
    tag_faux = hmac_sha256(cle, msg_faux)
    detecte = not hmac.compare_digest(tag, tag_faux)
    # Mauvaise clé
    mauvaise_cle = os.urandom(32)
    tag_mauvais = hmac_sha256(mauvaise_cle, msg)
    cle_detectee = not hmac.compare_digest(tag, tag_mauvais)
    return {
        'tag': tag,
        'verification_ok': ok,
        'falsification_detectee': detecte,
        'mauvaise_cle_detectee': cle_detectee,
    }


def benchmark_sha(taille_mo: float = 10.0) -> dict:
    """Benchmark SHA-256 vs SHA-512."""
    data = os.urandom(int(taille_mo * 1024 * 1024))
    resultats = {}
    for algo in ['sha256', 'sha512']:
        t0 = time.perf_counter()
        hashlib.new(algo, data).hexdigest()
        duree = time.perf_counter() - t0
        resultats[algo] = {
            'duree_s': duree,
            'debit_mos': taille_mo / duree,
        }
    return resultats


def demo():
    print("=" * 60)
    print("  TP4 - SHA-512 et HMAC")
    print("=" * 60)
    msg = b"Cryptographie appliquee SHA-512"
    print(f"\n--- Comparaison SHA-256 vs SHA-512 ---")
    comp = comparer_sha256_sha512(msg)
    print(f"  SHA-256 ({comp['sha256_bits']} bits) : {comp['sha256'][:32]}...")
    print(f"  SHA-512 ({comp['sha512_bits']} bits) : {comp['sha512'][:32]}...")
    print(f"\n--- Effet avalanche SHA-512 ---")
    av = effet_avalanche_sha512(msg)
    print(f"  {av['bits_differents']}/{av['bits_total']} bits différents ({av['taux_pct']:.1f}%)")
    print(f"\n--- HMAC-SHA256 ---")
    hm = hmac_verification_demo()
    print(f"  Tag : {hm['tag'][:32]}...")
    print(f"  Vérification OK       : {hm['verification_ok']}")
    print(f"  Falsification détectée: {hm['falsification_detectee']}")
    print(f"  Mauvaise clé détectée : {hm['mauvaise_cle_detectee']}")
    print(f"\n--- Benchmark (10 Mo) ---")
    bench = benchmark_sha(10.0)
    for algo, r in bench.items():
        print(f"  {algo} : {r['debit_mos']:.0f} Mo/s")
    print("\n  → SHA-512 est souvent PLUS RAPIDE que SHA-256 sur CPU 64 bits")
    print("    car ses opérations internes travaillent sur des mots de 64 bits.")


if __name__ == "__main__":
    demo()
