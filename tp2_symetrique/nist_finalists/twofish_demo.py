"""
TP2 - NIST Finalists : Twofish (démo pédagogique)
Implémentation simplifiée de la structure Feistel-like de Twofish
Utilise PyCryptodome pour la comparaison AES
"""
import os, time, hashlib, struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def twofish_key_schedule(key: bytes) -> list:
    """Génère les sous-clés Twofish (simplifié via hachage)."""
    subkeys = []
    for i in range(40):
        h = hashlib.sha256(key + struct.pack('>I', i)).digest()
        subkeys.append(int.from_bytes(h[:4], 'big'))
    return subkeys


def twofish_f_function(x: int, subkey: int) -> int:
    """Fonction F de Twofish (simplifiée pédagogiquement)."""
    x = x ^ subkey
    x = ((x * 0x01010101) & 0xFFFFFFFF)
    x = ((x >> 8) | (x << 24)) & 0xFFFFFFFF
    return x


def twofish_encrypt_block(block: bytes, subkeys: list) -> bytes:
    """Chiffre un bloc de 16 octets avec Twofish (structure Feistel 16 tours)."""
    assert len(block) == 16
    L = int.from_bytes(block[:8], 'big')
    R = int.from_bytes(block[8:], 'big')
    # Whitening d'entrée
    L ^= (subkeys[0] | (subkeys[1] << 32)) & ((1 << 64) - 1)
    R ^= (subkeys[2] | (subkeys[3] << 32)) & ((1 << 64) - 1)
    # 16 tours Feistel
    for i in range(16):
        f_out = twofish_f_function(L & 0xFFFFFFFF, subkeys[4 + i * 2])
        f_out2 = twofish_f_function((L >> 32) & 0xFFFFFFFF, subkeys[5 + i * 2])
        R ^= (f_out | (f_out2 << 32)) & ((1 << 64) - 1)
        L, R = R, L
    # Whitening de sortie
    L ^= (subkeys[36] | (subkeys[37] << 32)) & ((1 << 64) - 1)
    R ^= (subkeys[38] | (subkeys[39] << 32)) & ((1 << 64) - 1)
    return L.to_bytes(8, 'big') + R.to_bytes(8, 'big')


def twofish_decrypt_block(block: bytes, subkeys: list) -> bytes:
    """Déchiffre un bloc de 16 octets (inverse du chiffrement)."""
    assert len(block) == 16
    L = int.from_bytes(block[:8], 'big')
    R = int.from_bytes(block[8:], 'big')
    L ^= (subkeys[36] | (subkeys[37] << 32)) & ((1 << 64) - 1)
    R ^= (subkeys[38] | (subkeys[39] << 32)) & ((1 << 64) - 1)
    for i in range(15, -1, -1):
        L, R = R, L
        f_out = twofish_f_function(L & 0xFFFFFFFF, subkeys[4 + i * 2])
        f_out2 = twofish_f_function((L >> 32) & 0xFFFFFFFF, subkeys[5 + i * 2])
        R ^= (f_out | (f_out2 << 32)) & ((1 << 64) - 1)
    L ^= (subkeys[0] | (subkeys[1] << 32)) & ((1 << 64) - 1)
    R ^= (subkeys[2] | (subkeys[3] << 32)) & ((1 << 64) - 1)
    return L.to_bytes(8, 'big') + R.to_bytes(8, 'big')


def twofish_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Chiffre un message complet (ECB, avec padding PKCS7)."""
    subkeys = twofish_key_schedule(key)
    padded = pad(plaintext, 16)
    ct = b''
    for i in range(0, len(padded), 16):
        ct += twofish_encrypt_block(padded[i:i+16], subkeys)
    return ct


def twofish_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Déchiffre un message complet."""
    subkeys = twofish_key_schedule(key)
    pt = b''
    for i in range(0, len(ciphertext), 16):
        pt += twofish_decrypt_block(ciphertext[i:i+16], subkeys)
    return unpad(pt, 16)


def demo():
    print("=" * 60)
    print("  TP2 - Twofish (finaliste NIST)")
    print("=" * 60)
    key = os.urandom(32)
    message = b"Twofish est un finaliste AES concu par Bruce Schneier!"
    print(f"\nMessage  : {message}")
    print(f"Clé (hex): {key.hex()[:32]}...")
    ct = twofish_encrypt(message, key)
    print(f"Chiffré  : {ct.hex()[:40]}...")
    pt = twofish_decrypt(ct, key)
    print(f"Déchiffré: {pt}")
    print(f"Correct  : {pt == message}")
    print("\n--- Caractéristiques Twofish ---")
    print("  Bloc : 128 bits | Clé : 128/192/256 bits")
    print("  Structure : réseau de Feistel modifié (16 tours)")
    print("  S-Boxes : dépendantes de la clé (sécurité accrue)")
    print("  Performance : légèrement plus lent qu'AES sur x86")
    # Benchmark vs AES
    data = os.urandom(1024 * 64)
    t0 = time.perf_counter()
    twofish_encrypt(data, key)
    t_tw = time.perf_counter() - t0
    t0 = time.perf_counter()
    AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
    t_aes = time.perf_counter() - t0
    print(f"\n--- Benchmark (64 Ko) ---")
    print(f"  Twofish : {t_tw*1000:.1f} ms")
    print(f"  AES-256 : {t_aes*1000:.1f} ms")
    print(f"  Ratio   : Twofish {t_tw/t_aes:.1f}x plus lent")


if __name__ == "__main__":
    demo()
