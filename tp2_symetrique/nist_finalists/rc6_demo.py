"""
TP2 - NIST Finalists : RC6 (démo pédagogique)
Basé sur RC5 avec des multiplications (data-dependent rotations)
"""
import os, time, struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

W = 32       # taille des mots (bits)
R = 20       # nombre de tours
MASK = 0xFFFFFFFF
LOG_W = 5    # log2(W)


def rotl(x, n):
    """Rotation gauche 32 bits."""
    n = n % W
    return ((x << n) | (x >> (W - n))) & MASK


def rotr(x, n):
    """Rotation droite 32 bits."""
    n = n % W
    return ((x >> n) | (x << (W - n))) & MASK


def rc6_key_schedule(key: bytes) -> list[int]:
    """
    Key expansion RC6 : génère 2R+4 sous-clés de 32 bits.
    Utilise les constantes magiques P32 et Q32.
    """
    P32 = 0xB7E15163
    Q32 = 0x9E3779B9
    # Conversion de la clé en mots de 32 bits
    c = max(len(key) // 4, 1)
    L = [0] * c
    for i in range(len(key) - 1, -1, -1):
        L[i // 4] = (L[i // 4] << 8) + key[i]
    # Initialisation du tableau S
    t = 2 * R + 4
    S = [(P32 + i * Q32) & MASK for i in range(t)]
    # Mélange
    A = B = i = j = 0
    for _ in range(3 * max(t, c)):
        A = S[i] = rotl((S[i] + A + B) & MASK, 3)
        B = L[j] = rotl((L[j] + A + B) & MASK, (A + B) % W)
        i = (i + 1) % t
        j = (j + 1) % c
    return S


def rc6_encrypt_block(block: bytes, S: list) -> bytes:
    """Chiffre un bloc de 16 octets avec RC6."""
    A, B, C, D = struct.unpack('<4I', block)
    B = (B + S[0]) & MASK
    D = (D + S[1]) & MASK
    for i in range(1, R + 1):
        t = rotl((B * (2 * B + 1)) & MASK, LOG_W)
        u = rotl((D * (2 * D + 1)) & MASK, LOG_W)
        A = (rotl(A ^ t, u % W) + S[2 * i]) & MASK
        C = (rotl(C ^ u, t % W) + S[2 * i + 1]) & MASK
        A, B, C, D = B, C, D, A
    A = (A + S[2 * R + 2]) & MASK
    C = (C + S[2 * R + 3]) & MASK
    return struct.pack('<4I', A, B, C, D)


def rc6_decrypt_block(block: bytes, S: list) -> bytes:
    """Déchiffre un bloc de 16 octets avec RC6."""
    A, B, C, D = struct.unpack('<4I', block)
    C = (C - S[2 * R + 3]) & MASK
    A = (A - S[2 * R + 2]) & MASK
    for i in range(R, 0, -1):
        A, B, C, D = D, A, B, C
        u = rotl((D * (2 * D + 1)) & MASK, LOG_W)
        t = rotl((B * (2 * B + 1)) & MASK, LOG_W)
        C = rotr((C - S[2 * i + 1]) & MASK, t % W) ^ u
        A = rotr((A - S[2 * i]) & MASK, u % W) ^ t
    D = (D - S[1]) & MASK
    B = (B - S[0]) & MASK
    return struct.pack('<4I', A, B, C, D)


def rc6_encrypt(plaintext: bytes, key: bytes) -> bytes:
    S = rc6_key_schedule(key)
    padded = pad(plaintext, 16)
    ct = b''
    for i in range(0, len(padded), 16):
        ct += rc6_encrypt_block(padded[i:i+16], S)
    return ct


def rc6_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    S = rc6_key_schedule(key)
    pt = b''
    for i in range(0, len(ciphertext), 16):
        pt += rc6_decrypt_block(ciphertext[i:i+16], S)
    return unpad(pt, 16)


def demo():
    print("=" * 60)
    print("  TP2 - RC6 (finaliste NIST)")
    print("=" * 60)
    key = os.urandom(32)
    message = b"RC6 utilise des multiplications pour ses rotations!"
    print(f"\nMessage  : {message}")
    ct = rc6_encrypt(message, key)
    print(f"Chiffré  : {ct.hex()[:40]}...")
    pt = rc6_decrypt(ct, key)
    print(f"Déchiffré: {pt}")
    print(f"Correct  : {pt == message}")
    print("\n--- Caractéristiques RC6 ---")
    print("  Bloc : 128 bits | Clé : 128/192/256 bits")
    print("  Tours : 20 | Structure : réseau de Feistel généralisé")
    print("  Innovation : rotations dépendantes des données (DDR)")
    print("  Utilise des multiplications modulo 2^32")
    print("  Conçu par Rivest, Robshaw, Sidney, Yin (RSA Labs)")
    data = os.urandom(1024 * 16)
    t0 = time.perf_counter()
    rc6_encrypt(data, key)
    t_rc6 = time.perf_counter() - t0
    t0 = time.perf_counter()
    AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
    t_aes = time.perf_counter() - t0
    print(f"\n--- Benchmark (16 Ko) ---")
    print(f"  RC6   : {t_rc6*1000:.1f} ms")
    print(f"  AES   : {t_aes*1000:.1f} ms")


if __name__ == "__main__":
    demo()
