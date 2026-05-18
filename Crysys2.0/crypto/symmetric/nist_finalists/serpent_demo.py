"""
TP2 - NIST Finalists : Serpent (démo pédagogique)
Structure SPN (Substitution-Permutation Network) 32 tours
"""
import os, time, hashlib, struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# S-Boxes Serpent (versions simplifiées pédagogiques - 4 bits)
SBOXES = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
]

SBOXES_INV = []
for sbox in SBOXES:
    inv = [0] * 16
    for i, v in enumerate(sbox):
        inv[v] = i
    SBOXES_INV.append(inv)


def serpent_key_schedule(key: bytes) -> list[int]:
    """Génère 33 sous-clés de 128 bits via hachage (simplifié)."""
    subkeys = []
    for i in range(33):
        h = hashlib.sha256(key + struct.pack('>I', i)).digest()
        subkeys.append(int.from_bytes(h[:16], 'big'))
    return subkeys


def serpent_apply_sbox(state: int, round_num: int, inverse: bool = False) -> int:
    """Applique la S-Box appropriée (4 bits à la fois) sur l'état 128 bits."""
    sbox = SBOXES_INV[round_num % 8] if inverse else SBOXES[round_num % 8]
    result = 0
    for i in range(32):
        nibble = (state >> (i * 4)) & 0xF
        result |= sbox[nibble] << (i * 4)
    return result


def serpent_linear_transform(state: int) -> int:
    """Transformation linéaire (simplifiée) — rotation et XOR."""
    mask = (1 << 128) - 1
    x0 = (state >> 96) & 0xFFFFFFFF
    x1 = (state >> 64) & 0xFFFFFFFF
    x2 = (state >> 32) & 0xFFFFFFFF
    x3 = state & 0xFFFFFFFF
    x0 = ((x0 << 13) | (x0 >> 19)) & 0xFFFFFFFF
    x2 = ((x2 << 3) | (x2 >> 29)) & 0xFFFFFFFF
    x1 = x1 ^ x0 ^ x2
    x3 = x3 ^ x2 ^ ((x0 << 3) & 0xFFFFFFFF)
    x1 = ((x1 << 1) | (x1 >> 31)) & 0xFFFFFFFF
    x3 = ((x3 << 7) | (x3 >> 25)) & 0xFFFFFFFF
    x0 = x0 ^ x1 ^ x3
    x2 = x2 ^ x3 ^ ((x1 << 7) & 0xFFFFFFFF)
    x0 = ((x0 << 5) | (x0 >> 27)) & 0xFFFFFFFF
    x2 = ((x2 << 22) | (x2 >> 10)) & 0xFFFFFFFF
    return (x0 << 96) | (x1 << 64) | (x2 << 32) | x3


def serpent_encrypt_block(block: bytes, subkeys: list) -> bytes:
    """Chiffre un bloc 128 bits avec Serpent (32 tours SPN)."""
    state = int.from_bytes(block[:16], 'big')
    for r in range(31):
        state ^= subkeys[r]
        state = serpent_apply_sbox(state, r)
        state = serpent_linear_transform(state)
    state ^= subkeys[31]
    state = serpent_apply_sbox(state, 31)
    state ^= subkeys[32]
    return state.to_bytes(16, 'big')


def serpent_encrypt(plaintext: bytes, key: bytes) -> bytes:
    subkeys = serpent_key_schedule(key)
    padded = pad(plaintext, 16)
    ct = b''
    for i in range(0, len(padded), 16):
        ct += serpent_encrypt_block(padded[i:i+16], subkeys)
    return ct


def demo():
    print("=" * 60)
    print("  TP2 - Serpent (finaliste NIST)")
    print("=" * 60)
    key = os.urandom(32)
    message = b"Serpent : le plus conservateur des finalistes AES"
    print(f"\nMessage  : {message}")
    ct = serpent_encrypt(message, key)
    print(f"Chiffré  : {ct.hex()[:40]}...")
    print("\n--- Caractéristiques Serpent ---")
    print("  Bloc : 128 bits | Clé : 128/192/256 bits")
    print("  Structure : SPN (Substitution-Permutation Network)")
    print("  Tours : 32 (vs 14 pour AES-256) → marge de sécurité maximale")
    print("  Conçu par Anderson, Biham, Knudsen (cryptanalystes réputés)")
    print("  Performance : ~2x plus lent que Rijndael (AES) en logiciel")
    data = os.urandom(1024 * 16)
    t0 = time.perf_counter()
    serpent_encrypt(data, key)
    t_sp = time.perf_counter() - t0
    t0 = time.perf_counter()
    AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
    t_aes = time.perf_counter() - t0
    print(f"\n--- Benchmark (16 Ko) ---")
    print(f"  Serpent : {t_sp*1000:.1f} ms")
    print(f"  AES-256 : {t_aes*1000:.1f} ms")
    print(f"  Ratio   : Serpent {t_sp/t_aes:.1f}x plus lent")


if __name__ == "__main__":
    demo()
