"""
TP2 - NIST Finalists : MARS (démo pédagogique)
Structure hétérogène (pré-mélange, tours cryptographiques, post-mélange)
Conçu par IBM (Don Coppersmith et al.)
"""
import os, time, struct, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

MASK32 = 0xFFFFFFFF


def rotl32(x, n):
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & MASK32


def rotr32(x, n):
    n = n % 32
    return ((x >> n) | (x << (32 - n))) & MASK32


def mars_key_schedule(key: bytes) -> list[int]:
    """Génère 40 sous-clés de 32 bits (simplifié via SHA)."""
    subkeys = []
    for i in range(40):
        h = hashlib.sha256(key + struct.pack('>I', i) + b'MARS').digest()
        subkeys.append(int.from_bytes(h[:4], 'big'))
    return subkeys


def mars_e_function(a: int, key1: int, key2: int) -> tuple[int, int, int]:
    """Fonction E de MARS (simplifiée) — cœur cryptographique."""
    r = a ^ key1
    m = (a + key2) & MASK32
    r = rotl32(r, 13)
    l = r ^ ((r << 5) & MASK32) ^ ((r >> 5) & MASK32)
    m = rotl32(m, r & 0x1F)
    return l, m, r


def mars_encrypt_block(block: bytes, subkeys: list) -> bytes:
    """Chiffre un bloc de 16 octets (structure MARS simplifiée)."""
    D = list(struct.unpack('<4I', block))
    # Phase 1 : Pré-mélange (addition des sous-clés)
    for i in range(4):
        D[i] = (D[i] + subkeys[i]) & MASK32
    # Phase 2 : 8 tours avant (type 1)
    for i in range(8):
        D[0] = rotl32(D[0] ^ D[1], D[1] & 0x1F)
        D[0] = (D[0] + subkeys[4 + i]) & MASK32
        D[0], D[1], D[2], D[3] = D[1], D[2], D[3], D[0]
    # Phase 3 : 16 tours cryptographiques (E-function)
    for i in range(16):
        l, m, r = mars_e_function(D[0], subkeys[12 + i * 2], subkeys[13 + i * 2])
        D[1] = (D[1] + l) & MASK32
        D[2] = (D[2] ^ m) & MASK32
        D[3] = (D[3] + r) & MASK32
        D[0], D[1], D[2], D[3] = D[1], D[2], D[3], D[0]
    # Phase 4 : Post-mélange
    for i in range(4):
        D[i] = D[i] ^ subkeys[36 + i]
    return struct.pack('<4I', *D)


def mars_encrypt(plaintext: bytes, key: bytes) -> bytes:
    subkeys = mars_key_schedule(key)
    padded = pad(plaintext, 16)
    ct = b''
    for i in range(0, len(padded), 16):
        ct += mars_encrypt_block(padded[i:i+16], subkeys)
    return ct


def demo():
    print("=" * 60)
    print("  TP2 - MARS (finaliste NIST)")
    print("=" * 60)
    key = os.urandom(32)
    message = b"MARS fut concu par IBM, createurs de DES et Lucifer"
    print(f"\nMessage  : {message}")
    ct = mars_encrypt(message, key)
    print(f"Chiffré  : {ct.hex()[:40]}...")
    print("\n--- Caractéristiques MARS ---")
    print("  Bloc : 128 bits | Clé : 128-448 bits (variable)")
    print("  Structure : hétérogène en 3 phases")
    print("    1. Pré-mélange (8 tours simples)")
    print("    2. Cœur crypto (16 tours avec E-function)")
    print("    3. Post-mélange (8 tours simples)")
    print("  Conçu par IBM (Coppersmith, Halevi, Jutla)")
    print("  Breveté → obstacle pour sélection NIST")
    data = os.urandom(1024 * 16)
    t0 = time.perf_counter()
    mars_encrypt(data, key)
    t_mars = time.perf_counter() - t0
    t0 = time.perf_counter()
    AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
    t_aes = time.perf_counter() - t0
    print(f"\n--- Benchmark (16 Ko) ---")
    print(f"  MARS  : {t_mars*1000:.1f} ms")
    print(f"  AES   : {t_aes*1000:.1f} ms")
    print("\n--- Pourquoi AES (Rijndael) a gagné ? ---")
    print("  1. Simplicité et élégance mathématique (GF(2^8))")
    print("  2. Performance excellente en logiciel ET matériel")
    print("  3. Pas de brevet (libre de droits)")
    print("  4. Résistance prouvée aux attaques connues")
    print("  5. Implémentation facile sur processeurs embarqués")


if __name__ == "__main__":
    demo()
