import sys
import os

sys.path.insert(0, r"c:\Users\LENOVO\Desktop\crypto project\Crysys2.0")
import wrapper

algos = ["caesar", "affine", "vigenere", "playfair", "hill", "rc4", "des", "aes", "rc6", "serpent", "rsa", "elgamal"]

print("========================================")
print("Testing C Engine via wrapper.py")
print("========================================")

test_text = "HELLO WORLD CRYPTOGRAPHY ENGINE TEST 123"

keys = {
    "caesar": "3",
    "affine": "5,8",
    "vigenere": "SECRET",
    "playfair": "PLAYFAIRKEY",
    "hill": "9 4 5 7",
    "rc4": "mysecretkey",
    "des": "deskey12",
    "aes": "aeskey1234567890",
    "rc6": "rc6key1234567890",
    "serpent": "serpentkey123456",
    "rsa": "65537,10968988637",
    "elgamal": "104729,2"
}

extras = {
    "caesar": {"shift": 3},
    "affine": {"a_param": 5, "b_param": 8},
    "hill": {"matrix_size": 2}
}

for algo in algos:
    print(f"\nTesting algorithm: {algo}")
    
    if algo in ["rsa", "elgamal"]:
        print(f"  [Asymmetric Keygen] Generating keypair...")
        kg_res = wrapper.keygen(algo)
        print(f"  Keygen Output:\n{kg_res.get('output')}")
        if algo == "rsa":
            lines = kg_res['output'].splitlines()
            pub = lines[0].split(":")[1].strip()
            priv = lines[1].split(":")[1].strip()
            
            enc_res = wrapper.encrypt_text(algo, "HELLO", key=pub)
            print(f"  Encrypt: success={enc_res['success']}, output={enc_res.get('output') or enc_res.get('error')}")
            
            dec_res = wrapper.decrypt_text(algo, enc_res.get('output', ''), key=priv)
            print(f"  Decrypt: success={dec_res['success']}, output={dec_res.get('output') or dec_res.get('error')}")
        else: # elgamal
            lines = kg_res['output'].splitlines()
            priv = lines[0].split(":")[1].strip()
            pub = lines[1].split(":")[1].strip()
            
            enc_res = wrapper.encrypt_text(algo, "HELLO", key=pub)
            print(f"  Encrypt: success={enc_res['success']}, output={enc_res.get('output') or enc_res.get('error')}")
            
            dec_res = wrapper.decrypt_text(algo, enc_res.get('output', ''), key=priv)
            print(f"  Decrypt: success={dec_res['success']}, output={dec_res.get('output') or dec_res.get('error')}")
        continue

    key = keys.get(algo, "defaultkey")
    ext = extras.get(algo, {})
    
    enc_res = wrapper.encrypt_text(algo, test_text, key=key, **ext)
    print(f"  Encrypt: success={enc_res['success']}, output={enc_res.get('output') or enc_res.get('error')}")
    
    if enc_res['success']:
        dec_res = wrapper.decrypt_text(algo, enc_res['output'], key=key, **ext)
        print(f"  Decrypt: success={dec_res['success']}, output={dec_res.get('output') or dec_res.get('error')}")
        expected = test_text
        if algo in ["playfair", "hill"]:
            expected = "".join([c.upper() for c in test_text if c.isalpha()])
        if not dec_res['success'] or dec_res['output'].strip() != expected.strip():
            print(f"  [FAIL] Decryption details: res={dec_res}")
        else:
            print("  [SUCCESS] Plaintext matches!")
    else:
        print("  [FAIL] Encryption failed!")
