"""Tests TP2 — Chiffrement symétrique"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tp2_symetrique.rc4 import *
from tp2_symetrique.des_modes import *
from tp2_symetrique.aes_modes import *


class TestRC4:
    def test_chiffrement_dechiffrement(self):
        # RC4 : re-chiffrer le chiffré avec la même clé = déchiffrer
        cle = b"secret"
        msg = b"test message"
        ct = rc4_chiffrer(msg, cle)
        pt = rc4_dechiffrer(ct, cle)
        assert pt == msg


class TestDES:
    def test_ecb(self):
        cle = b"DESKEY!!"
        msg = b"A" * 64
        ct = des_ecb_chiffrer(msg, cle)
        pt = des_ecb_dechiffrer(ct, cle)
        assert pt == msg

    def test_cbc(self):
        cle = b"DESKEY!!"
        msg = b"Test DES CBC mode!"
        ct, iv = des_cbc_chiffrer(msg, cle)
        pt = des_cbc_dechiffrer(ct, cle, iv)
        assert pt == msg

    def test_3des_cbc(self):
        cle = os.urandom(24)
        msg = b"Triple DES!"
        ct, iv = triple_des_cbc_chiffrer(msg, cle)
        pt = triple_des_cbc_dechiffrer(ct, cle, iv)
        assert pt == msg


class TestAES:
    def test_ecb(self):
        cle = os.urandom(16)
        msg = b"AES ECB test msg"
        ct = aes_ecb_chiffrer(msg, cle)
        pt = aes_ecb_dechiffrer(ct, cle)
        assert pt == msg

    def test_cbc_256(self):
        cle = os.urandom(32)
        msg = b"AES-256 CBC!" * 10
        ct, iv = aes_cbc_chiffrer(msg, cle)
        pt = aes_cbc_dechiffrer(ct, cle, iv)
        assert pt == msg

    def test_ctr(self):
        cle = os.urandom(32)
        msg = b"CTR mode test"
        ct, nonce = aes_ctr_chiffrer(msg, cle)
        pt = aes_ctr_dechiffrer(ct, cle, nonce)
        assert pt == msg

    def test_ecb_blocs_identiques(self):
        cle = os.urandom(16)
        msg = b"AAAAAAAAAAAAAAAA" * 4
        ct = aes_ecb_chiffrer(msg, cle)
        blocs = [ct[i:i+16] for i in range(0, len(ct), 16)]
        # ECB : blocs identiques → chiffrés identiques
        assert blocs[0] == blocs[1]
