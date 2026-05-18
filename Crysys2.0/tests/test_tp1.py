"""Tests TP1 — Chiffres classiques"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.classic.cesar import chiffrer_cesar, dechiffrer_cesar, indice_coincidence, attaque_par_ic
from crypto.classic.vigenere import chiffrer_vigenere, dechiffrer_vigenere
from crypto.classic.hill import chiffrer_hill, dechiffrer_hill, valider_matrice_cle
from crypto.classic.otp import chiffrer_otp, dechiffrer_otp, generer_cle_otp


class TestCesar:
    def test_chiffrement_dechiffrement(self):
        msg = "bonjour"
        for k in range(26):
            assert dechiffrer_cesar(chiffrer_cesar(msg, k), k) == msg.upper().replace(" ", "")

    def test_rot13(self):
        assert chiffrer_cesar("ABC", 13) == "NOP"

    def test_ic_texte_francais(self):
        texte = "la cryptographie est la science du secret"
        ic = indice_coincidence(texte)
        assert 0.05 < ic < 0.10

    def test_attaque_ic(self):
        msg = "le chiffrement de cesar est simple"
        k = 7
        crypto = chiffrer_cesar(msg, k)
        k_trouve = attaque_par_ic(crypto)
        assert k_trouve == k


class TestVigenere:
    def test_chiffrement_dechiffrement(self):
        msg = "lacryptographieclassique"
        cle = "CRYPTO"
        crypto = chiffrer_vigenere(msg, cle)
        assert dechiffrer_vigenere(crypto, cle) == msg.upper()

    def test_cle_differente(self):
        msg = "test"
        c1 = chiffrer_vigenere(msg, "ABC")
        c2 = chiffrer_vigenere(msg, "XYZ")
        assert c1 != c2


class TestHill:
    def test_matrice_2x2(self):
        K = [[3, 3], [2, 5]]
        assert valider_matrice_cle(K)
        msg = "HILL"
        crypto = chiffrer_hill(msg, K)
        assert dechiffrer_hill(crypto, K) == msg

    def test_matrice_invalide(self):
        K = [[2, 4], [6, 8]]
        assert not valider_matrice_cle(K)


class TestOTP:
    def test_chiffrement_dechiffrement(self):
        msg = b"secret message"
        cle = generer_cle_otp(len(msg))
        crypto = chiffrer_otp(msg, cle)
        assert dechiffrer_otp(crypto, cle) == msg

    def test_cle_trop_courte(self):
        import pytest
        with pytest.raises(ValueError):
            chiffrer_otp(b"long message", b"short")

    def test_xor_annulation(self):
        msg = b"ABCDEF"
        cle = generer_cle_otp(len(msg))
        c1 = chiffrer_otp(msg, cle)
        msg2 = b"GHIJKL"
        c2 = chiffrer_otp(msg2, cle)
        xor_c = bytes(a ^ b for a, b in zip(c1, c2))
        xor_m = bytes(a ^ b for a, b in zip(msg, msg2))
        assert xor_c == xor_m
