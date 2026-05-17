"""Tests TP3 — Chiffrement asymétrique"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tp3_asymetrique.rsa import generer_paire_rsa, rsa_chiffrer_oaep, rsa_dechiffrer_oaep
from tp3_asymetrique.rsa import chiffrement_hybride_rsa_aes, dechiffrement_hybride_rsa_aes
from tp3_asymetrique.elgamal import elgamal_generer_cles, elgamal_chiffrer, elgamal_dechiffrer
from tp3_asymetrique.diffie_hellman import echange_dh
from tp3_asymetrique.hybrid_rsa_aes import chiffrement_hybride, dechiffrement_hybride
from tp3_asymetrique.hybrid_rsa_aes import generer_paire_rsa as gen_rsa


class TestRSA:
    def test_oaep_2048(self):
        priv, pub = generer_paire_rsa(2048)
        msg = b"Test RSA-2048"
        ct = rsa_chiffrer_oaep(msg, pub)
        pt = rsa_dechiffrer_oaep(ct, priv)
        assert pt == msg

    def test_hybride(self):
        priv, pub = generer_paire_rsa(2048)
        msg = b"A" * 1000
        paquet = chiffrement_hybride_rsa_aes(msg, pub)
        pt = dechiffrement_hybride_rsa_aes(paquet, priv)
        assert pt == msg


class TestElGamal:
    def test_chiffrement_dechiffrement(self):
        cle = elgamal_generer_cles()
        M = 42
        C1, C2 = elgamal_chiffrer(M, cle)
        D = elgamal_dechiffrer(C1, C2, cle)
        assert D == M

    def test_non_determinisme(self):
        cle = elgamal_generer_cles()
        M = 100
        c1 = elgamal_chiffrer(M, cle)
        c2 = elgamal_chiffrer(M, cle)
        assert c1 != c2  # non-déterministe


class TestDH:
    def test_echange(self):
        res = echange_dh()
        assert res['secrets_identiques']


class TestHybride:
    def test_rsa_aes_gcm(self):
        priv, pub = gen_rsa(2048)
        msg = b"Hybrid RSA+AES-GCM test" * 100
        paquet = chiffrement_hybride(msg, pub)
        pt = dechiffrement_hybride(paquet, priv)
        assert pt == msg
