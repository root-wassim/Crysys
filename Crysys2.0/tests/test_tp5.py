"""Tests TP5 — Signatures numériques"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.signatures.rsa_pss import generer_paire, signer_rsa_pss, verifier_rsa_pss
from crypto.signatures.dsa_ecdsa import (
    dsa_generer_cles, dsa_signer, dsa_verifier,
    ecdsa_generer_cles, ecdsa_signer, ecdsa_verifier
)


class TestRSAPSS:
    def test_sign_verify(self):
        priv, pub = generer_paire(2048)
        msg = b"Test RSA-PSS signature"
        sig = signer_rsa_pss(msg, priv)
        assert verifier_rsa_pss(msg, sig, pub)

    def test_falsification(self):
        priv, pub = generer_paire(2048)
        msg = b"Original"
        sig = signer_rsa_pss(msg, priv)
        assert not verifier_rsa_pss(b"Falsifie", sig, pub)

    def test_non_determinisme(self):
        priv, pub = generer_paire(2048)
        msg = b"test"
        s1 = signer_rsa_pss(msg, priv)
        s2 = signer_rsa_pss(msg, priv)
        assert s1 != s2  # PSS est probabiliste


class TestDSA:
    def test_sign_verify(self):
        priv, pub = dsa_generer_cles(2048)
        msg = b"DSA test"
        sig = dsa_signer(msg, priv)
        assert dsa_verifier(msg, sig, pub)

    def test_falsification(self):
        priv, pub = dsa_generer_cles(2048)
        sig = dsa_signer(b"OK", priv)
        assert not dsa_verifier(b"NOT OK", sig, pub)


class TestECDSA:
    def test_sign_verify(self):
        priv, pub = ecdsa_generer_cles()
        msg = b"ECDSA test"
        sig = ecdsa_signer(msg, priv)
        assert ecdsa_verifier(msg, sig, pub)

    def test_falsification(self):
        priv, pub = ecdsa_generer_cles()
        sig = ecdsa_signer(b"Original", priv)
        assert not ecdsa_verifier(b"Falsifie", sig, pub)
