"""Tests TP4 — Fonctions de hachage"""
import sys, os, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tp4_hachage.sha256_impl import sha256_impl, valider_sha256_impl
from tp4_hachage.md5_demo import md5_hash, effet_avalanche_md5
from tp4_hachage.sha512_demo import sha512_hash, hmac_sha256


class TestSHA256:
    def test_vecteurs_connus(self):
        assert sha256_impl(b'abc') == hashlib.sha256(b'abc').hexdigest()
        assert sha256_impl(b'') == hashlib.sha256(b'').hexdigest()

    def test_validation_complete(self):
        assert valider_sha256_impl()

    def test_taille_sortie(self):
        h = sha256_impl(b'test')
        assert len(h) == 64  # 256 bits = 64 hex


class TestMD5:
    def test_hash(self):
        assert md5_hash(b'') == hashlib.md5(b'').hexdigest()
        assert md5_hash(b'abc') == hashlib.md5(b'abc').hexdigest()

    def test_avalanche(self):
        res = effet_avalanche_md5(b"test avalanche")
        assert 30 <= res['taux_pct'] <= 70


class TestSHA512:
    def test_hash(self):
        assert sha512_hash(b'test') == hashlib.sha512(b'test').hexdigest()

    def test_hmac(self):
        import hmac as hmac_lib
        cle = b"secret_key"
        msg = b"message"
        assert hmac_sha256(cle, msg) == hmac_lib.new(cle, msg, hashlib.sha256).hexdigest()
