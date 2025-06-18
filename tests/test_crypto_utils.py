import os
import pytest
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidSignature
from jose import ExpiredSignatureError, JWTError
from src.crypto_utils import AESCipher, JWTAuth, generate_hmac, verify_hmac

@pytest.fixture
def aes_key():
    return os.urandom(32)

@pytest.fixture
def hmac_key():
    return os.urandom(32)

@pytest.fixture
def jwt_secret():
    return os.urandom(32).hex()

@pytest.fixture
def aes_cipher(aes_key, hmac_key):
    return AESCipher(aes_key, hmac_key)

@pytest.fixture
def jwt_auth(jwt_secret, monkeypatch):
    monkeypatch.setenv('JWT_SECRET', jwt_secret)
    return JWTAuth()

class TestCryptoUtils:
    def test_encrypt_decrypt_success(self, aes_cipher):
        plaintext = b"mensagem secreta"
        iv, ct, mac = aes_cipher.encrypt(plaintext)
        result = aes_cipher.decrypt(iv, ct, mac)
        assert result == plaintext

    def test_encrypt_plaintext_vazio(self, aes_cipher):
        with pytest.raises(ValueError, match="Plaintext não pode ser vazio"):
            aes_cipher.encrypt(b"")

    def test_decrypt_hmac_invalido(self, aes_cipher):
        plaintext = b"mensagem"
        iv, ct, mac = aes_cipher.encrypt(plaintext)
        with pytest.raises(InvalidSignature, match="HMAC inválido"):
            aes_cipher.decrypt(iv, ct, "00"*32)

    def test_decrypt_iv_invalido(self, aes_cipher):
        plaintext = b"mensagem"
        iv, ct, mac = aes_cipher.encrypt(plaintext)
        with pytest.raises(ValueError, match="IV deve ter 16 bytes"):
            aes_cipher.decrypt(b"shortiv", ct, mac)

    def test_decrypt_ciphertext_invalido(self, aes_cipher):
        plaintext = b"mensagem"
        iv, ct, mac = aes_cipher.encrypt(plaintext)
        with pytest.raises(ValueError, match="Ciphertext inválido"):
            aes_cipher.decrypt(iv, ct[:-1], mac)

    def test_generate_and_verify_hmac(self, hmac_key):
        msg = b"comando"
        sig = generate_hmac(hmac_key, msg)
        assert verify_hmac(hmac_key, msg, sig)

    def test_verify_hmac_invalido(self, hmac_key):
        msg = b"comando"
        sig = "00"*32
        assert not verify_hmac(hmac_key, msg, sig)

    def test_jwt_generate_and_verify(self, jwt_auth):
        payload = {"user": "iot"}
        token = jwt_auth.generate_token(payload, expires_minutes=1)
        decoded = jwt_auth.verify_token(token)
        assert decoded["user"] == "iot"

    def test_jwt_expired(self, jwt_auth):
        payload = {"user": "iot"}
        token = jwt_auth.generate_token(payload, expires_minutes=-1)
        with pytest.raises(ExpiredSignatureError):
            jwt_auth.verify_token(token)

    def test_jwt_invalido(self, jwt_auth):
        with pytest.raises(JWTError):
            jwt_auth.verify_token("token_invalido")

    def test_logger_operation_id_in_logs(self, aes_cipher, caplog):
        with caplog.at_level('INFO'):
            plaintext = b"mensagem"
            aes_cipher.encrypt(plaintext)
        found = any('operation_id=' in rec.message for rec in caplog.records)
        assert found

    def test_logger_erro_plaintext_vazio(self, aes_cipher, caplog):
        with caplog.at_level('ERROR'):
            with pytest.raises(ValueError):
                aes_cipher.encrypt(b"")
        assert any("Plaintext não pode ser vazio" in rec.message for rec in caplog.records) 