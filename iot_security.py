# iot_security.py
# Script de funções de segurança para aplicações IoT
# Requer: cryptography, pyjwt, hmac, hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import jwt  # pyjwt
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, Any
from cryptography.exceptions import InvalidKey, InvalidSignature
from jwt import ExpiredSignatureError, InvalidTokenError
import logging

# =========================
# Configuração de logging aprimorada
# =========================
def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None) -> None:
    """
    Configura o sistema de logging.
    :param level: Nível de log (ex: logging.DEBUG)
    :param log_file: Caminho para arquivo de log (opcional)
    """
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=handlers
    )

logger = logging.getLogger(__name__)

# =========================
# Utilitários para segredos seguros
# =========================

def get_env_var(name: str) -> str:
    """
    Obtém uma variável de ambiente ou lança exceção se não definida.
    :param name: Nome da variável de ambiente
    :return: Valor da variável
    :raises EnvironmentError: Se a variável não estiver definida
    """
    value = os.getenv(name)
    if not value:
        logger.error(f"Variável de ambiente '{name}' não definida.")
        raise EnvironmentError(f"Variável de ambiente '{name}' não definida.")
    return value

def generate_hmac_key(length: int = 32) -> bytes:
    """
    Gera uma chave HMAC aleatória de tamanho especificado.
    :param length: Tamanho em bytes (mínimo recomendado: 16)
    :return: Chave HMAC
    :raises ValueError: Se o comprimento for menor que 16 bytes
    """
    if length < 16:
        raise ValueError("O comprimento da chave HMAC deve ser pelo menos 16 bytes para segurança.")
    return os.urandom(length)

# =========================
# 1. AES-256-CBC + HMAC (Encrypt-then-MAC)
# =========================

class AESCipher:
    """
    Classe para criptografia e descriptografia AES-256-CBC com autenticação HMAC-SHA256 (Encrypt-then-MAC).

    Parâmetros:
        key (bytes): Chave AES de 32 bytes.
        hmac_key (bytes): Chave HMAC de pelo menos 16 bytes.
    Exceções:
        ValueError: Se as chaves forem inválidas.
    """
    def __init__(self, key: bytes, hmac_key: Optional[bytes] = None, hmac_key_length: int = 32):
        """
        Inicializa o AESCipher.
        :param key: Chave AES de 32 bytes
        :param hmac_key: Chave HMAC de pelo menos 16 bytes (opcional)
        :param hmac_key_length: Comprimento da chave HMAC a ser gerada se hmac_key não for fornecida
        :raises ValueError: Se as chaves forem inválidas
        """
        if len(key) != 32:
            logger.error("A chave AES deve ter 32 bytes (256 bits)")
            raise ValueError("A chave AES deve ter 32 bytes (256 bits)")
        if hmac_key is None:
            hmac_key = generate_hmac_key(hmac_key_length)
            logger.info(f"Chave HMAC gerada aleatoriamente com {hmac_key_length} bytes.")
        if len(hmac_key) < 16:
            logger.error("A chave HMAC deve ter pelo menos 16 bytes")
            raise ValueError("A chave HMAC deve ter pelo menos 16 bytes")
        self.key = key
        self.hmac_key = hmac_key

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes, str]:
        """
        Criptografa e autentica o plaintext.
        :param plaintext: Dados a criptografar (não pode ser vazio)
        :return: (iv, ciphertext, hmac_hex)
        :raises ValueError: Se o plaintext for vazio
        :raises Exception: Em caso de erro de criptografia
        """
        if not plaintext:
            logger.error("O plaintext não pode ser vazio para criptografia.")
            raise ValueError("O plaintext não pode ser vazio.")
        try:
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded) + encryptor.finalize()
            mac = hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).hexdigest()
            logger.info("Criptografia e autenticação realizadas com sucesso.")
            return iv, ciphertext, mac
        except Exception as e:
            logger.error(f"Erro ao criptografar: {e}")
            raise Exception(f"Erro ao criptografar: {e}")

    def decrypt(self, iv: bytes, ciphertext: bytes, mac_hex: str) -> bytes:
        """
        Verifica a integridade e descriptografa o ciphertext.
        :param iv: Vetor de inicialização
        :param ciphertext: Dados criptografados
        :param mac_hex: HMAC em hexadecimal
        :return: plaintext
        :raises InvalidSignature: Se o HMAC não for válido
        :raises Exception: Em caso de erro de descriptografia
        """
        expected_mac = hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, mac_hex):
            logger.error("HMAC inválido: integridade comprometida.")
            raise InvalidSignature("HMAC inválido: integridade comprometida.")
        try:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            logger.info("Descriptografia e verificação de integridade realizadas com sucesso.")
            return plaintext
        except ValueError as e:
            logger.error(f"Erro de padding ou chave inválida: {e}")
            raise Exception(f"Erro de padding ou chave inválida: {e}")
        except Exception as e:
            logger.error(f"Erro ao descriptografar: {e}")
            raise Exception(f"Erro ao descriptografar: {e}")

# =========================
# 2. JWT (Autenticação) - Classe
# =========================

class JWTAuth:
    """
    Classe para geração e verificação de tokens JWT.
    O segredo é obtido de variável de ambiente.

    Parâmetros:
        secret_env (str): Nome da variável de ambiente para o segredo JWT.
    Exceções:
        EnvironmentError: Se a variável não estiver definida.
    """
    def __init__(self, secret_env: str = 'JWT_SECRET'):
        """
        Inicializa o JWTAuth.
        :param secret_env: Nome da variável de ambiente para o segredo JWT
        :raises EnvironmentError: Se a variável não estiver definida
        """
        self.secret = get_env_var(secret_env)

    def generate_token(self, payload: Dict[str, Any], expires_minutes: int = 60) -> str:
        """
        Gera um token JWT assinado.
        :param payload: Dados do payload
        :param expires_minutes: Tempo de expiração em minutos
        :return: Token JWT (string)
        """
        payload_copy = payload.copy()
        payload_copy['exp'] = datetime.utcnow() + timedelta(minutes=expires_minutes)
        token = jwt.encode(payload_copy, self.secret, algorithm='HS256')
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        logger.info("Token JWT gerado com sucesso.")
        return token

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verifica e decodifica um token JWT.
        :param token: Token JWT
        :return: Payload decodificado
        :raises ExpiredSignatureError: Se o token estiver expirado
        :raises InvalidTokenError: Se o token for inválido
        """
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            logger.info("Token JWT verificado com sucesso.")
            return payload
        except ExpiredSignatureError as e:
            logger.error("Token JWT expirado.")
            raise ExpiredSignatureError("Token JWT expirado.") from e
        except InvalidTokenError as e:
            logger.error("Token JWT inválido.")
            raise InvalidTokenError("Token JWT inválido.") from e

# =========================
# 3. HMAC-SHA256 (Assinatura de comandos)
# =========================

def generate_hmac(key: bytes, message: bytes) -> str:
    """
    Gera uma assinatura HMAC-SHA256 para a mensagem.
    :param key: Chave HMAC (mínimo 16 bytes)
    :param message: Mensagem a assinar
    :return: Assinatura em hexadecimal
    :raises ValueError: Se a chave for muito curta
    """
    if len(key) < 16:
        logger.error("A chave HMAC deve ter pelo menos 16 bytes.")
        raise ValueError("A chave HMAC deve ter pelo menos 16 bytes.")
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, message: bytes, signature_hex: str) -> bool:
    """
    Verifica se a assinatura HMAC-SHA256 é válida para a mensagem.
    :param key: Chave HMAC (mínimo 16 bytes)
    :param message: Mensagem original
    :param signature_hex: Assinatura em hexadecimal
    :return: True se válido, False caso contrário
    :raises ValueError: Se a chave for muito curta
    """
    if len(key) < 16:
        logger.error("A chave HMAC deve ter pelo menos 16 bytes.")
        raise ValueError("A chave HMAC deve ter pelo menos 16 bytes.")
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)

# =========================
# Bloco de testes unitários (ativável/desativável)
# =========================
if __name__ == "__test__":
    import unittest
    import tempfile
    import shutil

    class TestAESCipher(unittest.TestCase):
        def setUp(self):
            self.key = os.urandom(32)
            self.hmac_key = os.urandom(32)
            self.cipher = AESCipher(self.key, self.hmac_key)

        def test_encrypt_decrypt(self):
            plaintext = b"mensagem secreta"
            iv, ct, mac = self.cipher.encrypt(plaintext)
            result = self.cipher.decrypt(iv, ct, mac)
            self.assertEqual(result, plaintext)

        def test_empty_plaintext(self):
            with self.assertRaises(ValueError):
                self.cipher.encrypt(b"")

        def test_invalid_hmac(self):
            plaintext = b"mensagem"
            iv, ct, mac = self.cipher.encrypt(plaintext)
            with self.assertRaises(InvalidSignature):
                self.cipher.decrypt(iv, ct, "00"*32)

        def test_hmac_key_length(self):
            with self.assertRaises(ValueError):
                AESCipher(self.key, b"short")

        def test_generate_hmac_key(self):
            key = generate_hmac_key(24)
            self.assertEqual(len(key), 24)
            with self.assertRaises(ValueError):
                generate_hmac_key(8)

    class TestJWTAuth(unittest.TestCase):
        def setUp(self):
            self.secret = "testsecret"
            os.environ['JWT_SECRET'] = self.secret
            self.jwt_auth = JWTAuth()

        def test_generate_and_verify(self):
            payload = {"user": "iot"}
            token = self.jwt_auth.generate_token(payload, expires_minutes=1)
            decoded = self.jwt_auth.verify_token(token)
            self.assertEqual(decoded["user"], "iot")

        def test_expired_token(self):
            payload = {"user": "iot"}
            token = self.jwt_auth.generate_token(payload, expires_minutes=-1)
            with self.assertRaises(ExpiredSignatureError):
                self.jwt_auth.verify_token(token)

    class TestHMACFunctions(unittest.TestCase):
        def setUp(self):
            self.key = os.urandom(32)
            self.msg = b"comando"

        def test_generate_and_verify(self):
            sig = generate_hmac(self.key, self.msg)
            self.assertTrue(verify_hmac(self.key, self.msg, sig))

        def test_invalid_key(self):
            with self.assertRaises(ValueError):
                generate_hmac(b"short", self.msg)
            with self.assertRaises(ValueError):
                verify_hmac(b"short", self.msg, "00"*32)

    unittest.main()

# =========================
# Exemplo de uso comentado (não execute em produção)
# =========================
# if __name__ == "__main__":
#     setup_logging(level=logging.DEBUG, log_file="iot_security.log")
#     # Exemplo de uso seguro
#     try:
#         aes_key = get_env_var('AES_KEY').encode('utf-8')
#         hmac_key = get_env_var('HMAC_KEY').encode('utf-8')
#     except EnvironmentError as e:
#         logger.error(f"Erro: {e}")
#         exit(1)
#
#     cipher = AESCipher(aes_key, hmac_key)
#     mensagem = b"Mensagem IoT confidencial"
#     try:
#         iv, ct, mac = cipher.encrypt(mensagem)
#         logger.info(f"Ciphertext (hex): {ct.hex()}")
#         logger.info(f"HMAC: {mac}")
#         plaintext = cipher.decrypt(iv, ct, mac)
#         logger.info(f"Decriptado com sucesso: {plaintext.decode('utf-8')}")
#     except Exception as e:
#         logger.error(f"Erro de criptografia: {e}")
#
#     jwt_auth = JWTAuth()
#     token = jwt_auth.generate_token({"device_id": 123})
#     logger.info(f"JWT token: {token}")
#     payload = jwt_auth.verify_token(token)
#     logger.info(f"JWT verificado. Claims: {list(payload.keys())}")
#
#     comando = b"comando importante"
#     sig = generate_hmac(hmac_key, comando)
#     logger.info(f"HMAC signature: {sig}")
#     valid = verify_hmac(hmac_key, comando, sig)
#     logger.info(f"HMAC válido: {valid}") 