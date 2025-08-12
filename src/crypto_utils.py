# crypto_utils.py
# Funções de criptografia e segurança para aplicações IoT
# Dependências: cryptography>=3.4.7, python-jose[cryptography]>=3.3.0, python-dotenv>=0.19.0, boto3 (opcional para AWS)
# Variáveis de ambiente necessárias: AES_KEY, HMAC_KEY, JWT_SECRET

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, padding
from cryptography.hazmat.backends import default_backend
import os
import logging
import hmac  # Importação do módulo hmac built-in para compare_digest
from datetime import datetime, timedelta, timezone  # Adicionar timezone
from typing import Tuple, Optional, Dict, Any
from cryptography.exceptions import InvalidSignature
from dotenv import load_dotenv
import uuid

# Suporte opcional a AWS Secrets Manager
try:
    import boto3
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

from jose import jwt, ExpiredSignatureError, JWTError
from src.config import setup_logging

# Carregar variáveis de ambiente
from pathlib import Path

# Obter o diretório do arquivo atual e carregar .env
current_dir = Path(__file__).parent
config_path = current_dir.parent / "config" / ".env"
load_dotenv(str(config_path))

# Cachear backend
BACKEND = default_backend()

# Inicializar logging automaticamente
setup_logging()
logger = logging.getLogger(__name__)

# LoggerAdapter para contexto
class ContextLogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        ctx = self.extra.copy()
        ctx_str = ' '.join(f'{k}={v}' for k, v in ctx.items())
        return f'[{ctx_str}] {msg}', kwargs

# =========================
# Utilitários para segredos
# =========================
def get_env_var(name: str, use_aws_secrets: bool = False) -> str:
    """
    Obtém uma variável de ambiente ou segredo do AWS Secrets Manager.
    """
    if use_aws_secrets and AWS_AVAILABLE:
        client = boto3.client('secretsmanager')
        try:
            response = client.get_secret_value(SecretId=name)
            return response['SecretString']
        except Exception as e:
            logger.error(f"Erro ao obter segredo {name} do AWS Secrets Manager: {e}")
            raise EnvironmentError(f"Erro ao obter segredo {name}")
    value = os.getenv(name)
    if not value:
        logger.error(f"Variável de ambiente '{name}' não definida")
        raise EnvironmentError(f"Variável de ambiente '{name}' não definida")
    return value

def generate_hmac_key(length: int = 32) -> bytes:
    """
    Gera uma chave HMAC aleatória de tamanho especificado.
    """
    if length < 16:
        logger.error("Chave HMAC deve ter pelo menos 16 bytes")
        raise ValueError("Chave HMAC deve ter pelo menos 16 bytes")
    key = os.urandom(length)
    logger.info(f"Chave HMAC gerada com {length} bytes")
    return key

# =========================
# Classe para validação de chaves
# =========================
class KeyValidator:
    @staticmethod
    def validate_aes_key(key: bytes) -> None:
        if len(key) != 32:
            logger.error("Chave AES deve ter 32 bytes")
            raise ValueError("Chave AES deve ter 32 bytes")

    @staticmethod
    def validate_hmac_key(key: bytes) -> None:
        if len(key) < 16:
            logger.error("Chave HMAC deve ter pelo menos 16 bytes")
            raise ValueError("Chave HMAC deve ter pelo menos 16 bytes")

# =========================
# Classe para criptografia AES-256-CBC
# =========================
class AESCipher:
    """
    Classe para criptografia e descriptografia AES-256-CBC com autenticação HMAC-SHA256.
    Inclui rastreamento de criação da chave HMAC para rotação manual.
    """
    def __init__(self, key: bytes, hmac_key: Optional[bytes] = None, hmac_key_length: int = 32):
        KeyValidator.validate_aes_key(key)
        if hmac_key is None:
            hmac_key = generate_hmac_key(hmac_key_length)
        KeyValidator.validate_hmac_key(hmac_key)
        self.key = key
        self.hmac_key = hmac_key
        self.created_at = datetime.now(timezone.utc)  # Corrigido: usar timezone.utc
        self._backend = BACKEND
        # Template para Cipher (modo CBC exige IV por operação)
        self._cipher_template = lambda iv: Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self._backend)
        # Logger contextualizado
        self.logger = ContextLogger(logger, {'operation_id': str(uuid.uuid4())})

    def _check_hmac_rotation(self):
        age = (datetime.now(timezone.utc) - self.created_at).days  # Corrigido: usar timezone.utc
        if age > 90:
            self.logger.warning(f"Chave HMAC tem {age} dias. Recomenda-se rotação a cada 90 dias.")

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes, str]:
        self._check_hmac_rotation()
        if not plaintext:
            self.logger.error("Plaintext não pode ser vazio")
            raise ValueError("Plaintext não pode ser vazio")
        try:
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()
            cipher = self._cipher_template(iv)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded) + encryptor.finalize()
            mac = self._generate_mac(iv, ciphertext)
            self.logger.info("Criptografia realizada com sucesso")
            return iv, ciphertext, mac
        except Exception as e:
            self.logger.error(f"Erro ao criptografar: {e}")
            raise

    def decrypt(self, iv: bytes, ciphertext: bytes, mac_hex: str) -> bytes:
        self._check_hmac_rotation()
        if len(iv) != 16:
            self.logger.error("IV deve ter 16 bytes")
            raise ValueError("IV deve ter 16 bytes")
        if len(ciphertext) % 16 != 0:
            self.logger.error("Ciphertext deve ser múltiplo de 16 bytes")
            raise ValueError("Ciphertext inválido")
        expected_mac = self._generate_mac(iv, ciphertext)
        # Corrigido: comparar ambos como hex string
        if not hmac.compare_digest(expected_mac, mac_hex):
            self.logger.error("HMAC inválido")
            raise InvalidSignature("HMAC inválido")
        try:
            cipher = self._cipher_template(iv)
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            self.logger.info("Descriptografia realizada com sucesso")
            return plaintext
        except Exception as e:
            self.logger.error(f"Erro ao descriptografar: {e}")
            raise

    def _generate_mac(self, iv: bytes, ciphertext: bytes) -> str:
        h = crypto_hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=self._backend)
        h.update(iv + ciphertext)
        return h.finalize().hex()

# =========================
# Classe para autenticação JWT
# =========================
class JWTAuth:
    """
    Classe para geração e verificação de tokens JWT.
    """
    def __init__(self, secret_env: str = 'JWT_SECRET', use_aws_secrets: bool = False):
        self.secret = get_env_var(secret_env, use_aws_secrets)
        self.algorithm = 'HS256'
        self.logger = ContextLogger(logger, {'operation_id': str(uuid.uuid4())})

    def generate_token(self, payload: Dict[str, Any], expires_minutes: int = 60) -> str:
        payload_copy = payload.copy()
        payload_copy['exp'] = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)  # Corrigido: usar timezone.utc
        try:
            token = jwt.encode(payload_copy, self.secret, algorithm=self.algorithm)
            self.logger.info("Token JWT gerado com sucesso")
            return token
        except Exception as e:
            self.logger.error(f"Erro ao gerar token: {e}")
            raise

    def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, self.secret, algorithms=[self.algorithm])
            self.logger.info("Token JWT verificado com sucesso")
            return payload
        except (ExpiredSignatureError, JWTError) as e:
            self.logger.error(f"Token JWT inválido ou expirado: {e}")
            raise

# =========================
# Funções HMAC
# =========================
def generate_hmac(key: bytes, message: bytes) -> str:
    KeyValidator.validate_hmac_key(key)
    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=BACKEND)
    h.update(message)
    return h.finalize().hex()

def verify_hmac(key: bytes, message: bytes, signature_hex: str) -> bool:
    KeyValidator.validate_hmac_key(key)
    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=BACKEND)
    h.update(message)
    expected = h.finalize().hex()
    # Corrigido: comparar ambos como hex string
    return hmac.compare_digest(expected, signature_hex)

# =========================
# Docstrings e instruções
# =========================
"""
Módulo de utilitários de segurança para IoT:
- Criptografia AES-256-CBC com HMAC-SHA256 (Encrypt-then-MAC)
- Geração e verificação de tokens JWT
- Geração e verificação de HMAC-SHA256

Dependências: cryptography>=3.4.7, python-jose[cryptography]>=3.3.0, python-dotenv>=0.19.0, boto3 (opcional)
Variáveis de ambiente: AES_KEY, HMAC_KEY, JWT_SECRET

Como gerar chaves seguras:
- AES_KEY: python -c "import os; print(os.urandom(32).hex())"
- HMAC_KEY: python -c "import os; print(os.urandom(32).hex())"
- JWT_SECRET: Gere uma string aleatória forte (>= 32 caracteres)

Para usar AWS Secrets Manager:
- Crie os segredos no AWS Console com os nomes desejados
- Use use_aws_secrets=True nas funções/classes

Exemplo de uso seguro:
from crypto_utils import AESCipher, JWTAuth, generate_hmac, verify_hmac

# Criptografia
cipher = AESCipher(aes_key, hmac_key)
iv, ct, mac = cipher.encrypt(b'dados')
plaintext = cipher.decrypt(iv, ct, mac)

# JWT
jwt_auth = JWTAuth()
token = jwt_auth.generate_token({'user': 'iot'})
claims = jwt_auth.verify_token(token)

# HMAC
sig = generate_hmac(hmac_key, b'dados')
"""
