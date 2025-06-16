from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os

def encrypt_aes256(plaintext: str, key: str) -> bytes:
    """
    Criptografa um texto usando AES-256 em modo CBC.
    
    Args:
        plaintext (str): Texto a ser criptografado
        key (str): Chave de criptografia (será ajustada para 32 bytes)
    
    Returns:
        bytes: Texto criptografado (IV + ciphertext)
    """
    iv = os.urandom(16)
    key = key.ljust(32)[:32].encode()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padding_length = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + chr(padding_length) * padding_length
    ciphertext = encryptor.update(plaintext_padded.encode()) + encryptor.finalize()
    return iv + ciphertext

def verify_hmac(message: str, signature: bytes, key: str) -> bool:
    """
    Verifica a assinatura HMAC-SHA256 de uma mensagem.
    
    Args:
        message (str): Mensagem original
        signature (bytes): Assinatura HMAC a ser verificada
        key (str): Chave HMAC
    
    Returns:
        bool: True se a assinatura for válida, False caso contrário
    """
    h = hmac.HMAC(key.encode(), hashes.SHA256())
    h.update(message.encode())
    return h.finalize() == signature
