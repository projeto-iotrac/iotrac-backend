import socket
import re
import logging
from typing import Optional
from src.config import setup_logging

# Inicializa logging centralizado (caso não tenha sido feito)
setup_logging()
logger = logging.getLogger(__name__)

# Regex simples para IPv4
_IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

_DEFAULT_TIMEOUT = 5  # segundos


def _validate_ip(ip: str) -> bool:
    """Valida se o IP está no formato IPv4 básico e dentro do range."""
    if not isinstance(ip, str) or not _IPV4_REGEX.match(ip):
        return False
    partes = ip.split('.')
    return all(0 <= int(p) <= 255 for p in partes)


def _validate_port(port: int) -> bool:
    """Valida se a porta está no intervalo permitido."""
    return isinstance(port, int) and 0 < port <= 65535


def _validate_message(message: str) -> bool:
    """Valida se a mensagem não é vazia."""
    return isinstance(message, str) and len(message.strip()) > 0


def send_udp(ip: str, port: int, message: str, timeout: Optional[float] = None) -> None:
    """
    Envia uma mensagem UDP para o IP e porta especificados.

    Args:
        ip (str): Endereço IPv4 de destino.
        port (int): Porta de destino (1-65535).
        message (str): Mensagem a ser enviada (não pode ser vazia).
        timeout (float, opcional): Timeout em segundos (padrão: 5).

    Raises:
        ValueError: Se algum parâmetro for inválido.
        RuntimeError: Se ocorrer erro de socket.
    """
    if not _validate_ip(ip):
        logger.error(f"IP inválido: {ip}")
        raise ValueError(f"Endereço IP inválido: {ip}")
    if not _validate_port(port):
        logger.error(f"Porta inválida: {port}")
        raise ValueError(f"Porta inválida: {port}")
    if not _validate_message(message):
        logger.error("Mensagem vazia não permitida")
        raise ValueError("Mensagem não pode ser vazia")
    if timeout is None:
        timeout = _DEFAULT_TIMEOUT

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(message.encode(), (ip, port))
            logger.info(f"Mensagem UDP enviada para {ip}:{port}: {message}")
    except socket.gaierror as e:
        logger.error(f"Erro de resolução de IP: {ip} - {e}")
        raise RuntimeError(f"Erro de resolução de IP: {ip}") from e
    except socket.timeout as e:
        logger.error(f"Timeout ao enviar UDP para {ip}:{port}")
        raise RuntimeError(f"Timeout ao enviar UDP para {ip}:{port}") from e
    except Exception as e:
        logger.error(f"Erro ao enviar UDP para {ip}:{port}: {e}")
        raise RuntimeError(f"Erro ao enviar UDP para {ip}:{port}: {e}") from e


def send_tcp(ip: str, port: int, message: str, timeout: Optional[float] = None) -> None:
    """
    Envia uma mensagem TCP para o IP e porta especificados.

    Args:
        ip (str): Endereço IPv4 de destino.
        port (int): Porta de destino (1-65535).
        message (str): Mensagem a ser enviada (não pode ser vazia).
        timeout (float, opcional): Timeout em segundos (padrão: 5).

    Raises:
        ValueError: Se algum parâmetro for inválido.
        RuntimeError: Se ocorrer erro de conexão ou envio.
    """
    if not _validate_ip(ip):
        logger.error(f"IP inválido: {ip}")
        raise ValueError(f"Endereço IP inválido: {ip}")
    if not _validate_port(port):
        logger.error(f"Porta inválida: {port}")
        raise ValueError(f"Porta inválida: {port}")
    if not _validate_message(message):
        logger.error("Mensagem vazia não permitida")
        raise ValueError("Mensagem não pode ser vazia")
    if timeout is None:
        timeout = _DEFAULT_TIMEOUT

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(message.encode())
            logger.info(f"Mensagem TCP enviada para {ip}:{port}: {message}")
    except socket.gaierror as e:
        logger.error(f"Erro de resolução de IP: {ip} - {e}")
        raise RuntimeError(f"Erro de resolução de IP: {ip}") from e
    except ConnectionRefusedError as e:
        logger.error(f"Conexão recusada por {ip}:{port}")
        raise RuntimeError(f"Conexão recusada por {ip}:{port}") from e
    except socket.timeout as e:
        logger.error(f"Timeout ao conectar/enviar para {ip}:{port}")
        raise RuntimeError(f"Timeout ao conectar/enviar para {ip}:{port}") from e
    except Exception as e:
        logger.error(f"Erro ao enviar TCP para {ip}:{port}: {e}")
        raise RuntimeError(f"Erro ao enviar TCP para {ip}:{port}: {e}") from e