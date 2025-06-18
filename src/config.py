# config.py
# Configuração centralizada de logging para o projeto IOTRAC
# Uso: from config import setup_logging

import logging
from typing import Optional

def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None) -> None:
    """
    Inicializa o sistema de logging do Python para todo o projeto.
    Args:
        level (int): Nível de log (ex: logging.INFO)
        log_file (str, opcional): Caminho para arquivo de log
    """
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=handlers
    ) 