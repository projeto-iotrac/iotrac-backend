# main.py
# Servidor FastAPI para a Camada 3 da aplicação IOTRAC
# Gerenciamento de dispositivos IoT com proteção e logs
# Dependências: fastapi, uvicorn, pydantic, python-dotenv

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

# Importações locais
from db_setup import db_manager, DatabaseManager
from device_interceptor import send_udp, send_tcp
from crypto_utils import AESCipher, JWTAuth, generate_hmac, verify_hmac
from src.config import setup_logging

# Carrega variáveis de ambiente
load_dotenv()

# Logging centralizado
setup_logging()
logger = logging.getLogger(__name__)

# Configurações do servidor
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")

# Configurações de segurança
AES_KEY = os.getenv("AES_KEY")
HMAC_KEY = os.getenv("HMAC_KEY")

# Validação das chaves de segurança
if not AES_KEY or len(AES_KEY.encode()) < 32:
    raise RuntimeError("AES_KEY não definida ou menor que 32 bytes. Defina uma chave segura no .env.")
if not HMAC_KEY or len(HMAC_KEY.encode()) < 32:
    raise RuntimeError("HMAC_KEY não definida ou menor que 32 bytes. Defina uma chave segura no .env.")

# Inicialização do FastAPI
app = FastAPI(
    title="IOTRAC - Camada 3",
    description="API para gerenciamento de dispositivos IoT com proteção e logs",
    version="1.0.0"
)

# Inicialização dos componentes de segurança
try:
    aes_cipher = AESCipher(
        AES_KEY.encode()[:32].ljust(32, b'0'),
        HMAC_KEY.encode()[:32].ljust(32, b'0')
    )
    # JWTAuth não utilizado nesta versão. Futuramente será implementado para autenticação JWT.
    logger.info("Componentes de segurança inicializados com sucesso")
except Exception as e:
    logger.error(f"Erro ao inicializar componentes de segurança: {e}")
    aes_cipher = None

# Modelos Pydantic para validação de dados

class CommandRequest(BaseModel):
    """Modelo para requisição de comando."""
    device_id: int = Field(..., description="ID do dispositivo")
    command: str = Field(..., min_length=1, description="Comando a ser executado")
    
    @validator('command')
    def validate_command(cls, v):
        """Valida se o comando é permitido."""
        allowed_commands = [
            "move_up", "move_down", "move_left", "move_right", "move_forward", "move_backward",
            "turn_on", "turn_off", "set_speed", "get_status", "emergency_stop"
        ]
        if v not in allowed_commands:
            raise ValueError(f"Comando '{v}' não é permitido. Comandos válidos: {allowed_commands}")
        return v

class CommandResponse(BaseModel):
    """Modelo para resposta de comando."""
    success: bool
    message: str
    device_id: int
    command: str
    timestamp: str
    protection_enabled: bool

class ProtectionStatus(BaseModel):
    """Modelo para status de proteção."""
    protection_enabled: bool
    timestamp: str

class LogEntry(BaseModel):
    """Modelo para entrada de log."""
    id: int
    device_id: int
    device_type: str
    ip_address: str
    command: str
    timestamp: str
    status: str

class ToggleResponse(BaseModel):
    """Modelo para resposta de alternância de proteção."""
    protection_enabled: bool
    message: str
    timestamp: str

# Funções auxiliares

def get_db_manager() -> DatabaseManager:
    """Dependency injection para o gerenciador de banco."""
    return db_manager

def encrypt_command(command: str) -> Dict[str, str]:
    """
    Criptografa um comando usando AES e HMAC.
    
    Args:
        command (str): Comando a ser criptografado
        
    Returns:
        Dict[str, str]: Dados criptografados (iv, ciphertext, hmac)
    """
    if not aes_cipher:
        raise HTTPException(status_code=500, detail="Sistema de criptografia não disponível")
    
    try:
        command_bytes = command.encode('utf-8')
        iv, ciphertext, hmac_hex = aes_cipher.encrypt(command_bytes)
        return {
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "hmac": hmac_hex
        }
    except Exception as e:
        logger.error(f"Falha na criptografia do comando: {e}")
        raise HTTPException(status_code=500, detail=f"Falha na criptografia do comando: {e}")

def send_command_to_device(device: Dict[str, Any], command: str, protection_enabled: bool) -> str:
    """
    Envia comando para dispositivo usando o interceptor apropriado.
    
    Args:
        device (Dict[str, Any]): Dados do dispositivo
        command (str): Comando a ser enviado
        protection_enabled (bool): Se a proteção está ativa
        
    Returns:
        str: Status do envio ("success", "blocked", "error")
    """
    # Validação dos campos obrigatórios
    if not isinstance(device, dict) or "device_type" not in device or "ip_address" not in device:
        logger.error(f"Dados do dispositivo incompletos: {device}")
        raise ValueError("Dados do dispositivo incompletos")
    try:
        device_type = device["device_type"]
        ip_address = device["ip_address"]
        
        # Determina porta baseada no tipo de dispositivo
        if device_type == "drone":
            port = 5000  # Porta UDP para drones
            message = command
            if protection_enabled:
                encrypted_data = encrypt_command(command)
                message = json.dumps(encrypted_data)
            
            send_udp(ip_address, port, message)
            logger.info(f"Comando enviado para drone {ip_address}: {command}")
            return "success"
            
        elif device_type == "veículo":
            port = 5001  # Porta TCP para veículos
            message = command
            if protection_enabled:
                encrypted_data = encrypt_command(command)
                message = json.dumps(encrypted_data)
            
            send_tcp(ip_address, port, message)
            logger.info(f"Comando enviado para veículo {ip_address}: {command}")
            return "success"
            
        else:
            # Para outros tipos de dispositivo, usa TCP por padrão
            port = 5002
            message = command
            if protection_enabled:
                encrypted_data = encrypt_command(command)
                message = json.dumps(encrypted_data)
            
            send_tcp(ip_address, port, message)
            logger.info(f"Comando enviado para {device_type} {ip_address}: {command}")
            return "success"
            
    except ValueError as ve:
        logger.error(f"Erro de validação ao enviar comando: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Erro ao enviar comando para dispositivo {device.get('id')}: {e}")
        raise HTTPException(status_code=503, detail=f"Falha ao enviar comando para o dispositivo: {e}")

# Endpoints da API

@app.get("/", response_model=Dict[str, str])
async def root():
    """
    Endpoint raiz - informações básicas da API.
    """
    return {
        "message": "IOTRAC - Camada 3 API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/status", response_model=ProtectionStatus)
async def get_protection_status(db: DatabaseManager = Depends(get_db_manager)):
    """
    Retorna o status atual da proteção.
    
    Returns:
        ProtectionStatus: Status da proteção e timestamp
    """
    try:
        protection_enabled = db.get_protection_status()
        return ProtectionStatus(
            protection_enabled=protection_enabled,
            timestamp=datetime.now().isoformat()
        )
    except Exception as e:
        logger.error(f"Erro ao obter status de proteção: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/toggle_protection", response_model=ToggleResponse)
async def toggle_protection(db: DatabaseManager = Depends(get_db_manager)):
    """
    Alterna o estado da proteção (ativa/desativa).
    
    Returns:
        ToggleResponse: Novo status da proteção
    """
    try:
        new_status = db.toggle_protection()
        status_text = "ativada" if new_status else "desativada"
        
        return ToggleResponse(
            protection_enabled=new_status,
            message=f"Proteção {status_text} com sucesso",
            timestamp=datetime.now().isoformat()
        )
    except Exception as e:
        logger.error(f"Erro ao alternar proteção: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs", response_model=List[LogEntry])
async def get_logs(
    limit: int = 100,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Retorna logs de comandos enviados aos dispositivos.
    
    Args:
        limit (int): Número máximo de logs a retornar (padrão: 100)
        
    Returns:
        List[LogEntry]: Lista de logs de comandos
    """
    try:
        if limit <= 0 or limit > 1000:
            raise HTTPException(status_code=400, detail=f"Limit inválido: {limit}. Deve estar entre 1 e 1000")
        
        logs = db.get_logs(limit)
        return [LogEntry(**log) for log in logs]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao obter logs: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/command", response_model=CommandResponse)
async def send_command(
    command_request: CommandRequest,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Recebe e processa comandos para dispositivos IoT.
    
    Args:
        command_request (CommandRequest): Dados do comando
        
    Returns:
        CommandResponse: Resultado do processamento do comando
    """
    try:
        device_id = command_request.device_id
        command = command_request.command
        
        # Verifica se o dispositivo existe
        device = db.get_device(device_id)
        if not device:
            # Registra tentativa de comando para dispositivo inexistente
            db.insert_log(device_id, command, "device_not_found")
            raise HTTPException(
                status_code=404,
                detail=f"Dispositivo com ID {device_id} não encontrado"
            )
        
        # Verifica status da proteção
        protection_enabled = db.get_protection_status()
        
        # Processa o comando
        if protection_enabled:
            # Comando com proteção ativa
            status = send_command_to_device(device, command, True)
            message = f"Comando '{command}' enviado para {device['device_type']} com proteção ativa"
        else:
            # Comando sem proteção
            status = send_command_to_device(device, command, False)
            message = f"Comando '{command}' enviado para {device['device_type']} sem proteção"
        
        # Registra o log
        db.insert_log(device_id, command, status)
        
        # Determina mensagem de resposta
        if status == "success":
            response_message = message
        elif status == "blocked":
            response_message = f"Comando '{command}' bloqueado pela proteção"
        else:
            response_message = f"Erro ao enviar comando '{command}'"
        
        return CommandResponse(
            success=status == "success",
            message=response_message,
            device_id=device_id,
            command=command,
            timestamp=datetime.now().isoformat(),
            protection_enabled=protection_enabled
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao processar comando: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/devices", response_model=List[Dict[str, Any]])
async def get_devices(db: DatabaseManager = Depends(get_db_manager)):
    """
    Retorna todos os dispositivos registrados.
    
    Returns:
        List[Dict[str, Any]]: Lista de dispositivos
    """
    try:
        return db.get_all_devices()
    except Exception as e:
        logger.error(f"Erro ao obter dispositivos: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/devices/{device_id}", response_model=Dict[str, Any])
async def get_device(
    device_id: int,
    db: DatabaseManager = Depends(get_db_manager)
):
    """
    Retorna dados de um dispositivo específico.
    
    Args:
        device_id (int): ID do dispositivo
        
    Returns:
        Dict[str, Any]: Dados do dispositivo
    """
    try:
        device = db.get_device(device_id)
        if not device:
            raise HTTPException(
                status_code=404,
                detail=f"Dispositivo com ID {device_id} não encontrado"
            )
        return device
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao obter dispositivo {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

# Middleware para logging de requisições
@app.middleware("http")
async def log_requests(request, call_next):
    """Middleware para logging de requisições HTTP."""
    start_time = datetime.now()
    response = await call_next(request)
    end_time = datetime.now()
    
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Tempo: {(end_time - start_time).total_seconds():.3f}s"
    )
    
    return response

# Tratamento de erros global
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handler global para exceções não tratadas."""
    logger.error(f"Erro não tratado: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Erro interno do servidor"}
    )

if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Iniciando servidor IOTRAC na porta {SERVER_PORT}")
    logger.info(f"Host: {SERVER_HOST}")
    logger.info("Endpoints disponíveis:")
    logger.info("  GET  /status - Status da proteção")
    logger.info("  POST /toggle_protection - Alternar proteção")
    logger.info("  GET  /logs - Logs de comandos")
    logger.info("  POST /command - Enviar comando")
    logger.info("  GET  /devices - Listar dispositivos")
    logger.info("  GET  /devices/{device_id} - Detalhes do dispositivo")
    
    uvicorn.run(
        "main:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=True,
        log_level="info",
        timeout_keep_alive=10
    )
