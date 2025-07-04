# main.py
# Servidor FastAPI para a Camada 3 da aplicação IOTRAC
# Gerenciamento de dispositivos IoT com proteção e logs
# Dependências: fastapi, uvicorn, pydantic, python-dotenv

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator, field_validator
from dotenv import load_dotenv
import hmac
import jwt

# Importações locais
from src.db_setup import db_manager, DatabaseManager
from src.device_interceptor import send_udp, send_tcp
from src.crypto_utils import AESCipher, JWTAuth, generate_hmac, verify_hmac
from src.config import setup_logging

# Carrega variáveis de ambiente
load_dotenv("config/.env")

# Logging centralizado
setup_logging()
logger = logging.getLogger(__name__)

# Configurações do servidor
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")

# Configurações de segurança
AES_KEY = os.getenv("AES_KEY")
HMAC_KEY = os.getenv("HMAC_KEY")
JWT_SECRET = os.getenv('JWT_SECRET', 'iotrac_secret_key')

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

# Configurar CORS para permitir conexões do frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, especifique os domínios permitidos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

    @field_validator('command')
    @staticmethod
    def validate_command(v, info):
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

class DeviceRegister(BaseModel):
    """Modelo para registro de dispositivo."""
    device_type: str = Field(..., description="Tipo do dispositivo")
    ip_address: str = Field(..., description="Endereço IP do dispositivo")

    @field_validator('device_type')
    @staticmethod
    def validate_device_type(v):
        allowed_types = ["drone", "veículo", "smart-lamp", "smart-lock", 
                        "security-camera", "smart-tv", "smart-thermostat"]
        if v not in allowed_types:
            raise ValueError(f"Tipo de dispositivo '{v}' não é permitido. Tipos válidos: {allowed_types}")
        return v

    @field_validator('ip_address')
    @staticmethod
    def validate_ip(v):
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, v):
            raise ValueError("Endereço IP inválido")
        return v

# Funções auxiliares

def get_db_manager():
    # Sempre retorna uma nova instância para garantir leitura atualizada
    return DatabaseManager()

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
    if not isinstance(device, dict) or "device_type" not in device or "ip_address" not in device:
        logger.error(f"Dados do dispositivo incompletos: {device}")
        raise ValueError("Dados do dispositivo incompletos")
    try:
        device_type = device["device_type"]
        ip_address = device["ip_address"]
        if device_type == "drone":
            port = 5000
            message = command
            if protection_enabled:
                encrypted_data = encrypt_command(command)
                message = json.dumps(encrypted_data)
            send_udp(ip_address, port, message)
            logger.info(f"Comando enviado para drone {ip_address}: {command}")
            return "success"
        elif device_type == "veículo":
            port = 5001
            message = command
            if protection_enabled:
                encrypted_data = encrypt_command(command)
                message = json.dumps(encrypted_data)
            send_tcp(ip_address, port, message)
            logger.info(f"Comando enviado para veículo {ip_address}: {command}")
            return "success"
        else:
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
        if str(ve) == "Dados do dispositivo incompletos":
            raise HTTPException(status_code=400, detail="Dados do dispositivo incompletos")
        raise HTTPException(status_code=400, detail=str(ve))
    except RuntimeError as re:
        logger.error(f"Erro ao enviar comando para dispositivo {device.get('id')}: {re}")
        raise HTTPException(status_code=503, detail=f"Falha ao enviar comando: {re}")
    except Exception as e:
        logger.error(f"Falha na criptografia do comando: {e}")
        if any(word in str(e).lower() for word in ["envio", "enviar"]):
            raise HTTPException(status_code=503, detail=f"Falha ao enviar comando: {e}")
        raise HTTPException(status_code=500, detail=f"Falha na criptografia do comando: {e}")

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
        if "readonly" in str(e):
            raise HTTPException(status_code=500, detail="Banco de dados em modo somente leitura")
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
async def send_command(command_request: CommandRequest, db: DatabaseManager = Depends(get_db_manager)):
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
        
        # Busca o dispositivo primeiro
        device = db.get_device(device_id)
        if not device:
            db.insert_log(device_id, command, "device_not_found")
            raise HTTPException(status_code=404, detail=f"Dispositivo com ID {device_id} não encontrado")
        
        # Verifica a proteção individual do dispositivo
        device_protection_enabled = device.get("protection_enabled", False)
        
        # Se proteção do dispositivo está ativa, verifica se comando está criptografado
        if device_protection_enabled:
            # Verifica se o comando parece estar criptografado (base64 ou hex)
            import base64
            import re
            
            # Padrão para detectar dados criptografados (hex ou base64)
            hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
            base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
            
            is_encrypted = False
            
            # Verifica se comando parece estar criptografado
            if len(command) > 32:  # Comandos criptografados são longos
                if hex_pattern.match(command) or base64_pattern.match(command):
                    try:
                        # Tenta descriptografar
                        if aes_cipher:
                            # Assume que é hex
                            try:
                                ciphertext = bytes.fromhex(command)
                                # Tenta descriptografar (pode falhar se não for realmente criptografado)
                                # Por enquanto, apenas verifica se parece criptografado
                                is_encrypted = True
                                logger.info("Comando parece estar criptografado")
                            except:
                                pass
                    except:
                        pass
            
            if not is_encrypted:
                logger.warning(f"Comando não criptografado quando proteção do dispositivo {device_id} ativa - BLOQUEANDO")
                # Insere log de comando bloqueado
                try:
                    db.insert_log(device_id, command, "blocked")
                except Exception as log_error:
                    logger.error(f"Erro ao inserir log de comando bloqueado: {log_error}")
                
                # BLOQUEIA o comando quando proteção do dispositivo está ativa
                raise HTTPException(
                    status_code=401, 
                    detail=f"Comando deve estar criptografado quando proteção do dispositivo {device_id} está ativa"
                )
        
        try:
            status = send_command_to_device(device, command, device_protection_enabled)
        except HTTPException as he:
            raise he
        except ValueError as ve:
            logger.error(f"Dados do dispositivo incompletos: {device}")
            if str(ve) == "Dados do dispositivo incompletos":
                raise HTTPException(status_code=400, detail="Dados do dispositivo incompletos")
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as e:
            logger.error(f"Falha na criptografia do comando: {e}")
            raise HTTPException(status_code=500, detail=f"Falha na criptografia do comando: {e}")
        
        try:
            db.insert_log(device_id, command, status)
        except ValueError as ve:
            logger.error(f"Status inválido: {status}")
            if str(ve) == "Dados do dispositivo incompletos":
                raise HTTPException(status_code=400, detail="Dados do dispositivo incompletos")
            if str(ve) == "Status inválido":
                raise HTTPException(status_code=400, detail="Dados do dispositivo incompletos")
        
        if status == "success":
            response_message = f"Comando '{command}' enviado para {device['device_type']} {'com proteção ativa' if device_protection_enabled else 'sem proteção'}"
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
            protection_enabled=device_protection_enabled
        )
    except HTTPException as he:
        if hasattr(he, 'detail') and str(he.detail) == "Status inválido":
            raise HTTPException(status_code=400, detail="Dados do dispositivo incompletos")
        raise he
    except ValueError as ve:
        if str(ve) == "Dados do dispositivo incompletos":
            raise HTTPException(status_code=400, detail="Dados do dispositivo incompletos")
        if str(ve) == "Status inválido":
            raise HTTPException(status_code=400, detail="Dados do dispositivo incompletos")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Erro ao processar comando: {e}")
        if "Falha ao enviar comando" in str(e):
            raise HTTPException(status_code=503, detail=f"Falha ao enviar comando: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/devices", response_model=List[Dict[str, Any]])
async def get_devices(db: DatabaseManager = Depends(get_db_manager), request: Request = None):
    """
    Retorna todos os dispositivos registrados.
    
    Returns:
        List[Dict[str, Any]]: Lista de dispositivos
    """
    try:
        # Verifica se algum dispositivo tem proteção ativa
        devices = db.get_all_devices()
        any_protected = any(device.get("protection_enabled", False) for device in devices)
        
        # Se algum dispositivo tem proteção ativa, verifica HMAC
        if any_protected and request:
            hmac_header = request.headers.get("X-HMAC")
            user_agent = request.headers.get("User-Agent", "")
            
            # Se não tem HMAC, permite acesso mas loga o evento
            if not hmac_header:
                logger.warning("Acesso a /devices sem HMAC quando algum dispositivo tem proteção ativa")
                # Permite acesso mas registra o evento
            else:
                # Verifica se HMAC é válido
                try:
                    # Gera HMAC esperado para a requisição
                    message = f"GET:/devices:{datetime.now().isoformat()}"
                    expected_hmac = generate_hmac(HMAC_KEY.encode(), message.encode())
                    
                    if not hmac.compare_digest(expected_hmac, hmac_header):
                        logger.warning("HMAC inválido detectado em /devices")
                        return JSONResponse(
                            status_code=401,
                            content={"detail": "Assinatura HMAC inválida"}
                        )
                    else:
                        logger.info("HMAC válido em /devices")
                except Exception as e:
                    logger.error(f"Erro ao verificar HMAC: {e}")
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Erro na verificação HMAC"}
                    )
        
        return devices
    except Exception as e:
        logger.error(f"Erro ao obter dispositivos: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/devices/{device_id}", response_model=Dict[str, Any])
async def get_device(device_id: int, db: DatabaseManager = Depends(get_db_manager)):
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
            raise HTTPException(status_code=404, detail=f"Dispositivo com ID {device_id} não encontrado")
        return device
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao obter dispositivo {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/device/register", response_model=Dict[str, Any])
async def register_device(device: DeviceRegister, db: DatabaseManager = Depends(get_db_manager)):
    """
    Registra um novo dispositivo.
    """
    try:
        logger.info(f"Tentando registrar dispositivo: {device.dict()}")
        
        # Verificar se o IP já está registrado
        existing_device = db.get_device_by_ip(device.ip_address)
        if existing_device:
            logger.warning(f"IP {device.ip_address} já está registrado")
            raise HTTPException(
                status_code=400, 
                detail=f"Dispositivo já registrado com este IP: {device.ip_address}"
            )
            
        device_data = {
            "device_type": device.device_type,
            "ip_address": device.ip_address,
            "registered_at": datetime.now().isoformat()
        }
        
        device_id = db.add_device(device_data)
        device_data["id"] = device_id
        logger.info(f"Dispositivo registrado com sucesso: {device_data}")
        return device_data
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro inesperado ao registrar dispositivo: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro inesperado ao registrar dispositivo: {str(e)}")

@app.delete("/devices/{device_id}", response_model=Dict[str, str])
async def delete_device(device_id: int, db: DatabaseManager = Depends(get_db_manager)):
    """
    Remove um dispositivo.
    
    Args:
        device_id (int): ID do dispositivo a ser removido
        
    Returns:
        Dict[str, str]: Mensagem de sucesso
    """
    try:
        logger.info(f"Tentando remover dispositivo {device_id}")
        
        # Verificar se o dispositivo existe
        device = db.get_device(device_id)
        if not device:
            logger.warning(f"Dispositivo {device_id} não encontrado")
            raise HTTPException(status_code=404, detail=f"Dispositivo {device_id} não encontrado")
            
        # Remover dispositivo
        db.delete_device(device_id)
        logger.info(f"Dispositivo {device_id} removido com sucesso")
        return {"message": f"Dispositivo {device_id} removido com sucesso"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao remover dispositivo {device_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao remover dispositivo: {str(e)}")

@app.get("/devices/{device_id}/protection", response_model=Dict[str, Any])
async def get_device_protection(device_id: int, db: DatabaseManager = Depends(get_db_manager)):
    """
    Retorna o status de proteção de um dispositivo específico.
    
    Args:
        device_id (int): ID do dispositivo
        
    Returns:
        Dict[str, Any]: Status de proteção do dispositivo
    """
    try:
        # Verificar se o dispositivo existe
        device = db.get_device(device_id)
        if not device:
            raise HTTPException(status_code=404, detail=f"Dispositivo {device_id} não encontrado")
            
        protection_enabled = db.get_device_protection_status(device_id)
        return {
            "device_id": device_id,
            "protection_enabled": protection_enabled,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao obter proteção do dispositivo {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/devices/{device_id}/protection/toggle", response_model=Dict[str, Any])
async def toggle_device_protection(device_id: int, db: DatabaseManager = Depends(get_db_manager)):
    """
    Alterna o status de proteção de um dispositivo específico.
    
    Args:
        device_id (int): ID do dispositivo
        
    Returns:
        Dict[str, Any]: Novo status de proteção do dispositivo
    """
    try:
        # Verificar se o dispositivo existe
        device = db.get_device(device_id)
        if not device:
            raise HTTPException(status_code=404, detail=f"Dispositivo {device_id} não encontrado")
            
        new_status = db.toggle_device_protection(device_id)
        status_text = "ativada" if new_status else "desativada"
        
        return {
            "device_id": device_id,
            "protection_enabled": new_status,
            "message": f"Proteção do dispositivo {device_id} {status_text} com sucesso",
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao alternar proteção do dispositivo {device_id}: {e}")
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
    logger.info("  POST /device/register - Registrar dispositivo")
    logger.info("  DELETE /devices/{device_id} - Remover dispositivo")
    logger.info("  GET  /devices/{device_id}/protection - Status de proteção do dispositivo")
    logger.info("  POST /devices/{device_id}/protection/toggle - Alternar proteção do dispositivo")
    
    uvicorn.run(
        "main:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=True,
        log_level="info",
        timeout_keep_alive=10
    )
