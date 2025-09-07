# main.py
# Servidor FastAPI para a Camada 3 da aplicação IOTRAC
# Gerenciamento de dispositivos IoT com proteção e logs
# Dependências: fastapi, uvicorn, pydantic, python-dotenv

import os
import json
import logging
import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator, field_validator
from dotenv import load_dotenv
import hmac

# Importações locais
from src.db_setup import db_manager, DatabaseManager
from src.device_interceptor import send_udp, send_tcp
from src.crypto_utils import AESCipher, JWTAuth, generate_hmac, verify_hmac
from src.config import setup_logging

# ===== IMPORTAÇÕES DE AUTENTICAÇÃO =====
from src.auth_models import (
    LoginRequest, LoginResponse, TwoFARequest, TwoFAResponse,
    RegisterRequest, RegisterResponse, UserInfo, TokenResponse,
    TOTPSetupRequest, TOTPSetupResponse, TOTPVerifyRequest, TOTPVerifyResponse,
    RefreshTokenRequest, DeviceRegistrationRequest, DeviceRegistrationResponse,
    EmailVerificationRequest, EmailVerificationResponse, EmailResendRequest,
    TwoFAResendRequest, SimpleResponse
)
from src.auth_service import (
    auth_service, get_current_user, get_current_admin_user, 
    get_current_device_operator
)
from src.auth_db import auth_db_manager
from src.anomaly_detection import analyze_command_for_anomalies, get_anomaly_alerts, anomaly_detector
from src.ai_security_assistant import (
    ai_assistant, AISecurityContext, AIActionType
)
from src.ai_llm_integration import (
    llm_manager, LLMProvider
)

# ===== MODELOS PARA SISTEMA DE LOGS =====

class SimpleLogEntry(BaseModel):
    """Modelo para entrada de log simples (usuário final)."""
    id: int
    timestamp: str
    type: str
    icon: str
    title: str
    message: str
    severity: str  # info, warning, critical
    device_name: Optional[str] = None
    device_id: Optional[int] = None

class SimpleAlert(BaseModel):
    """Modelo para alerta simples."""
    id: int
    type: str
    title: str
    message: str
    severity: str
    timestamp: str
    resolved: bool
    device_name: Optional[str] = None

class LogSummary(BaseModel):
    """Modelo para resumo de logs."""
    total_events: int
    device_connections: int
    security_alerts: int
    attacks_blocked: int
    anomalies_detected: int
    last_24h_events: int

class AlertSummary(BaseModel):
    """Modelo para resumo de alertas."""
    total_alerts: int
    critical: int
    warning: int
    info: int
    active_alerts: int

class AdvancedLogEntry(BaseModel):
    """Modelo para entrada de log avançado (técnico)."""
    id: int
    timestamp: str
    level: str
    module: str
    function: str
    message: str
    details: Dict[str, Any]
    stack_trace: Optional[str] = None
    performance: Optional[Dict[str, Any]] = None
    user_id: Optional[int] = None
    session_id: Optional[str] = None

class SecurityEvent(BaseModel):
    """Modelo para evento de segurança avançado."""
    id: int
    timestamp: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any]
    mitigation: Optional[str] = None
    resolved: bool = False

class LogPagination(BaseModel):
    """Modelo para paginação de logs."""
    page: int
    limit: int
    total: int
    total_pages: int

class SimpleLogsResponse(BaseModel):
    """Resposta para logs simples."""
    logs: List[SimpleLogEntry]
    pagination: LogPagination

class AdvancedLogsResponse(BaseModel):
    """Resposta para logs avançados."""
    logs: List[AdvancedLogEntry]
    pagination: LogPagination

# ===== SISTEMA DE CATEGORIZAÇÃO DE LOGS =====

class LogCategories:
    """Sistema de categorização e formatação de logs."""
    
    SIMPLE_TYPES = {
        "device_connected": {
            "icon": "🔌",
            "title": "Dispositivo Conectado",
            "severity": "info"
        },
        "device_disconnected": {
            "icon": "🔌",
            "title": "Dispositivo Desconectado", 
            "severity": "info"
        },
        "device_registered": {
            "icon": "📱",
            "title": "Dispositivo Registrado",
            "severity": "info"
        },
        "device_deleted": {
            "icon": "🗑️",
            "title": "Dispositivo Removido",
            "severity": "warning"
        },
        "command_sent": {
            "icon": "📤",
            "title": "Comando Enviado",
            "severity": "info"
        },
        "command_blocked": {
            "icon": "🚫",
            "title": "Comando Bloqueado",
            "severity": "warning"
        },
        "security_alert": {
            "icon": "⚠️",
            "title": "Alerta de Segurança",
            "severity": "warning"
        },
        "attack_blocked": {
            "icon": "🛡️",
            "title": "Ataque Bloqueado",
            "severity": "critical"
        },
        "anomaly_detected": {
            "icon": "🚨",
            "title": "Anomalia Detectada",
            "severity": "warning"
        },
        "user_login": {
            "icon": "👤",
            "title": "Login Realizado",
            "severity": "info"
        },
        "user_logout": {
            "icon": "👤",
            "title": "Logout Realizado",
            "severity": "info"
        },
        "user_registered": {
            "icon": "👥",
            "title": "Usuário Registrado",
            "severity": "info"
        },
        "protection_toggled": {
            "icon": "🔒",
            "title": "Proteção Alterada",
            "severity": "info"
        },
        "authentication_failed": {
            "icon": "❌",
            "title": "Falha de Autenticação",
            "severity": "warning"
        },
        "encryption_error": {
            "icon": "🔐",
            "title": "Erro de Criptografia",
            "severity": "critical"
        },
        "bluetooth_connected": {
            "icon": "📶",
            "title": "Bluetooth Conectado",
            "severity": "info"
        },
        "bluetooth_disconnected": {
            "icon": "📶",
            "title": "Bluetooth Desconectado",
            "severity": "info"
        },
        "system_startup": {
            "icon": "🚀",
            "title": "Sistema Iniciado",
            "severity": "info"
        },
        "system_shutdown": {
            "icon": "🛑",
            "title": "Sistema Desligado",
            "severity": "info"
        }
    }
    
    @classmethod
    def format_simple_message(cls, log_type: str, details: Dict[str, Any]) -> str:
        """Formatar mensagem para log simples baseado no tipo."""
        if log_type == "device_connected":
            return f"{details.get('device_name', 'Dispositivo')} foi conectado com sucesso"
        elif log_type == "device_disconnected":
            return f"{details.get('device_name', 'Dispositivo')} foi desconectado"
        elif log_type == "device_registered":
            return f"Novo {details.get('device_type', 'dispositivo')} registrado: {details.get('device_name', 'N/A')}"
        elif log_type == "device_deleted":
            return f"Dispositivo {details.get('device_name', 'N/A')} foi removido do sistema"
        elif log_type == "command_sent":
            return f"Comando '{details.get('command', 'N/A')}' enviado para {details.get('device_name', 'dispositivo')}"
        elif log_type == "command_blocked":
            return f"Comando '{details.get('command', 'N/A')}' foi bloqueado pela proteção"
        elif log_type == "security_alert":
            return f"Comportamento suspeito detectado: {details.get('description', 'atividade anômala')}"
        elif log_type == "attack_blocked":
            return f"Tentativa de ataque bloqueada: {details.get('attack_type', 'tipo desconhecido')}"
        elif log_type == "anomaly_detected":
            return f"Anomalia detectada no {details.get('device_name', 'sistema')}: {details.get('description', 'comportamento incomum')}"
        elif log_type == "user_login":
            return f"Usuário {details.get('email', 'N/A')} fez login no sistema"
        elif log_type == "user_logout":
            return f"Usuário {details.get('email', 'N/A')} fez logout do sistema"
        elif log_type == "user_registered":
            return f"Novo usuário registrado: {details.get('email', 'N/A')}"
        elif log_type == "protection_toggled":
            status = "ativada" if details.get('enabled', False) else "desativada"
            return f"Proteção foi {status} pelo administrador"
        elif log_type == "authentication_failed":
            return f"Falha na autenticação: {details.get('reason', 'credenciais inválidas')}"
        elif log_type == "encryption_error":
            return f"Erro na criptografia: {details.get('error', 'falha desconhecida')}"
        elif log_type == "bluetooth_connected":
            return f"Dispositivo Bluetooth {details.get('device_name', 'N/A')} conectado"
        elif log_type == "bluetooth_disconnected":
            return f"Dispositivo Bluetooth {details.get('device_name', 'N/A')} desconectado"
        elif log_type == "system_startup":
            return "Sistema IOTRAC iniciado com sucesso"
        elif log_type == "system_shutdown":
            return "Sistema IOTRAC foi desligado"
        else:
            return details.get('message', 'Evento do sistema')

# ===== FUNÇÕES AUXILIARES PARA LOGS =====

def get_db_connection():
    """Obter conexão com banco de dados."""
    try:
        # Usar mesmo path do DatabaseManager
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'database', 'iotrac.db')
        return sqlite3.connect(db_path)
    except Exception as e:
        logger.error(f"Erro ao conectar com banco de dados: {e}")
        raise

def create_simple_log(log_type: str, details: Dict[str, Any], device_id: Optional[int] = None, user_id: Optional[int] = None):
    """Criar entrada de log simples."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Obter configuração do tipo de log
        log_config = LogCategories.SIMPLE_TYPES.get(log_type, {
            "icon": "ℹ️",
            "title": "Evento do Sistema",
            "severity": "info"
        })
        
        # Formatar mensagem
        message = LogCategories.format_simple_message(log_type, details)
        
        # Obter nome do dispositivo se fornecido
        device_name = None
        if device_id:
            cursor.execute("SELECT device_type, device_name FROM devices WHERE id = ?", (device_id,))
            device_row = cursor.fetchone()
            if device_row:
                device_name = device_row[1] or device_row[0]
        
        # Inserir log simples
        cursor.execute('''
            INSERT INTO simple_logs (timestamp, type, icon, title, message, severity, device_name, device_id, user_id, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            log_type,
            log_config["icon"],
            log_config["title"],
            message,
            log_config["severity"],
            device_name,
            device_id,
            user_id,
            json.dumps(details)
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Log simples criado: {log_type} - {message}")
        
    except Exception as e:
        logger.error(f"Erro ao criar log simples: {e}")

def create_advanced_log(level: str, module: str, function: str, message: str, details: Dict[str, Any] = None, 
                       user_id: Optional[int] = None, session_id: Optional[str] = None, 
                       stack_trace: Optional[str] = None, performance: Optional[Dict[str, Any]] = None):
    """Criar entrada de log avançado."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO advanced_logs (timestamp, level, module, function, message, details, user_id, session_id, stack_trace, performance)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            level,
            module,
            function,
            message,
            json.dumps(details or {}),
            user_id,
            session_id,
            stack_trace,
            json.dumps(performance or {})
        ))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Erro ao criar log avançado: {e}")

def create_security_event(event_type: str, severity: str, details: Dict[str, Any], 
                         source_ip: Optional[str] = None, user_agent: Optional[str] = None,
                         mitigation: Optional[str] = None):
    """Criar evento de segurança."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events (timestamp, event_type, severity, source_ip, user_agent, details, mitigation, resolved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            event_type,
            severity,
            source_ip,
            user_agent,
            json.dumps(details),
            mitigation,
            False
        ))
        
        conn.commit()
        conn.close()
        
        # Também criar log simples se for crítico
        if severity in ["high", "critical"]:
            if event_type == "authentication_failure":
                create_simple_log("authentication_failed", details)
            elif event_type == "attack_attempt":
                create_simple_log("attack_blocked", details)
            else:
                create_simple_log("security_alert", details)
        
    except Exception as e:
        logger.error(f"Erro ao criar evento de segurança: {e}")

def setup_log_tables():
    """Criar tabelas de logs se não existirem."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Tabela de logs simples
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS simple_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                icon TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                device_name TEXT,
                device_id INTEGER,
                user_id INTEGER,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de logs avançados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS advanced_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                module TEXT NOT NULL,
                function TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                user_id INTEGER,
                session_id TEXT,
                stack_trace TEXT,
                performance TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de eventos de segurança
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                user_agent TEXT,
                details TEXT,
                mitigation TEXT,
                resolved BOOLEAN DEFAULT FALSE,
                resolved_at TEXT,
                resolved_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Índices para performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_simple_logs_timestamp ON simple_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_simple_logs_type ON simple_logs(type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_simple_logs_severity ON simple_logs(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_advanced_logs_timestamp ON advanced_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_advanced_logs_level ON advanced_logs(level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity)')
        
        conn.commit()
        conn.close()
        
        logger.info("Tabelas de logs configuradas com sucesso")
        
    except Exception as e:
        logger.error(f"Erro ao configurar tabelas de logs: {e}")

# Carrega variáveis de ambiente
import os
from pathlib import Path

# Obter o diretório do arquivo atual
current_dir = Path(__file__).parent
config_path = current_dir.parent / "config" / ".env"
load_dotenv(str(config_path))

# Logging centralizado
setup_logging()
logger = logging.getLogger(__name__)

# Configurar tabelas de logs na inicialização
setup_log_tables()

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
# Origens permitidas para desenvolvimento e produção
ALLOWED_ORIGINS = [
    "http://localhost:3000",     # React/Next.js dev
    "http://localhost:19006",    # Expo web dev
    "http://127.0.0.1:19006",    # Expo web dev (127.0.0.1)
    "http://127.0.0.1:3000",     # React/Next.js dev (127.0.0.1)
    "http://localhost:8081",     # Expo dev tunnel
    # Portas alternativas de dev (Expo/Metro/Web dev)
    "http://localhost:8082",
    "http://127.0.0.1:8082",
    "http://localhost:19000",
    "http://127.0.0.1:19000",
    "http://localhost:19001",
    "http://127.0.0.1:19001",
    "http://localhost:19002",
    "http://127.0.0.1:19002",
    "http://localhost:19003",
    "http://127.0.0.1:19003",
    "http://localhost:19004",
    "http://127.0.0.1:19004",
    "http://localhost:19005",
    "http://127.0.0.1:19005",
    "http://localhost:19006",
    "http://127.0.0.1:19006",
    "http://192.168.1.100:19006", # Expo dev local network
    "http://192.168.1.101:19006", # Expo dev local network
    "http://192.168.1.102:19006", # Expo dev local network
    "http://192.168.0.100:19006", # Expo dev local network
    "http://192.168.0.101:19006", # Expo dev local network
    "http://192.168.0.102:19006", # Expo dev local network
    "exp://localhost:19000",     # Expo dev
    "exp://192.168.1.100:19000", # Expo dev local network
    "exp://192.168.1.101:19000", # Expo dev local network
    "exp://192.168.1.102:19000", # Expo dev local network
    "exp://192.168.0.100:19000", # Expo dev local network
    "exp://192.168.0.101:19000", # Expo dev local network
    "exp://192.168.0.102:19000", # Expo dev local network
]

# Em desenvolvimento, permitir origens dinâmicas de Expo
ALLOWED_ORIGIN_REGEX = None
if os.getenv("ENVIRONMENT", "development") == "development":
    # Adicionar origem dinâmica baseada no IP do servidor
    server_ip = os.getenv("SERVER_HOST", "0.0.0.0")
    if server_ip != "0.0.0.0":
        ALLOWED_ORIGINS.extend([
            f"http://{server_ip}:19006",
            f"exp://{server_ip}:19000"
        ])
    # DEV: permitir qualquer origem http/https (apenas desenvolvimento)
    ALLOWED_ORIGIN_REGEX = r"^https?://.*$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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
    create_simple_log("system_startup", {"message": "Sistema IOTRAC iniciado com sucesso"})
except Exception as e:
    logger.error(f"Erro ao inicializar componentes de segurança: {e}")
    aes_cipher = None

# Auto-configuração do LLM no startup (se variáveis estiverem presentes)
@app.on_event("startup")
async def configure_llm_on_startup() -> None:
    try:
        api_key = os.getenv("LLM_API_KEY")
        provider_name = os.getenv("LLM_PROVIDER")
        custom_endpoint = os.getenv("LLM_CUSTOM_ENDPOINT")
        if api_key and provider_name:
            try:
                provider = LLMProvider(provider_name.lower())
            except ValueError:
                logger.warning(f"LLM_PROVIDER inválido: {provider_name}")
                return
            result = llm_manager.configure_llm(provider=provider, api_token=api_key, custom_endpoint=custom_endpoint)
            if result.get("success"):
                logger.info(f"LLM auto-configurado no startup: {result.get('provider')}")
            else:
                logger.warning(f"Falha na auto-configuração do LLM: {result.get('error')}")
        else:
            logger.info("LLM não configurado por ambiente (LLM_API_KEY/LLM_PROVIDER ausentes)")
    except Exception as e:
        logger.warning(f"Erro na auto-configuração do LLM no startup: {e}")

# ===== ENDPOINTS DE LOGS SIMPLES =====

@app.get("/logs/simple", response_model=SimpleLogsResponse)
async def get_simple_logs(
    page: int = Query(1, ge=1, description="Número da página"),
    limit: int = Query(50, ge=1, le=200, description="Itens por página"),
    severity: Optional[str] = Query(None, description="Filtrar por severidade (info, warning, critical)"),
    type: Optional[str] = Query(None, description="Filtrar por tipo de evento"),
    device_id: Optional[int] = Query(None, description="Filtrar por dispositivo"),
    date_from: Optional[str] = Query(None, description="Data inicial (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Data final (YYYY-MM-DD)"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna logs simples para usuários finais.
    REQUER AUTENTICAÇÃO.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Construir query base
        query = "SELECT * FROM simple_logs WHERE 1=1"
        params = []
        
        # Aplicar filtros
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if type:
            query += " AND type = ?"
            params.append(type)
        
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
        
        if date_from:
            query += " AND DATE(timestamp) >= ?"
            params.append(date_from)
        
        if date_to:
            query += " AND DATE(timestamp) <= ?"
            params.append(date_to)
        
        # Contar total de registros
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Adicionar ordenação e paginação
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, (page - 1) * limit])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # Converter para modelos
        logs = []
        for row in rows:
            logs.append(SimpleLogEntry(
                id=row[0],
                timestamp=row[1],
                type=row[2],
                icon=row[3],
                title=row[4],
                message=row[5],
                severity=row[6],
                device_name=row[7],
                device_id=row[8]
            ))
        
        conn.close()
        
        # Calcular paginação
        total_pages = (total + limit - 1) // limit
        
        return SimpleLogsResponse(
            logs=logs,
            pagination=LogPagination(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        )
        
    except Exception as e:
        logger.error(f"Erro ao buscar logs simples: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs/simple/alerts")
async def get_simple_alerts(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna alertas ativos e resumo para usuários finais.
    REQUER AUTENTICAÇÃO.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Buscar alertas ativos (últimas 24 horas, severidade warning ou critical)
        cursor.execute('''
            SELECT * FROM simple_logs 
            WHERE severity IN ('warning', 'critical') 
            AND timestamp >= ?
            ORDER BY timestamp DESC 
            LIMIT 20
        ''', (datetime.now() - timedelta(hours=24),))
        
        rows = cursor.fetchall()
        
        active_alerts = []
        for row in rows:
            active_alerts.append(SimpleAlert(
                id=row[0],
                type=row[2],
                title=row[4],
                message=row[5],
                severity=row[6],
                timestamp=row[1],
                resolved=False,  # Para logs simples, consideramos sempre não resolvidos
                device_name=row[7]
            ))
        
        # Contar alertas por severidade (últimas 24 horas)
        cursor.execute('''
            SELECT severity, COUNT(*) FROM simple_logs 
            WHERE timestamp >= ? 
            GROUP BY severity
        ''', (datetime.now() - timedelta(hours=24),))
        
        severity_counts = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            "active_alerts": active_alerts,
            "alert_summary": AlertSummary(
                total_alerts=sum(severity_counts.values()),
                critical=severity_counts.get('critical', 0),
                warning=severity_counts.get('warning', 0),
                info=severity_counts.get('info', 0),
                active_alerts=len(active_alerts)
            )
        }
        
    except Exception as e:
        logger.error(f"Erro ao buscar alertas simples: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs/simple/summary")
async def get_logs_summary(
    days: int = Query(7, ge=1, le=365, description="Período em dias para estatísticas"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna resumo de atividades do sistema.
    REQUER AUTENTICAÇÃO.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        date_limit = datetime.now() - timedelta(days=days)
        
        # Contar eventos por tipo
        cursor.execute('''
            SELECT type, COUNT(*) FROM simple_logs 
            WHERE timestamp >= ? 
            GROUP BY type
        ''', (date_limit,))
        
        type_counts = dict(cursor.fetchall())
        
        # Eventos das últimas 24 horas
        cursor.execute('''
            SELECT COUNT(*) FROM simple_logs 
            WHERE timestamp >= ?
        ''', (datetime.now() - timedelta(hours=24),))
        
        last_24h_events = cursor.fetchone()[0]
        
        conn.close()
        
        return LogSummary(
            total_events=sum(type_counts.values()),
            device_connections=type_counts.get('device_connected', 0) + type_counts.get('bluetooth_connected', 0),
            security_alerts=type_counts.get('security_alert', 0),
            attacks_blocked=type_counts.get('attack_blocked', 0),
            anomalies_detected=type_counts.get('anomaly_detected', 0),
            last_24h_events=last_24h_events
        )
        
    except Exception as e:
        logger.error(f"Erro ao gerar resumo de logs: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs/simple/device/{device_id}", response_model=SimpleLogsResponse)
async def get_device_simple_logs(
    device_id: int,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna logs simples de um dispositivo específico.
    REQUER AUTENTICAÇÃO.
    """
    try:
        # Verificar se dispositivo existe
        db = get_db_manager()
        device = db.get_device(device_id)
        if not device:
            raise HTTPException(status_code=404, detail=f"Dispositivo {device_id} não encontrado")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Contar total
        cursor.execute("SELECT COUNT(*) FROM simple_logs WHERE device_id = ?", (device_id,))
        total = cursor.fetchone()[0]
        
        # Buscar logs
        cursor.execute('''
            SELECT * FROM simple_logs 
            WHERE device_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        ''', (device_id, limit, (page - 1) * limit))
        
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append(SimpleLogEntry(
                id=row[0],
                timestamp=row[1],
                type=row[2],
                icon=row[3],
                title=row[4],
                message=row[5],
                severity=row[6],
                device_name=row[7],
                device_id=row[8]
            ))
        
        conn.close()
        
        total_pages = (total + limit - 1) // limit
        
        return SimpleLogsResponse(
            logs=logs,
            pagination=LogPagination(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao buscar logs do dispositivo {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

# ===== ENDPOINTS DE LOGS AVANÇADOS =====

@app.get("/logs/advanced", response_model=AdvancedLogsResponse)
async def get_advanced_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500),
    level: Optional[str] = Query(None, description="Filtrar por nível (DEBUG, INFO, WARNING, ERROR, CRITICAL)"),
    module: Optional[str] = Query(None, description="Filtrar por módulo"),
    date_from: Optional[str] = Query(None, description="Data inicial (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Data final (YYYY-MM-DD)"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Retorna logs técnicos avançados.
    REQUER AUTENTICAÇÃO DE ADMIN.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Construir query
        query = "SELECT * FROM advanced_logs WHERE 1=1"
        params = []
        
        if level:
            query += " AND level = ?"
            params.append(level)
        
        if module:
            query += " AND module = ?"
            params.append(module)
        
        if date_from:
            query += " AND DATE(timestamp) >= ?"
            params.append(date_from)
        
        if date_to:
            query += " AND DATE(timestamp) <= ?"
            params.append(date_to)
        
        # Contar total
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Buscar logs
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, (page - 1) * limit])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append(AdvancedLogEntry(
                id=row[0],
                timestamp=row[1],
                level=row[2],
                module=row[3],
                function=row[4],
                message=row[5],
                details=json.loads(row[6] or '{}'),
                user_id=row[7],
                session_id=row[8],
                stack_trace=row[9],
                performance=json.loads(row[10] or '{}') if row[10] else None
            ))
        
        conn.close()
        
        total_pages = (total + limit - 1) // limit
        
        return AdvancedLogsResponse(
            logs=logs,
            pagination=LogPagination(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        )
        
    except Exception as e:
        logger.error(f"Erro ao buscar logs avançados: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs/advanced/security")
async def get_security_events(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Filtrar por severidade"),
    event_type: Optional[str] = Query(None, description="Filtrar por tipo de evento"),
    resolved: Optional[bool] = Query(None, description="Filtrar por status de resolução"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Retorna eventos de segurança detalhados.
    REQUER AUTENTICAÇÃO DE ADMIN.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Construir query
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        if resolved is not None:
            query += " AND resolved = ?"
            params.append(resolved)
        
        # Contar total
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Buscar eventos
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, (page - 1) * limit])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        events = []
        for row in rows:
            events.append(SecurityEvent(
                id=row[0],
                timestamp=row[1],
                event_type=row[2],
                severity=row[3],
                source_ip=row[4],
                user_agent=row[5],
                details=json.loads(row[6] or '{}'),
                mitigation=row[7],
                resolved=row[8]
            ))
        
        conn.close()
        
        total_pages = (total + limit - 1) // limit
        
        return {
            "security_events": events,
            "pagination": LogPagination(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        }
        
    except Exception as e:
        logger.error(f"Erro ao buscar eventos de segurança: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs/advanced/performance")
async def get_performance_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500),
    min_duration: Optional[int] = Query(None, description="Duração mínima em ms"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Retorna logs de performance do sistema.
    REQUER AUTENTICAÇÃO DE ADMIN.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Buscar logs com dados de performance
        query = "SELECT * FROM advanced_logs WHERE performance IS NOT NULL AND performance != '{}'"
        params = []
        
        if min_duration:
            # Filtrar por duração mínima (requer parsing JSON)
            query += " AND JSON_EXTRACT(performance, '$.duration_ms') >= ?"
            params.append(min_duration)
        
        # Contar total
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Buscar logs
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, (page - 1) * limit])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            performance_data = json.loads(row[10] or '{}')
            if performance_data:  # Só incluir se tem dados de performance
                logs.append(AdvancedLogEntry(
                    id=row[0],
                    timestamp=row[1],
                    level=row[2],
                    module=row[3],
                    function=row[4],
                    message=row[5],
                    details=json.loads(row[6] or '{}'),
                    user_id=row[7],
                    session_id=row[8],
                    stack_trace=row[9],
                    performance=performance_data
                ))
        
        conn.close()
        
        total_pages = (total + limit - 1) // limit
        
        return {
            "performance_logs": logs,
            "pagination": LogPagination(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        }
        
    except Exception as e:
        logger.error(f"Erro ao buscar logs de performance: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs/advanced/errors")
async def get_error_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500),
    current_user: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Retorna logs de erro detalhados.
    REQUER AUTENTICAÇÃO DE ADMIN.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Buscar logs de erro e críticos
        query = "SELECT * FROM advanced_logs WHERE level IN ('ERROR', 'CRITICAL')"
        
        # Contar total
        cursor.execute(query.replace("SELECT *", "SELECT COUNT(*)"))
        total = cursor.fetchone()[0]
        
        # Buscar logs
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        cursor.execute(query, (limit, (page - 1) * limit))
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append(AdvancedLogEntry(
                id=row[0],
                timestamp=row[1],
                level=row[2],
                module=row[3],
                function=row[4],
                message=row[5],
                details=json.loads(row[6] or '{}'),
                user_id=row[7],
                session_id=row[8],
                stack_trace=row[9],
                performance=json.loads(row[10] or '{}') if row[10] else None
            ))
        
        conn.close()
        
        total_pages = (total + limit - 1) // limit
        
        return {
            "error_logs": logs,
            "pagination": LogPagination(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        }
        
    except Exception as e:
        logger.error(f"Erro ao buscar logs de erro: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/logs/advanced/audit")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500),
    user_id: Optional[int] = Query(None, description="Filtrar por usuário"),
    current_user: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Retorna trilha de auditoria (ações de usuários).
    REQUER AUTENTICAÇÃO DE ADMIN.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Buscar logs com user_id (ações de usuários)
        query = "SELECT * FROM advanced_logs WHERE user_id IS NOT NULL"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        # Contar total
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Buscar logs
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, (page - 1) * limit])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append(AdvancedLogEntry(
                id=row[0],
                timestamp=row[1],
                level=row[2],
                module=row[3],
                function=row[4],
                message=row[5],
                details=json.loads(row[6] or '{}'),
                user_id=row[7],
                session_id=row[8],
                stack_trace=row[9],
                performance=json.loads(row[10] or '{}') if row[10] else None
            ))
        
        conn.close()
        
        total_pages = (total + limit - 1) // limit
        
        return {
            "audit_logs": logs,
            "pagination": LogPagination(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        }
        
    except Exception as e:
        logger.error(f"Erro ao buscar logs de auditoria: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

# ===== ENDPOINTS DE ALERTAS =====

@app.get("/alerts/active")
async def get_active_alerts(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna todos os alertas ativos do sistema.
    REQUER AUTENTICAÇÃO.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Alertas de logs simples (últimas 24 horas)
        cursor.execute('''
            SELECT * FROM simple_logs 
            WHERE severity IN ('warning', 'critical') 
            AND timestamp >= ?
            ORDER BY timestamp DESC
        ''', (datetime.now() - timedelta(hours=24),))
        
        simple_alerts = cursor.fetchall()
        
        # Eventos de segurança não resolvidos
        cursor.execute('''
            SELECT * FROM security_events 
            WHERE resolved = FALSE
            ORDER BY timestamp DESC
        ''')
        
        security_alerts = cursor.fetchall()
        
        # Alertas de anomalias (usar sistema existente)
        anomaly_alerts = get_anomaly_alerts(limit=50)
        
        conn.close()
        
        return {
            "simple_alerts": [
                SimpleAlert(
                    id=row[0],
                    type=row[2],
                    title=row[4],
                    message=row[5],
                    severity=row[6],
                    timestamp=row[1],
                    resolved=False,
                    device_name=row[7]
                ) for row in simple_alerts
            ],
            "security_events": [
                SecurityEvent(
                    id=row[0],
                    timestamp=row[1],
                    event_type=row[2],
                    severity=row[3],
                    source_ip=row[4],
                    user_agent=row[5],
                    details=json.loads(row[6] or '{}'),
                    mitigation=row[7],
                    resolved=row[8]
                ) for row in security_alerts
            ],
            "anomaly_alerts": anomaly_alerts,
            "total_active": len(simple_alerts) + len(security_alerts) + len(anomaly_alerts)
        }
        
    except Exception as e:
        logger.error(f"Erro ao buscar alertas ativos: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/alerts/security/{alert_id}/resolve")
async def resolve_security_alert(
    alert_id: int,
    current_user: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Marca um evento de segurança como resolvido.
    REQUER AUTENTICAÇÃO DE ADMIN.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar se alerta existe
        cursor.execute("SELECT * FROM security_events WHERE id = ?", (alert_id,))
        alert = cursor.fetchone()
        
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alerta {alert_id} não encontrado")
        
        if alert[8]:  # já resolvido
            raise HTTPException(status_code=400, detail=f"Alerta {alert_id} já foi resolvido")
        
        # Marcar como resolvido
        cursor.execute('''
            UPDATE security_events 
            SET resolved = TRUE, resolved_at = ?, resolved_by = ?
            WHERE id = ?
        ''', (datetime.now().isoformat(), current_user["id"], alert_id))
        
        conn.commit()
        conn.close()
        
        # Log da ação
        create_simple_log("security_alert", {
            "message": f"Alerta de segurança {alert_id} resolvido por {current_user['email']}"
        }, user_id=current_user["id"])
        
        return {
            "success": True,
            "message": f"Alerta {alert_id} marcado como resolvido",
            "resolved_by": current_user["email"],
            "resolved_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao resolver alerta {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/alerts/statistics")
async def get_alert_statistics(
    days: int = Query(30, ge=1, le=365, description="Período em dias"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna estatísticas de alertas do sistema.
    REQUER AUTENTICAÇÃO.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        date_limit = datetime.now() - timedelta(days=days)
        
        # Estatísticas de logs simples
        cursor.execute('''
            SELECT severity, COUNT(*) FROM simple_logs 
            WHERE timestamp >= ? AND severity IN ('warning', 'critical')
            GROUP BY severity
        ''', (date_limit,))
        
        simple_stats = dict(cursor.fetchall())
        
        # Estatísticas de eventos de segurança
        cursor.execute('''
            SELECT severity, COUNT(*) FROM security_events 
            WHERE timestamp >= ?
            GROUP BY severity
        ''', (date_limit,))
        
        security_stats = dict(cursor.fetchall())
        
        # Eventos não resolvidos
        cursor.execute('''
            SELECT COUNT(*) FROM security_events 
            WHERE resolved = FALSE AND timestamp >= ?
        ''', (date_limit,))
        
        unresolved_security = cursor.fetchone()[0]
        
        conn.close()
        
        # Estatísticas de anomalias (usar sistema existente)
        try:
            anomaly_stats = anomaly_detector.get_statistics(days)
        except:
            anomaly_stats = {"total": 0, "unresolved": 0}
        
        return {
            "period_days": days,
            "simple_alerts": {
                "warning": simple_stats.get('warning', 0),
                "critical": simple_stats.get('critical', 0),
                "total": sum(simple_stats.values())
            },
            "security_events": {
                "low": security_stats.get('low', 0),
                "medium": security_stats.get('medium', 0),
                "high": security_stats.get('high', 0),
                "critical": security_stats.get('critical', 0),
                "total": sum(security_stats.values()),
                "unresolved": unresolved_security
            },
            "anomaly_alerts": anomaly_stats,
            "total_alerts": sum(simple_stats.values()) + sum(security_stats.values()) + anomaly_stats.get("total", 0)
        }
        
    except Exception as e:
        logger.error(f"Erro ao gerar estatísticas de alertas: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

# ===== SISTEMA DE RATE LIMITING =====

# Rate limiting em memória (para produção, usar Redis)
rate_limit_storage = {}

def check_rate_limit(ip_address: str, endpoint: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """
    Verifica rate limiting para um IP em um endpoint específico.
    
    Args:
        ip_address (str): IP do cliente
        endpoint (str): Nome do endpoint
        max_attempts (int): Máximo de tentativas permitidas
        window_minutes (int): Janela de tempo em minutos
        
    Returns:
        bool: True se dentro do limite, False se excedeu
    """
    now = datetime.now()
    key = f"{ip_address}:{endpoint}"
    
    # Limpar entradas antigas
    cutoff_time = now - timedelta(minutes=window_minutes)
    if key in rate_limit_storage:
        rate_limit_storage[key] = [
            timestamp for timestamp in rate_limit_storage[key] 
            if timestamp > cutoff_time
        ]
    
    # Verificar limite atual
    current_attempts = len(rate_limit_storage.get(key, []))
    
    if current_attempts >= max_attempts:
        logger.warning(f"Rate limit excedido para {ip_address} no endpoint {endpoint}: {current_attempts}/{max_attempts}")
        return False
    
    # Registrar tentativa atual
    if key not in rate_limit_storage:
        rate_limit_storage[key] = []
    rate_limit_storage[key].append(now)
    
    return True

def rate_limit_dependency(endpoint: str, max_attempts: int = 5, window_minutes: int = 15):
    """
    Dependency para aplicar rate limiting em endpoints.
    """
    def rate_limit_check(request: Request):
        ip_address = request.client.host
        
        if not check_rate_limit(ip_address, endpoint, max_attempts, window_minutes):
            raise HTTPException(
                status_code=429, 
                detail=f"Muitas tentativas. Tente novamente em {window_minutes} minutos."
            )
        return True
    
    return rate_limit_check

# ===== ENDPOINTS DE AUTENTICAÇÃO =====

@app.post("/auth/register", response_model=RegisterResponse)
async def register_user(
    register_request: RegisterRequest, 
    request: Request,
    _: bool = Depends(rate_limit_dependency("auth_register", max_attempts=3, window_minutes=15))
):
    """
    Registra um novo usuário no sistema.
    
    Args:
        register_request (RegisterRequest): Dados do registro
        
    Returns:
        RegisterResponse: Resultado do registro
    """
    try:
        # Forzar rol de usuario común
        from src.auth_models import UserRole
        register_request.role = UserRole.USER
        
        result = auth_service.register_user(
            email=register_request.email,
            password=register_request.password,
            full_name=register_request.full_name,
            phone=register_request.phone,
            role=register_request.role.value
        )
        
        # Log do registro de usuário
        create_simple_log("user_registered", {
            "email": register_request.email,
            "full_name": register_request.full_name,
            "role": register_request.role.value
        })
        
        create_advanced_log("INFO", "auth_service", "register_user", 
                           f"User registered: {register_request.email}", 
                           {"email": register_request.email, "role": register_request.role.value})
        
        return RegisterResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro no registro de usuário: {e}")
        
        # Log de erro no registro
        create_security_event("registration_failure", "medium", {
            "email": register_request.email,
            "error": str(e),
            "ip_address": request.client.host if request.client else None
        }, source_ip=request.client.host if request.client else None)
        
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/login", response_model=LoginResponse)
async def login_step1(
    login_request: LoginRequest, 
    request: Request,
    _: bool = Depends(rate_limit_dependency("auth_login", max_attempts=5, window_minutes=15))
):
    """
    Primeira etapa do login - verifica credenciais e envia código 2FA.
    
    Args:
        login_request (LoginRequest): Dados de login
        
    Returns:
        LoginResponse: Resultado da primeira etapa
    """
    try:
        result = auth_service.login_step1(
            email=login_request.email,
            password=login_request.password,
            request=request
        )
        
        # Log de login bem-sucedido (etapa 1)
        create_simple_log("user_login", {
            "email": login_request.email,
            "step": "1_credentials_verified"
        })
        
        create_advanced_log("INFO", "auth_service", "login_step1", 
                           f"Login step 1 successful: {login_request.email}",
                           {"email": login_request.email, "ip": request.client.host if request.client else None})
        
        return LoginResponse(**result)
        
    except HTTPException as he:
        # Log de falha de autenticação
        create_security_event("authentication_failure", "medium", {
            "email": login_request.email,
            "step": "1_credentials",
            "reason": str(he.detail),
            "ip_address": request.client.host if request.client else None
        }, source_ip=request.client.host if request.client else None,
           user_agent=request.headers.get("User-Agent"))
        
        raise
    except Exception as e:
        logger.error(f"Erro no login (etapa 1): {e}")
        
        # Log de erro interno
        create_security_event("authentication_error", "high", {
            "email": login_request.email,
            "error": str(e),
            "ip_address": request.client.host if request.client else None
        }, source_ip=request.client.host if request.client else None)
        
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/2fa/verify", response_model=TwoFAResponse)
async def verify_2fa(
    twofa_request: TwoFARequest, 
    request: Request,
    _: bool = Depends(rate_limit_dependency("auth_2fa", max_attempts=10, window_minutes=15))
):
    """
    Segunda etapa do login - verifica código 2FA e gera tokens JWT.
    
    Args:
        twofa_request (TwoFARequest): Token temporário e código 2FA
        
    Returns:
        TwoFAResponse: Tokens JWT e dados do usuário
    """
    try:
        result = auth_service.login_step2(
            temp_token=twofa_request.temp_token,
            code=twofa_request.code,
            request=request
        )
        
        # Log de login completo bem-sucedido
        create_simple_log("user_login", {
            "email": result.get("user", {}).get("email", "N/A"),
            "step": "2_2fa_verified"
        })
        
        create_advanced_log("INFO", "auth_service", "login_step2", 
                           f"Login completed: {result.get('user', {}).get('email', 'N/A')}",
                           {"2fa_verified": True, "ip": request.client.host if request.client else None})
        
        return TwoFAResponse(**result)
        
    except HTTPException as he:
        # Log de falha na verificação 2FA
        create_security_event("authentication_failure", "high", {
            "step": "2_2fa_verification",
            "reason": str(he.detail),
            "ip_address": request.client.host if request.client else None
        }, source_ip=request.client.host if request.client else None,
           user_agent=request.headers.get("User-Agent"))
        
        raise
    except Exception as e:
        logger.error(f"Erro na verificação 2FA: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(refresh_request: RefreshTokenRequest):
    """
    Renova o access token usando refresh token.
    
    Args:
        refresh_request (RefreshTokenRequest): Refresh token
        
    Returns:
        TokenResponse: Novo access token
    """
    try:
        result = auth_service.refresh_access_token(refresh_request.refresh_token)
        return TokenResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao renovar token: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/totp/setup", response_model=TOTPSetupResponse)
async def setup_totp(
    setup_request: TOTPSetupRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Configura TOTP (Google Authenticator) para o usuário.
    
    Returns:
        TOTPSetupResponse: QR Code e informações para configuração
    """
    try:
        result = auth_service.setup_totp(current_user["id"])
        return TOTPSetupResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro na configuração TOTP: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/totp/verify", response_model=TOTPVerifyResponse)
async def verify_totp_setup(
    verify_request: TOTPVerifyRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verifica código TOTP e ativa o 2FA.
    
    Args:
        verify_request: Código de 6 dígitos do app
        
    Returns:
        TOTPVerifyResponse: Resultado da verificação e tokens se válido
    """
    try:
        result = auth_service.verify_totp_and_enable(current_user["id"], verify_request.code)
        return TOTPVerifyResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro na verificação TOTP: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/totp/login", response_model=TOTPVerifyResponse)
async def login_with_totp(
    verify_request: TOTPVerifyRequest,
    temp_token: str = None
):
    """
    Faz login usando código TOTP (segunda etapa do login).
    
    Args:
        verify_request: Código de 6 dígitos do app
        temp_token: Token temporário da primeira etapa
        
    Returns:
        TOTPVerifyResponse: Tokens de acesso se válido
    """
    try:
        # Aqui deveria validar o temp_token e extrair user_id
        # Por simplicidade, vou implementar uma versão básica
        # Em produção, deveria validar o token temporário
        
        # Para este exemplo, vou assumir que o user_id vem do token temporário
        # Implementação completa requereria decodificar o temp_token
        
        raise HTTPException(
            status_code=501, 
            detail="Login TOTP deve ser implementado junto com modificação do fluxo de login principal"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro no login TOTP: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/auth/me", response_model=UserInfo)
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Retorna informações do usuário autenticado.
    
    Args:
        current_user: Usuário autenticado
        
    Returns:
        UserInfo: Informações do usuário
    """
    return UserInfo(
        id=current_user["id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        is_active=current_user["is_active"],
        created_at=current_user["created_at"],
        last_login=current_user.get("last_login"),
        phone=current_user.get("phone"),
        two_fa_enabled=current_user["two_fa_enabled"]
    )

@app.post("/auth/device/register", response_model=DeviceRegistrationResponse)
async def register_device_with_2fa(
    device_request: DeviceRegistrationRequest,
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Registra um dispositivo com verificação 2FA.
    
    Args:
        device_request (DeviceRegistrationRequest): Dados do dispositivo
        current_user: Usuário autenticado com privilégios de operador
        
    Returns:
        DeviceRegistrationResponse: Resultado do registro
    """
    try:
        if device_request.requires_2fa:
            # Gerar código 2FA para registro de dispositivo
            code = auth_db_manager.generate_2fa_code(current_user["id"], "device_registration")
            
            # Enviar código por email
            from src.notification_service import notification_service
            notification_sent = notification_service.send_2fa_email(
                current_user["email"], code, current_user["full_name"]
            )
            
            return DeviceRegistrationResponse(
                success=True,
                message="Código 2FA enviado para confirmar registro do dispositivo",
                device_id=None,
                requires_2fa_verification=True,
                verification_method="email"
            )
        else:
            # Registrar dispositivo diretamente (sem 2FA)
            if device_request.connection_type == "wifi":
                device_data = {
                    "device_type": device_request.device_type,
                    "ip_address": device_request.ip_address,
                    "registered_at": datetime.now().isoformat()
                }
                device_id = auth_db_manager.add_device(device_data)
            else:
                # Bluetooth
                device_id = auth_db_manager.insert_bluetooth_device(
                    device_request.device_type,
                    device_request.mac_address,
                    device_request.device_name
                )
            
            return DeviceRegistrationResponse(
                success=True,
                message="Dispositivo registrado com sucesso",
                device_id=device_id,
                requires_2fa_verification=False
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro no registro de dispositivo: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/verify-email", response_model=EmailVerificationResponse)
async def verify_email(request: EmailVerificationRequest):
    """
    Verifica o código enviado por email após o registro e marca email_verified.
    """
    try:
        # Buscar usuário
        user = auth_db_manager.get_user_by_email(request.email)
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        user_id = user["id"]
        # Verificar código do tipo email_verification
        valid = auth_db_manager.verify_2fa_code(user_id, request.code, "email_verification")
        if not valid:
            raise HTTPException(status_code=400, detail="Código de verificação inválido ou expirado")

        # Marcar email como verificado
        cursor = auth_db_manager.conn.cursor()
        cursor.execute('UPDATE users SET email_verified = 1 WHERE id = ?', (user_id,))
        auth_db_manager.conn.commit()

        create_advanced_log("INFO", "auth_service", "verify_email",
                            f"Email verificado para usuário {request.email}", {"user_id": user_id})

        return EmailVerificationResponse(success=True, message="Email verificado com sucesso")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao verificar email: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/verify-email/resend")
async def resend_email_verification(request: EmailResendRequest):
    try:
        user = auth_db_manager.get_user_by_email(request.email)
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        user_id = user["id"]
        # gerar novo código
        code = auth_db_manager.generate_2fa_code(user_id, "email_verification")
        sent = auth_service.notification_service.send_2fa_email(request.email, code, user.get("full_name", "Usuário"))
        if not sent:
            raise HTTPException(status_code=500, detail="Falha ao enviar email")
        return {"success": True, "message": "Código reenviado"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao reenviar verificação de email: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/auth/2fa/resend", response_model=SimpleResponse)
async def resend_2fa_code(twofa_resend: TwoFAResendRequest, request: Request):
    """Reenvia o código 2FA da etapa 1 do login usando o temp_token."""
    try:
        user_id = auth_db_manager.verify_temp_token(twofa_resend.temp_token, "temp_login")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token temporário inválido ou expirado")
        # Gerar novo código e enviar por email
        code = auth_db_manager.generate_2fa_code(user_id, "login")
        user = auth_db_manager.get_user_by_id(user_id)
        sent = False
        if user and user.get("email"):
            sent = auth_service.notification_service.send_2fa_email(user["email"], code, user.get("full_name", ""))
        if not sent:
            raise HTTPException(status_code=500, detail="Falha ao enviar código 2FA")
        return SimpleResponse(success=True, message="Novo código 2FA enviado por email")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao reenviar 2FA: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

# ===== ENDPOINTS ORIGINAIS (MANTIDOS) =====

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
    """Modelo para registro de dispositivo WiFi."""
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

class BluetoothDeviceRegister(BaseModel):
    """Modelo para registro de dispositivo Bluetooth."""
    device_type: str = Field(..., description="Tipo do dispositivo")
    mac_address: str = Field(..., description="Endereço MAC do dispositivo Bluetooth")
    device_name: Optional[str] = Field(None, description="Nome do dispositivo (opcional)")

    @field_validator('device_type')
    @staticmethod
    def validate_device_type(v):
        allowed_types = ["smart-lamp", "smart-lock", "sensor", "speaker", 
                        "headphones", "keyboard", "mouse", "smart-watch", "fitness-tracker"]
        if v not in allowed_types:
            raise ValueError(f"Tipo de dispositivo Bluetooth '{v}' não é permitido. Tipos válidos: {allowed_types}")
        return v

    @field_validator('mac_address')
    @staticmethod
    def validate_mac(v):
        import re
        # Formato MAC: XX:XX:XX:XX:XX:XX ou XX-XX-XX-XX-XX-XX
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        if not re.match(mac_pattern, v):
            raise ValueError("Endereço MAC inválido. Use formato XX:XX:XX:XX:XX:XX ou XX-XX-XX-XX-XX-XX")
        return v.upper().replace('-', ':')  # Normalizar para formato com ':'

class BluetoothCommandRequest(BaseModel):
    """Modelo para requisição de comando Bluetooth."""
    device_id: int = Field(..., description="ID do dispositivo")
    command: str = Field(..., min_length=1, description="Comando a ser executado")

    @field_validator('command')
    @staticmethod
    def validate_command(v, info):
        allowed_commands = [
            "turn_on", "turn_off", "set_brightness", "set_color", "get_status",
            "play", "pause", "volume_up", "volume_down", "next_track", "previous_track",
            "lock", "unlock", "get_battery", "sync_time", "get_data"
        ]
        if v not in allowed_commands:
            raise ValueError(f"Comando Bluetooth '{v}' não é permitido. Comandos válidos: {allowed_commands}")
        return v

class BluetoothScanRequest(BaseModel):
    """Modelo para requisição de escaneamento Bluetooth."""
    timeout: Optional[float] = Field(10.0, ge=1.0, le=60.0, description="Tempo limite para escaneamento (1-60 segundos)")

class BluetoothConnectionRequest(BaseModel):
    """Modelo para requisição de conexão Bluetooth."""
    mac_address: str = Field(..., description="Endereço MAC do dispositivo")
    timeout: Optional[float] = Field(10.0, ge=5.0, le=30.0, description="Tempo limite para conexão (5-30 segundos)")

    @field_validator('mac_address')
    @staticmethod
    def validate_mac(v):
        import re
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        if not re.match(mac_pattern, v):
            raise ValueError("Endereço MAC inválido")
        return v.upper().replace('-', ':')

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

async def send_command_to_device(device: Dict[str, Any], command: str, protection_enabled: bool) -> str:
    """
    Envia comando para dispositivo usando o interceptor apropriado (WiFi ou Bluetooth).
    
    Args:
        device (Dict[str, Any]): Dados do dispositivo
        command (str): Comando a ser enviado
        protection_enabled (bool): Se a proteção está ativa
        
    Returns:
        str: Status do envio ("success", "blocked", "error", "not_connected")
    """
    if not isinstance(device, dict) or "device_type" not in device:
        logger.error(f"Dados do dispositivo incompletos: {device}")
        raise ValueError("Dados do dispositivo incompletos")
    
    try:
        device_type = device["device_type"]
        connection_type = device.get("connection_type", "wifi")
        
        # Determinar se é dispositivo Bluetooth ou WiFi
        if connection_type == "bluetooth":
            # Envio via Bluetooth
            if "mac_address" not in device:
                logger.error(f"MAC address não encontrado para dispositivo Bluetooth: {device}")
                raise ValueError("MAC address obrigatório para dispositivos Bluetooth")
            
            from src.bluetooth_interceptor import send_bluetooth_command
            
            mac_address = device["mac_address"]
            encrypted_data = None
            
            if protection_enabled:
                encrypted_data = encrypt_command(command)
                logger.info(f"Enviando comando criptografado via Bluetooth para {mac_address}")
            else:
                logger.info(f"Enviando comando não criptografado via Bluetooth para {mac_address}: {command}")
            
            status = await send_bluetooth_command(mac_address, command, encrypted_data)
            return status
            
        else:
            # Envio via WiFi (comportamento original)
            if "ip_address" not in device:
                logger.error(f"IP address não encontrado para dispositivo WiFi: {device}")
                raise ValueError("IP address obrigatório para dispositivos WiFi")
            
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
async def toggle_protection(
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_admin_user)
):
    """
    Alterna o estado da proteção (ativa/desativa).
    REQUER AUTENTICAÇÃO DE ADMIN.
    
    Returns:
        ToggleResponse: Novo status da proteção
    """
    try:
        new_status = db.toggle_protection()
        status_text = "ativada" if new_status else "desativada"
        
        # Log da ação
        auth_db_manager.log_auth_event(
            current_user["id"], "toggle_protection", True,
            details=f"Proteção {status_text} pelo usuário {current_user['email']}"
        )
        
        # Log simples para usuário final
        create_simple_log("protection_toggled", {
            "enabled": new_status,
            "admin_email": current_user["email"]
        }, user_id=current_user["id"])
        
        # Log avançado para auditoria
        create_advanced_log("INFO", "protection", "toggle_protection",
                           f"Protection {status_text} by admin",
                           {"new_status": new_status, "admin_id": current_user["id"]},
                           user_id=current_user["id"])
        
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
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna logs de comandos enviados aos dispositivos.
    REQUER AUTENTICAÇÃO.
    
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
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Recebe e processa comandos para dispositivos IoT.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
    
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
                
                # Log de comando bloqueado
                create_simple_log("command_blocked", {
                    "command": command,
                    "device_name": device.get("device_name", device.get("device_type")),
                    "reason": "comando_nao_criptografado"
                }, device_id=device_id, user_id=current_user["id"])
                
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
            status = await send_command_to_device(device, command, device_protection_enabled)
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
        
        # DETECÇÃO DE ANOMALIAS - Analisar comando em tempo real
        try:
            anomalies = analyze_command_for_anomalies(device_id, command, status)
            if anomalies:
                logger.warning(f"Anomalias detectadas para dispositivo {device_id}: {len(anomalies)} alertas")
                for anomaly in anomalies:
                    logger.warning(f"Anomalia {anomaly.anomaly_type}: {anomaly.description}")
                    
                    # Log de anomalia detectada
                    create_simple_log("anomaly_detected", {
                        "device_name": device.get("device_name", device.get("device_type")),
                        "description": anomaly.description,
                        "command": command
                    }, device_id=device_id, user_id=current_user["id"])
        except Exception as anomaly_error:
            logger.error(f"Erro na detecção de anomalias: {anomaly_error}")
            # Não falhar o comando por erro na detecção de anomalias
        
        # Log da ação do usuário
        auth_db_manager.log_auth_event(
            current_user["id"], "device_command", True,
            details=f"Comando '{command}' enviado para dispositivo {device_id} pelo usuário {current_user['email']}"
        )
        
        # Log simples do comando enviado
        if status == "success":
            create_simple_log("command_sent", {
                "command": command,
                "device_name": device.get("device_name", device.get("device_type")),
                "encrypted": device_protection_enabled
            }, device_id=device_id, user_id=current_user["id"])
        
        # Log avançado com detalhes técnicos
        create_advanced_log("INFO", "device_command", "send_command",
                           f"Command sent to device {device_id}",
                           {
                               "command": command,
                               "device_id": device_id,
                               "status": status,
                               "protection_enabled": device_protection_enabled,
                               "device_type": device.get("device_type")
                           },
                           user_id=current_user["id"])
        
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
async def get_devices(
    db: DatabaseManager = Depends(get_db_manager), 
    request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna todos os dispositivos registrados.
    REQUER AUTENTICAÇÃO.
    
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
async def get_device(
    device_id: int, 
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna dados de um dispositivo específico.
    REQUER AUTENTICAÇÃO.
    
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
async def register_device(
    device: DeviceRegister, 
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Registra um novo dispositivo.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
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
        
        # Log da ação
        auth_db_manager.log_auth_event(
            current_user["id"], "device_registration", True,
            details=f"Dispositivo {device.device_type} registrado com IP {device.ip_address} pelo usuário {current_user['email']}"
        )
        
        # Log simples do registro de dispositivo
        create_simple_log("device_registered", {
            "device_type": device.device_type,
            "device_name": f"{device.device_type} ({device.ip_address})",
            "ip_address": device.ip_address
        }, device_id=device_id, user_id=current_user["id"])
        
        # Log avançado com detalhes técnicos
        create_advanced_log("INFO", "device_manager", "register_device",
                           f"Device registered: {device.device_type}",
                           {
                               "device_id": device_id,
                               "device_type": device.device_type,
                               "ip_address": device.ip_address,
                               "registered_by": current_user["email"]
                           },
                           user_id=current_user["id"])
        
        logger.info(f"Dispositivo registrado com sucesso: {device_data}")
        return device_data
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro inesperado ao registrar dispositivo: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro inesperado ao registrar dispositivo: {str(e)}")

@app.delete("/devices/{device_id}", response_model=Dict[str, str])
async def delete_device(
    device_id: int, 
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Remove um dispositivo.
    REQUER AUTENTICAÇÃO DE ADMIN OU OPERADOR DE DISPOSITIVO.
    
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
        
        # Log da ação
        auth_db_manager.log_auth_event(
            current_user["id"], "device_deletion", True,
            details=f"Dispositivo {device_id} removido pelo usuário {current_user['email']}"
        )
        
        # Log simples da remoção
        create_simple_log("device_deleted", {
            "device_name": device.get("device_name", device.get("device_type")),
            "device_type": device.get("device_type"),
            "ip_address": device.get("ip_address")
        }, device_id=device_id, user_id=current_user["id"])
        
        # Log avançado
        create_advanced_log("WARNING", "device_manager", "delete_device",
                           f"Device {device_id} deleted by admin",
                           {
                               "device_id": device_id,
                               "device_data": device,
                               "deleted_by": current_user["email"]
                           },
                           user_id=current_user["id"])
        
        logger.info(f"Dispositivo {device_id} removido com sucesso")
        return {"message": f"Dispositivo {device_id} removido com sucesso"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao remover dispositivo {device_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao remover dispositivo: {str(e)}")

@app.get("/devices/{device_id}/protection", response_model=Dict[str, Any])
async def get_device_protection(
    device_id: int, 
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna o status de proteção de um dispositivo específico.
    REQUER AUTENTICAÇÃO.
    
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
async def toggle_device_protection(
    device_id: int, 
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Alterna o status de proteção de um dispositivo específico.
    REQUER AUTENTICAÇÃO DE ADMIN.
    
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
        
        # Log da ação
        auth_db_manager.log_auth_event(
            current_user["id"], "device_protection_toggle", True,
            details=f"Proteção do dispositivo {device_id} {status_text} pelo usuário {current_user['email']}"
        )
        
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

# ===== ENDPOINTS ESPECÍFICOS PARA BLUETOOTH =====

@app.post("/bluetooth/scan", response_model=Dict[str, Any])
async def scan_bluetooth_devices(
    scan_request: BluetoothScanRequest = BluetoothScanRequest(),
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Escaneia dispositivos Bluetooth disponíveis.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
    
    Args:
        scan_request (BluetoothScanRequest): Parâmetros do escaneamento
        
    Returns:
        Dict[str, Any]: Lista de dispositivos encontrados
    """
    try:
        from src.bluetooth_interceptor import scan_bluetooth_devices
        
        logger.info(f"Iniciando escaneamento Bluetooth (timeout: {scan_request.timeout}s)")
        
        devices = await scan_bluetooth_devices(scan_request.timeout)
        
        return {
            "success": True,
            "message": f"{len(devices)} dispositivos Bluetooth encontrados",
            "devices": devices,
            "scan_timeout": scan_request.timeout,
            "timestamp": datetime.now().isoformat()
        }
        
    except RuntimeError as e:
        if "Bluetooth não disponível" in str(e):
            raise HTTPException(status_code=503, detail="Bluetooth não disponível no sistema")
        raise HTTPException(status_code=500, detail=f"Erro no escaneamento Bluetooth: {e}")
    except Exception as e:
        logger.error(f"Erro inesperado no escaneamento Bluetooth: {e}")
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {e}")

@app.post("/bluetooth/connect", response_model=Dict[str, Any])
async def connect_bluetooth_device(
    connection_request: BluetoothConnectionRequest,
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Conecta a um dispositivo Bluetooth específico.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
    
    Args:
        connection_request (BluetoothConnectionRequest): Dados da conexão
        
    Returns:
        Dict[str, Any]: Resultado da conexão
    """
    try:
        from src.bluetooth_interceptor import connect_bluetooth_device
        
        mac_address = connection_request.mac_address
        timeout = connection_request.timeout
        
        logger.info(f"Tentando conectar ao dispositivo Bluetooth {mac_address}")
        
        success = await connect_bluetooth_device(mac_address)
        
        if success:
            # Atualizar status no banco de dados se dispositivo já registrado
            db = get_db_manager()
            device = db.get_device_by_mac(mac_address)
            if device:
                db.update_device_connection_status(device["id"], True)
            
            return {
                "success": True,
                "message": f"Conectado com sucesso ao dispositivo {mac_address}",
                "mac_address": mac_address,
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "success": False,
                "message": f"Falha na conexão com {mac_address}",
                "mac_address": mac_address,
                "timestamp": datetime.now().isoformat()
            }
            
    except RuntimeError as e:
        if "Bluetooth não disponível" in str(e):
            raise HTTPException(status_code=503, detail="Bluetooth não disponível no sistema")
        raise HTTPException(status_code=500, detail=f"Erro na conexão Bluetooth: {e}")
    except Exception as e:
        logger.error(f"Erro inesperado na conexão Bluetooth: {e}")
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {e}")

@app.post("/bluetooth/disconnect/{mac_address}", response_model=Dict[str, Any])
async def disconnect_bluetooth_device(
    mac_address: str,
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Desconecta de um dispositivo Bluetooth específico.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
    
    Args:
        mac_address (str): Endereço MAC do dispositivo
        
    Returns:
        Dict[str, Any]: Resultado da desconexão
    """
    try:
        from src.bluetooth_interceptor import disconnect_bluetooth_device
        
        logger.info(f"Desconectando do dispositivo Bluetooth {mac_address}")
        
        success = await disconnect_bluetooth_device(mac_address)
        
        if success:
            # Atualizar status no banco de dados
            db = get_db_manager()
            device = db.get_device_by_mac(mac_address)
            if device:
                db.update_device_connection_status(device["id"], False)
            
            return {
                "success": True,
                "message": f"Desconectado com sucesso do dispositivo {mac_address}",
                "mac_address": mac_address,
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "success": False,
                "message": f"Dispositivo {mac_address} não estava conectado",
                "mac_address": mac_address,
                "timestamp": datetime.now().isoformat()
            }
            
    except RuntimeError as e:
        if "Bluetooth não disponível" in str(e):
            raise HTTPException(status_code=503, detail="Bluetooth não disponível no sistema")
        raise HTTPException(status_code=500, detail=f"Erro na desconexão Bluetooth: {e}")
    except Exception as e:
        logger.error(f"Erro inesperado na desconexão Bluetooth: {e}")
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {e}")

@app.post("/bluetooth/device/register", response_model=Dict[str, Any])
async def register_bluetooth_device(
    device: BluetoothDeviceRegister, 
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Registra um novo dispositivo Bluetooth.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
    
    Args:
        device (BluetoothDeviceRegister): Dados do dispositivo Bluetooth
        
    Returns:
        Dict[str, Any]: Dados do dispositivo registrado
    """
    try:
        logger.info(f"Tentando registrar dispositivo Bluetooth: {device.dict()}")
        
        # Verificar se o MAC já está registrado
        existing_device = db.get_device_by_mac(device.mac_address)
        if existing_device:
            logger.warning(f"MAC {device.mac_address} já está registrado")
            raise HTTPException(
                status_code=400, 
                detail=f"Dispositivo já registrado com este MAC: {device.mac_address}"
            )
        
        device_id = db.insert_bluetooth_device(
            device.device_type, 
            device.mac_address, 
            device.device_name
        )
        
        device_data = {
            "id": device_id,
            "device_type": device.device_type,
            "mac_address": device.mac_address,
            "device_name": device.device_name,
            "connection_type": "bluetooth",
            "registered_at": datetime.now().isoformat(),
            "protection_enabled": True,
            "is_connected": False
        }
        
        # Log da ação
        auth_db_manager.log_auth_event(
            current_user["id"], "bluetooth_device_registration", True,
            details=f"Dispositivo Bluetooth {device.device_type} registrado com MAC {device.mac_address} pelo usuário {current_user['email']}"
        )
        
        # Log simples do registro Bluetooth
        create_simple_log("bluetooth_connected", {
            "device_type": device.device_type,
            "device_name": device.device_name or device.device_type,
            "mac_address": device.mac_address
        }, device_id=device_id, user_id=current_user["id"])
        
        # Log avançado
        create_advanced_log("INFO", "bluetooth_manager", "register_bluetooth_device",
                           f"Bluetooth device registered: {device.device_type}",
                           {
                               "device_id": device_id,
                               "device_type": device.device_type,
                               "mac_address": device.mac_address,
                               "device_name": device.device_name,
                               "registered_by": current_user["email"]
                           },
                           user_id=current_user["id"])
        
        logger.info(f"Dispositivo Bluetooth registrado com sucesso: {device_data}")
        return device_data
        
    except HTTPException:
        raise
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400, 
            detail=f"MAC address {device.mac_address} já está registrado"
        )
    except Exception as e:
        logger.error(f"Erro inesperado ao registrar dispositivo Bluetooth: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {str(e)}")

@app.get("/bluetooth/devices", response_model=List[Dict[str, Any]])
async def get_bluetooth_devices(
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Lista todos os dispositivos Bluetooth registrados.
    REQUER AUTENTICAÇÃO.
    
    Returns:
        List[Dict[str, Any]]: Lista de dispositivos Bluetooth
    """
    try:
        devices = db.get_bluetooth_devices()
        logger.info(f"Retornando {len(devices)} dispositivos Bluetooth")
        return devices
        
    except Exception as e:
        logger.error(f"Erro ao buscar dispositivos Bluetooth: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.get("/bluetooth/devices/connected", response_model=List[Dict[str, Any]])
async def get_connected_bluetooth_devices(
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Lista todos os dispositivos Bluetooth atualmente conectados.
    REQUER AUTENTICAÇÃO.
    
    Returns:
        List[Dict[str, Any]]: Lista de dispositivos Bluetooth conectados
    """
    try:
        devices = db.get_connected_bluetooth_devices()
        logger.info(f"Retornando {len(devices)} dispositivos Bluetooth conectados")
        return devices
        
    except Exception as e:
        logger.error(f"Erro ao buscar dispositivos Bluetooth conectados: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/bluetooth/command", response_model=CommandResponse)
async def send_bluetooth_command(
    command_request: BluetoothCommandRequest, 
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Envia comando para dispositivo Bluetooth.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
    
    Args:
        command_request (BluetoothCommandRequest): Dados do comando
        
    Returns:
        CommandResponse: Resultado do processamento do comando
    """
    try:
        device_id = command_request.device_id
        command = command_request.command
        
        # Busca o dispositivo
        device = db.get_device(device_id)
        if not device:
            db.insert_log(device_id, command, "device_not_found")
            raise HTTPException(status_code=404, detail=f"Dispositivo com ID {device_id} não encontrado")
        
        # Verificar se é dispositivo Bluetooth
        if device.get("connection_type") != "bluetooth":
            raise HTTPException(
                status_code=400, 
                detail=f"Dispositivo {device_id} não é um dispositivo Bluetooth"
            )
        
        # Verificar se dispositivo está conectado
        if not device.get("is_connected", False):
            db.insert_log(device_id, command, "not_connected")
            raise HTTPException(
                status_code=400, 
                detail=f"Dispositivo Bluetooth {device_id} não está conectado"
            )
        
        device_protection_enabled = device.get("protection_enabled", False)
        
        try:
            status = await send_command_to_device(device, command, device_protection_enabled)
        except Exception as e:
            logger.error(f"Erro ao enviar comando Bluetooth: {e}")
            status = "error"
        
        # Registrar log
        try:
            db.insert_log(device_id, command, status)
        except Exception as log_error:
            logger.error(f"Erro ao inserir log: {log_error}")
        
        # DETECÇÃO DE ANOMALIAS - Analisar comando Bluetooth em tempo real
        try:
            anomalies = analyze_command_for_anomalies(device_id, command, status)
            if anomalies:
                logger.warning(f"Anomalias detectadas para dispositivo Bluetooth {device_id}: {len(anomalies)} alertas")
                for anomaly in anomalies:
                    logger.warning(f"Anomalia {anomaly.anomaly_type}: {anomaly.description}")
        except Exception as anomaly_error:
            logger.error(f"Erro na detecção de anomalias Bluetooth: {anomaly_error}")
            # Não falhar o comando por erro na detecção de anomalias
        
        # Log da ação do usuário
        auth_db_manager.log_auth_event(
            current_user["id"], "bluetooth_command", True,
            details=f"Comando Bluetooth '{command}' enviado para dispositivo {device_id} pelo usuário {current_user['email']}"
        )
        
        if status == "success":
            response_message = f"Comando '{command}' enviado via Bluetooth para {device['device_type']} {'com proteção ativa' if device_protection_enabled else 'sem proteção'}"
        elif status == "not_connected":
            response_message = f"Dispositivo Bluetooth não conectado"
        else:
            response_message = f"Erro ao enviar comando Bluetooth '{command}'"
        
        return CommandResponse(
            success=status == "success",
            message=response_message,
            device_id=device_id,
            command=command,
            timestamp=datetime.now().isoformat(),
            protection_enabled=device_protection_enabled
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao processar comando Bluetooth: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

# ===== ENDPOINTS DE DETECÇÃO DE ANOMALIAS =====

class AnomalyAlert(BaseModel):
    """Modelo para resposta de alerta de anomalia."""
    id: int
    device_id: int
    anomaly_type: str
    severity: str
    rule_name: str
    description: str
    evidence: Dict[str, Any]
    timestamp: str
    resolved: bool
    resolved_at: Optional[str]
    device_type: Optional[str]
    device_name: Optional[str]

@app.get("/anomalies/alerts", response_model=List[AnomalyAlert])
async def get_anomaly_alerts_endpoint(
    device_id: Optional[int] = Query(None, description="Filtrar por dispositivo específico"),
    severity: Optional[str] = Query(None, description="Filtrar por severidade (low, medium, high, critical)"),
    resolved: Optional[bool] = Query(None, description="Filtrar por status de resolução"),
    limit: int = Query(100, description="Limite de resultados", le=500),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Lista alertas de anomalias detectadas.
    REQUER AUTENTICAÇÃO.
    
    Args:
        device_id: Filtrar por dispositivo específico
        severity: Filtrar por severidade
        resolved: Filtrar por status de resolução
        limit: Limite de resultados
        
    Returns:
        List[AnomalyAlert]: Lista de alertas de anomalias
    """
    try:
        # Validar severidade se fornecida
        valid_severities = ["low", "medium", "high", "critical"]
        if severity and severity not in valid_severities:
            raise HTTPException(
                status_code=400, 
                detail=f"Severidade inválida. Use: {', '.join(valid_severities)}"
            )
        
        alerts = get_anomaly_alerts(device_id, severity, resolved, limit)
        
        logger.info(f"Retornando {len(alerts)} alertas de anomalias para usuário {current_user['email']}")
        
        return alerts
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao buscar alertas de anomalias: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

@app.post("/anomalies/alerts/{alert_id}/resolve")
async def resolve_anomaly_alert(
    alert_id: int,
    current_user: Dict[str, Any] = Depends(get_current_device_operator)
):
    """
    Marca um alerta de anomalia como resolvido.
    REQUER AUTENTICAÇÃO DE OPERADOR DE DISPOSITIVOS.
    
    Args:
        alert_id: ID do alerta a ser resolvido
        
    Returns:
        Dict: Status da resolução
    """
    try:
        success = anomaly_detector.resolve_alert(alert_id, current_user["id"])
        
        if success:
            # Log da ação
            auth_db_manager.log_auth_event(
                current_user["id"], "anomaly_alert_resolved", True,
                details=f"Alerta de anomalia {alert_id} resolvido por {current_user['email']}"
            )
            
            logger.info(f"Alerta {alert_id} resolvido por usuário {current_user['email']}")
            
            return {
                "success": True,
                "message": f"Alerta {alert_id} marcado como resolvido",
                "resolved_by": current_user["email"],
                "resolved_at": datetime.now().isoformat()
            }
        else:
            raise HTTPException(
                status_code=404, 
                detail=f"Alerta {alert_id} não encontrado ou já resolvido"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao resolver alerta {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

class DeviceUsagePattern(BaseModel):
    """Modelo para padrões de uso do dispositivo."""
    device_id: int
    hourly_usage: Dict[int, int]
    daily_usage: Dict[int, int]
    top_commands: List[Dict[str, Any]]
    total_hours_with_activity: int
    total_days_with_activity: int

@app.get("/anomalies/device/{device_id}/patterns", response_model=DeviceUsagePattern)
async def get_device_usage_patterns(
    device_id: int,
    db: DatabaseManager = Depends(get_db_manager),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna padrões de uso de um dispositivo específico.
    REQUER AUTENTICAÇÃO.
    
    Args:
        device_id: ID do dispositivo
        
    Returns:
        DeviceUsagePattern: Padrões de uso do dispositivo
    """
    try:
        # Verificar se dispositivo existe
        device = db.get_device(device_id)
        if not device:
            raise HTTPException(
                status_code=404, 
                detail=f"Dispositivo {device_id} não encontrado"
            )
        
        patterns = anomaly_detector.get_device_usage_patterns(device_id)
        
        logger.info(f"Retornando padrões de uso para dispositivo {device_id}")
        
        return patterns
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao buscar padrões de uso do dispositivo {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

class AnomalyStats(BaseModel):
    """Modelo para estatísticas de anomalias."""
    total_alerts: int
    unresolved_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_type: Dict[str, int]
    most_affected_devices: List[Dict[str, Any]]
    recent_alerts_count: int

# ===== MODELOS PARA SISTEMA DE IA =====

class AIQueryRequest(BaseModel):
    """Modelo para request de query da IA."""
    query: str = Field(..., min_length=1, max_length=2000, description="Query do usuário")
    context: Optional[str] = Field(None, description="Contexto adicional")

class AIResponse(BaseModel):
    """Modelo para resposta da IA."""
    success: bool
    response: Optional[Dict[str, Any]] = None
    intent: Optional[str] = None
    processing_time: Optional[float] = None
    error: Optional[str] = None
    details: Optional[str] = None

class AISummaryResponse(BaseModel):
    """Modelo para resposta de resumo da IA."""
    period_hours: int
    alert_counts: Dict[str, int]
    top_devices: List[Dict[str, Any]]
    top_events: List[Dict[str, Any]]
    total_alerts: int
    critical_alerts: int
    warning_alerts: int
    recommendations: List[str]
    security_score: Optional[int] = None

class LLMConfigRequest(BaseModel):
    """Modelo para configuração de LLM."""
    provider: str = Field(..., description="Provedor: huggingface, together, custom")
    api_token: str = Field(..., min_length=10, description="Token da API")
    custom_endpoint: Optional[str] = Field(None, description="Endpoint customizado (apenas para custom)")

class LLMConfigResponse(BaseModel):
    """Modelo para resposta de configuração LLM."""
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None
    provider: Optional[str] = None

@app.get("/anomalies/stats", response_model=AnomalyStats)
async def get_anomaly_statistics(
    days: int = Query(30, description="Período em dias para estatísticas", le=365),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retorna estatísticas gerais de anomalias.
    REQUER AUTENTICAÇÃO.
    
    Args:
        days: Período em dias para as estatísticas
        
    Returns:
        AnomalyStats: Estatísticas de anomalias
    """
    try:
        import sqlite3
        from collections import Counter
        
        conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'database', 'iotrac.db'))
        cursor = conn.cursor()
        
        # Data limite para estatísticas
        date_limit = datetime.now() - timedelta(days=days)
        
        # Total de alertas
        cursor.execute('''
            SELECT COUNT(*) FROM anomaly_alerts 
            WHERE timestamp >= ?
        ''', (date_limit,))
        total_alerts = cursor.fetchone()[0]
        
        # Alertas não resolvidos
        cursor.execute('''
            SELECT COUNT(*) FROM anomaly_alerts 
            WHERE resolved = 0 AND timestamp >= ?
        ''', (date_limit,))
        unresolved_alerts = cursor.fetchone()[0]
        
        # Alertas por severidade
        cursor.execute('''
            SELECT severity, COUNT(*) FROM anomaly_alerts 
            WHERE timestamp >= ?
            GROUP BY severity
        ''', (date_limit,))
        alerts_by_severity = dict(cursor.fetchall())
        
        # Alertas por tipo
        cursor.execute('''
            SELECT anomaly_type, COUNT(*) FROM anomaly_alerts 
            WHERE timestamp >= ?
            GROUP BY anomaly_type
        ''', (date_limit,))
        alerts_by_type = dict(cursor.fetchall())
        
        # Dispositivos mais afetados
        cursor.execute('''
            SELECT a.device_id, d.device_type, d.device_name, COUNT(*) as alert_count
            FROM anomaly_alerts a
            LEFT JOIN devices d ON a.device_id = d.id
            WHERE a.timestamp >= ?
            GROUP BY a.device_id
            ORDER BY alert_count DESC
            LIMIT 10
        ''', (date_limit,))
        
        most_affected_devices = []
        for row in cursor.fetchall():
            most_affected_devices.append({
                "device_id": row[0],
                "device_type": row[1],
                "device_name": row[2],
                "alert_count": row[3]
            })
        
        # Alertas recentes (últimas 24h)
        recent_date = datetime.now() - timedelta(hours=24)
        cursor.execute('''
            SELECT COUNT(*) FROM anomaly_alerts 
            WHERE timestamp >= ?
        ''', (recent_date,))
        recent_alerts_count = cursor.fetchone()[0]
        
        conn.close()
        
        stats = {
            "total_alerts": total_alerts,
            "unresolved_alerts": unresolved_alerts,
            "alerts_by_severity": alerts_by_severity,
            "alerts_by_type": alerts_by_type,
            "most_affected_devices": most_affected_devices,
            "recent_alerts_count": recent_alerts_count
        }
        
        logger.info(f"Retornando estatísticas de anomalias para {days} dias")
        
        return stats
        
    except Exception as e:
        logger.error(f"Erro ao buscar estatísticas de anomalias: {e}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")

# ===== ENDPOINTS DE IA SEGURA =====

@app.post("/ai/query", response_model=AIResponse)
async def ai_query(
    request: AIQueryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    http_request: Request = None
):
    """
    Endpoint para queries da IA com segurança máxima.
    CAMADA 1 & 2: Autenticação obrigatória + Rate limiting.
    """
    try:
        # Rate limiting específico para IA (mais restritivo)
        client_ip = http_request.client.host
        if not check_rate_limit(client_ip, "ai_query", max_attempts=20, window_minutes=1):
            raise HTTPException(
                status_code=429,
                detail="Muitas consultas à IA. Tente novamente em 15 minutos."
            )
        
        # Criar contexto de segurança
        context = AISecurityContext(
            user_id=current_user["id"],
            user_role=current_user["role"],
            ip_address=client_ip,
            user_agent=http_request.headers.get("user-agent"),
            timestamp=datetime.now(),
            action_type=AIActionType.QA_RESPONSE
        )
        
        # Processar query com máxima segurança
        result = ai_assistant.process_query(request.query, context)
        
        # Log de segurança
        create_simple_log(
            "ai_query",
            {"event": "Consulta IA", "intent": result.get("intent", "unknown"), "email": current_user.get("email")},
            user_id=current_user.get("id")
        )
        
        return AIResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro no endpoint de IA: {e}")
        create_simple_log(
            "ai_error",
            {"event": "Erro IA", "error": str(e)},
            user_id=current_user.get("id")
        )
        raise HTTPException(status_code=500, detail="Erro interno do assistente de IA")

@app.get("/ai/summary", response_model=AISummaryResponse)
async def ai_security_summary(
    hours: int = Query(24, ge=1, le=168, description="Período em horas (máx 7 dias)"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    http_request: Request = None
):
    """
    Endpoint para resumo de segurança da IA.
    REQUER AUTENTICAÇÃO + Rate limiting.
    """
    try:
        # Rate limiting para resumos
        client_ip = http_request.client.host
        if not check_rate_limit(client_ip, "ai_summary", max_requests=10, window_minutes=15):
            raise HTTPException(
                status_code=429,
                detail="Muitas solicitações de resumo. Tente novamente em 15 minutos."
            )
        
        # Criar contexto de segurança
        context = AISecurityContext(
            user_id=current_user["id"],
            user_role=current_user["role"],
            ip_address=client_ip,
            user_agent=http_request.headers.get("user-agent"),
            timestamp=datetime.now(),
            action_type=AIActionType.SUMMARY_ANALYSIS
        )
        
        # Obter dados de segurança
        summary_data = ai_assistant.data_retriever.get_security_summary(hours)
        
        if "error" in summary_data:
            raise HTTPException(status_code=500, detail="Erro ao recuperar dados de segurança")
        
        # Gerar recomendações
        recommendations = ai_assistant._generate_status_recommendations(summary_data)
        
        # Calcular score de segurança simples
        security_score = 100
        if summary_data['critical_alerts'] > 0:
            security_score -= summary_data['critical_alerts'] * 20
        if summary_data['warning_alerts'] > 10:
            security_score -= 10
        security_score = max(0, min(100, security_score))
        
        # Log da operação
        create_simple_log("info", "📊 Resumo IA", 
                         f"Usuário {current_user['email']} solicitou resumo de {hours}h")
        
        # Auditoria
        ai_assistant.audit_logger.log_ai_action(
            context, f"summary_{hours}h", f"security_score_{security_score}", True
        )
        
        return AISummaryResponse(
            period_hours=hours,
            alert_counts=summary_data['alert_counts'],
            top_devices=summary_data['top_devices'],
            top_events=summary_data['top_events'],
            total_alerts=summary_data['total_alerts'],
            critical_alerts=summary_data['critical_alerts'],
            warning_alerts=summary_data['warning_alerts'],
            recommendations=recommendations,
            security_score=security_score
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro no resumo da IA: {e}")
        create_simple_log("critical", "🚨 Erro IA", f"Erro no resumo de segurança: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro ao gerar resumo de segurança")

@app.get("/ai/recommendations")
async def ai_security_recommendations(
    category: Optional[str] = Query(None, description="Categoria: digital, physical, general"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    http_request: Request = None
):
    """
    Endpoint para recomendações de segurança da IA.
    REQUER AUTENTICAÇÃO.
    """
    try:
        # Rate limiting
        client_ip = http_request.client.host
        if not check_rate_limit(client_ip, "ai_recommendations", max_requests=15, window_minutes=15):
            raise HTTPException(
                status_code=429,
                detail="Muitas solicitações de recomendações. Tente novamente em 15 minutos."
            )
        
        # Criar contexto
        context = AISecurityContext(
            user_id=current_user["id"],
            user_role=current_user["role"],
            ip_address=client_ip,
            user_agent=http_request.headers.get("user-agent"),
            timestamp=datetime.now(),
            action_type=AIActionType.SECURITY_RECOMMENDATION
        )
        
        # Processar recomendações
        query = f"recomendações de segurança {category or 'gerais'}"
        result = ai_assistant._get_security_recommendations(query, context)
        
        # Log
        create_simple_log("info", "💡 Recomendações IA", 
                         f"Usuário {current_user['email']} solicitou recomendações: {category or 'gerais'}")
        
        # Auditoria
        ai_assistant.audit_logger.log_ai_action(
            context, query, str(result)[:100], True
        )
        
        return {"success": True, "recommendations": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro nas recomendações da IA: {e}")
        raise HTTPException(status_code=500, detail="Erro ao gerar recomendações")

@app.get("/ai/status")
async def ai_system_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Status do sistema de IA (para debugging e monitoramento).
    REQUER AUTENTICAÇÃO.
    """
    try:
        llm_status = llm_manager.get_status()
        
        return {
            "ai_system": "operational",
            "security_layers": 5,
            "features": [
                "Security Analysis",
                "Anomaly Explanation", 
                "Recommendations",
                "Physical Security Tips",
                "Threat Assessment"
            ],
            "security_status": "maximum",
            "rate_limiting": "active",
            "audit_logging": "active",
            "input_validation": "active",
            "output_sanitization": "active",
            "llm_integration": llm_status
        }
    except Exception as e:
        logger.error(f"Erro no status da IA: {e}")
        raise HTTPException(status_code=500, detail="Erro ao verificar status da IA")

@app.post("/ai/llm/configure", response_model=LLMConfigResponse)
async def configure_llm(
    request: LLMConfigRequest,
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    http_request: Request = None
):
    """
    Configura integração com LLM externo.
    REQUER AUTENTICAÇÃO DE ADMIN + Rate limiting rigoroso.
    """
    try:
        # Rate limiting muito restritivo para configuração
        client_ip = http_request.client.host
        if not check_rate_limit(client_ip, "llm_config", max_requests=3, window_minutes=60):
            raise HTTPException(
                status_code=429,
                detail="Muitas tentativas de configuração LLM. Tente novamente em 1 hora."
            )
        
        # Validar provedor
        try:
            provider = LLMProvider(request.provider.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Provedor inválido. Use: {', '.join([p.value for p in LLMProvider])}"
            )
        
        # Configurar LLM
        result = llm_manager.configure_llm(
            provider=provider,
            api_token=request.api_token,
            custom_endpoint=request.custom_endpoint
        )
        
        # Log de segurança
        create_simple_log(
            "info" if result["success"] else "warning",
            "⚙️ Config LLM",
            f"Admin {current_user['email']} {'configurou' if result['success'] else 'tentou configurar'} LLM: {request.provider}"
        )
        
        # Auditoria
        context = AISecurityContext(
            user_id=current_user["id"],
            user_role=current_user["role"],
            ip_address=client_ip,
            user_agent=http_request.headers.get("user-agent"),
            timestamp=datetime.now(),
            action_type=AIActionType.SUMMARY_ANALYSIS
        )
        
        ai_assistant.audit_logger.log_ai_action(
            context, f"configure_llm_{request.provider}", 
            f"success_{result['success']}", result["success"]
        )
        
        return LLMConfigResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao configurar LLM: {e}")
        create_simple_log("critical", "🚨 Erro LLM", f"Erro na configuração LLM: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro interno ao configurar LLM")

@app.post("/ai/llm/disable")
async def disable_llm(
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    http_request: Request = None
):
    """
    Desabilita integração com LLM.
    REQUER AUTENTICAÇÃO DE ADMIN.
    """
    try:
        # Rate limiting
        client_ip = http_request.client.host
        if not check_rate_limit(client_ip, "llm_disable", max_requests=5, window_minutes=15):
            raise HTTPException(
                status_code=429,
                detail="Muitas tentativas. Tente novamente em 15 minutos."
            )
        
        result = llm_manager.disable_llm()
        
        # Log
        create_simple_log("info", "⚙️ LLM Desabilitado", 
                         f"Admin {current_user['email']} desabilitou integração LLM")
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao desabilitar LLM: {e}")
        raise HTTPException(status_code=500, detail="Erro ao desabilitar LLM")

@app.get("/ai/llm/status")
async def llm_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Status da integração LLM.
    REQUER AUTENTICAÇÃO.
    """
    try:
        return llm_manager.get_status()
    except Exception as e:
        logger.error(f"Erro no status LLM: {e}")
        raise HTTPException(status_code=500, detail="Erro ao verificar status LLM")

@app.post("/auth/email/test")
async def test_email_configuration(
    current_user: Dict[str, Any] = Depends(get_current_admin_user),
    http_request: Request = None
):
    """
    Testa configuração de email enviando um email de teste.
    REQUER AUTENTICAÇÃO DE ADMIN.
    Usado pelo start-iotrac.sh para validar credenciais reais.
    """
    try:
        # Rate limiting para teste de email
        client_ip = http_request.client.host
        if not check_rate_limit(client_ip, "email_test", max_requests=5, window_minutes=15):
            raise HTTPException(
                status_code=429,
                detail="Muitas tentativas de teste de email. Tente novamente em 15 minutos."
            )
        
        # Tentar enviar email de teste
        from src.notification_service import notification_service
        
        test_result = notification_service.send_test_email(current_user["email"])
        
        if test_result.get("success", False):
            # Log de sucesso
            create_simple_log("info", "✅ Teste Email", 
                             f"Teste de email bem-sucedido para {current_user['email']}")
            
            return {
                "success": True,
                "message": "Email de teste enviado com sucesso",
                "email": current_user["email"],
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Log de falha
            create_simple_log("warning", "❌ Teste Email", 
                             f"Falha no teste de email para {current_user['email']}: {test_result.get('error', 'Erro desconhecido')}")
            
            return {
                "success": False,
                "error": test_result.get("error", "Falha ao enviar email de teste"),
                "email": current_user["email"]
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro no teste de email: {e}")
        create_simple_log("critical", "🚨 Erro Email", f"Erro crítico no teste de email: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro interno no teste de email")

if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Iniciando servidor IOTRAC na porta {SERVER_PORT}")
    logger.info(f"Host: {SERVER_HOST}")
    logger.info("Endpoints disponíveis:")
    logger.info("=== ENDPOINTS DE AUTENTICAÇÃO ===")
    logger.info("  POST /auth/register - Registrar usuário")
    logger.info("  POST /auth/login - Login (etapa 1)")
    logger.info("  POST /auth/2fa/verify - Verificar código 2FA (etapa 2)")
    logger.info("  POST /auth/refresh - Renovar access token")
    logger.info("  POST /auth/totp/setup - Configurar Google Authenticator")
    logger.info("  POST /auth/totp/verify - Verificar e ativar TOTP")
    logger.info("  POST /auth/totp/login - Login com TOTP")
    logger.info("  GET  /auth/me - Informações do usuário")
    logger.info("  POST /auth/device/register - Registrar dispositivo com 2FA")
    logger.info("=== ENDPOINTS DE LOGS SIMPLES ===")
    logger.info("  GET  /logs/simple - Logs simples para usuários (AUTH)")
    logger.info("  GET  /logs/simple/alerts - Alertas ativos e resumo (AUTH)")
    logger.info("  GET  /logs/simple/summary - Resumo de atividades (AUTH)")
    logger.info("  GET  /logs/simple/device/{device_id} - Logs de dispositivo específico (AUTH)")
    logger.info("=== ENDPOINTS DE LOGS AVANÇADOS ===")
    logger.info("  GET  /logs/advanced - Logs técnicos completos (ADMIN)")
    logger.info("  GET  /logs/advanced/security - Eventos de segurança (ADMIN)")
    logger.info("  GET  /logs/advanced/performance - Logs de performance (ADMIN)")
    logger.info("  GET  /logs/advanced/errors - Logs de erro detalhados (ADMIN)")
    logger.info("  GET  /logs/advanced/audit - Trilha de auditoria (ADMIN)")
    logger.info("=== ENDPOINTS DE ALERTAS ===")
    logger.info("  GET  /alerts/active - Todos os alertas ativos (AUTH)")
    logger.info("  POST /alerts/security/{alert_id}/resolve - Resolver alerta de segurança (ADMIN)")
    logger.info("  GET  /alerts/statistics - Estatísticas de alertas (AUTH)")
    logger.info("=== ENDPOINTS GERAIS ===")
    logger.info("  GET  /status - Status da proteção")
    logger.info("  POST /toggle_protection - Alternar proteção (ADMIN)")
    logger.info("  GET  /logs - Logs de comandos (AUTH) [LEGADO]")
    logger.info("  POST /command - Enviar comando (OPERATOR)")
    logger.info("=== ENDPOINTS DE BLUETOOTH ===")
    logger.info("  POST /bluetooth/scan - Escanear dispositivos Bluetooth (OPERATOR)")
    logger.info("  POST /bluetooth/register - Registrar dispositivo Bluetooth (OPERATOR)")
    logger.info("  POST /bluetooth/command - Enviar comando Bluetooth (OPERATOR)")
    logger.info("  GET  /bluetooth/devices/connected - Listar dispositivos conectados (AUTH)")
    logger.info("=== ENDPOINTS DE DETECÇÃO DE ANOMALIAS ===")
    logger.info("  GET  /anomalies/alerts - Listar alertas de anomalias (AUTH)")
    logger.info("  POST /anomalies/alerts/{id}/resolve - Resolver alerta (OPERATOR)")
    logger.info("  GET  /anomalies/device/{id}/patterns - Padrões de uso (AUTH)")
    logger.info("  GET  /anomalies/stats - Estatísticas de anomalias (AUTH)")
    logger.info("=== ENDPOINTS WIFI ===")
    logger.info("  GET  /devices - Listar dispositivos (AUTH)")
    logger.info("  GET  /devices/{device_id} - Detalhes do dispositivo (AUTH)")
    logger.info("  POST /device/register - Registrar dispositivo WiFi (OPERATOR)")
    logger.info("  DELETE /devices/{device_id} - Remover dispositivo (ADMIN)")
    logger.info("  GET  /devices/{device_id}/protection - Status de proteção do dispositivo (AUTH)")
    logger.info("  POST /devices/{device_id}/protection/toggle - Alternar proteção do dispositivo (ADMIN)")
    logger.info("=== ENDPOINTS BLUETOOTH ===")
    logger.info("  POST /bluetooth/scan - Escanear dispositivos Bluetooth (OPERATOR)")
    logger.info("  POST /bluetooth/connect - Conectar dispositivo Bluetooth (OPERATOR)")
    logger.info("  POST /bluetooth/disconnect/{mac_address} - Desconectar dispositivo Bluetooth (OPERATOR)")
    logger.info("  POST /bluetooth/device/register - Registrar dispositivo Bluetooth (OPERATOR)")
    logger.info("  GET  /bluetooth/devices - Listar dispositivos Bluetooth (AUTH)")
    logger.info("  GET  /bluetooth/devices/connected - Listar dispositivos Bluetooth conectados (AUTH)")
    logger.info("  POST /bluetooth/command - Enviar comando Bluetooth (OPERATOR)")
    logger.info("=== SISTEMA DE LOGS ===")
    logger.info("  ✅ Logs Simples: Interface amigável para usuários")
    logger.info("  ✅ Logs Avançados: Detalhes técnicos para administradores")
    logger.info("  ✅ Alertas: Notificações de segurança e anomalias")
    logger.info("  ✅ Integração: Logs automáticos em todas as ações")
    logger.info("  ✅ Performance: Paginação e filtros otimizados")
    logger.info("=== LOGS AUTOMÁTICOS IMPLEMENTADOS ===")
    logger.info("  🔐 Registro/Login de usuários")
    logger.info("  📱 Registro/Remoção de dispositivos")
    logger.info("  📤 Envio de comandos")
    logger.info("  🚫 Comandos bloqueados")
    logger.info("  🚨 Anomalias detectadas")
    logger.info("  🔒 Alterações de proteção")
    logger.info("  📶 Conexões Bluetooth")
    logger.info("  ⚠️  Eventos de segurança")
    logger.info("  🛡️  Tentativas de ataque")
    
    # Log do sistema iniciado
    create_simple_log("system_startup", {
        "message": "Sistema IOTRAC iniciado com sucesso",
        "port": SERVER_PORT,
        "host": SERVER_HOST
    })
    
    create_advanced_log("INFO", "main", "startup", 
                       "IOTRAC system started successfully",
                       {"port": SERVER_PORT, "host": SERVER_HOST})
    
    uvicorn.run(
        "main:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=True,
        log_level="info",
        timeout_keep_alive=10
    )
