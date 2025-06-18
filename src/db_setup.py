# db_setup.py
# Script para configuração e gerenciamento do banco de dados SQLite da aplicação IOTRAC
# Camada 3 - Gerenciamento de Dispositivos e Logs
# Dependências: sqlite3 (nativo), datetime

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
import logging
from src.config import setup_logging

# Configuração de logging centralizada
setup_logging()
logger = logging.getLogger(__name__)

DATABASE_PATH = "devices.db"
VALID_STATUSES = {"pending", "success", "error", "blocked"}

class DatabaseManager:
    """
    Classe para gerenciar o banco de dados SQLite da aplicação IOTRAC.
    Responsável pela criação de tabelas, inserção de logs e consultas.
    UNIFICADO: Usa o mesmo banco de dados que device_manager.py
    """
    
    def __init__(self, db_path: str = DATABASE_PATH):
        """
        Inicializa o gerenciador de banco de dados.
        
        Args:
            db_path (str): Caminho para o arquivo do banco SQLite
        """
        self.db_path = db_path
        self.conn = self.get_connection()
        self.init_database()
    
    def __del__(self):
        try:
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
        except Exception:
            pass
    
    def get_connection(self) -> sqlite3.Connection:
        """
        Cria e retorna uma conexão com o banco de dados.
        
        Returns:
            sqlite3.Connection: Conexão com o banco SQLite
        """
        return sqlite3.connect(self.db_path, check_same_thread=False)
    
    def init_database(self) -> None:
        """
        Inicializa o banco de dados criando as tabelas necessárias se não existirem.
        Cria as tabelas: devices (se não existir), device_logs e protection_config
        UNIFICADO: Mantém compatibilidade com device_manager.py
        """
        try:
            cursor = self.conn.cursor()
            
            # Tabela de dispositivos registrados (compatível com device_manager.py)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_type TEXT NOT NULL,
                    ip_address TEXT NOT NULL UNIQUE,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de logs de comandos (nova funcionalidade da Camada 3)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    command TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL DEFAULT 'pending',
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            # Tabela de configuração de proteção (nova funcionalidade da Camada 3)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protection_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protection_enabled BOOLEAN DEFAULT 1,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Inserir configuração padrão de proteção se não existir
            cursor.execute('''
                INSERT OR IGNORE INTO protection_config (id, protection_enabled)
                VALUES (1, 1)
            ''')
            
            # Índices para performance
            cursor.execute('''CREATE INDEX IF NOT EXISTS idx_device_logs_device_id ON device_logs(device_id)''')
            cursor.execute('''CREATE INDEX IF NOT EXISTS idx_device_logs_timestamp ON device_logs(timestamp)''')
            
            self.conn.commit()
            logger.info(f"Banco de dados unificado inicializado: {self.db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao inicializar banco de dados: {e}")
            raise
    
    def insert_device(self, device_type: str, ip_address: str) -> int:
        """
        Insere um novo dispositivo na tabela devices.
        COMPATÍVEL: Usa a mesma estrutura que device_manager.py
        
        Args:
            device_type (str): Tipo do dispositivo (ex: "drone", "veículo", "lâmpada")
            ip_address (str): Endereço IP do dispositivo
            
        Returns:
            int: ID do dispositivo inserido
            
        Raises:
            sqlite3.IntegrityError: Se o IP já estiver registrado
        """
        if not device_type or not ip_address:
            logger.error("Campos obrigatórios para dispositivo não informados")
            raise ValueError("Campos obrigatórios: device_type e ip_address")
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO devices (device_type, ip_address) VALUES (?, ?)",
                (device_type, ip_address)
            )
            self.conn.commit()
            device_id = cursor.lastrowid
            logger.info(f"Dispositivo registrado: {device_type} - {ip_address} (ID: {device_id})")
            return device_id
                
        except sqlite3.IntegrityError:
            logger.warning(f"IP {ip_address} já está registrado")
            raise
        except sqlite3.Error as e:
            logger.error(f"Erro ao inserir dispositivo: {e}")
            raise
    
    def get_device(self, device_id: int) -> Optional[Dict[str, Any]]:
        """
        Busca um dispositivo pelo ID.
        COMPATÍVEL: Usa a mesma estrutura que device_manager.py
        
        Args:
            device_id (int): ID do dispositivo
            
        Returns:
            Optional[Dict[str, Any]]: Dados do dispositivo ou None se não encontrado
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, device_type, ip_address, registered_at FROM devices WHERE id = ?",
                (device_id,)
            )
            row = cursor.fetchone()
            
            if row:
                return {
                    "id": row[0],
                    "device_type": row[1],
                    "ip_address": row[2],
                    "registered_at": row[3]
                }
            return None
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar dispositivo: {e}")
            raise
    
    def get_all_devices(self) -> List[Dict[str, Any]]:
        """
        Retorna todos os dispositivos registrados.
        COMPATÍVEL: Usa a mesma estrutura que device_manager.py
        
        Returns:
            List[Dict[str, Any]]: Lista de dispositivos
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, device_type, ip_address, registered_at FROM devices ORDER BY id"
            )
            rows = cursor.fetchall()
            
            return [
                {
                    "id": row[0],
                    "device_type": row[1],
                    "ip_address": row[2],
                    "registered_at": row[3]
                }
                for row in rows
            ]
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar dispositivos: {e}")
            raise
    
    def insert_log(self, device_id: int, command: str, status: str = "pending") -> int:
        """
        Insere um log de comando na tabela device_logs.
        NOVA FUNCIONALIDADE: Logs de comandos da Camada 3
        
        Args:
            device_id (int): ID do dispositivo
            command (str): Comando enviado
            status (str): Status do comando (ex: "success", "blocked", "error")
            
        Returns:
            int: ID do log inserido
        """
        if not command:
            logger.error("Comando não pode ser vazio")
            raise ValueError("Comando não pode ser vazio")
        if status not in VALID_STATUSES:
            logger.error(f"Status inválido: {status}")
            raise ValueError("Status inválido")
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO device_logs (device_id, command, status) VALUES (?, ?, ?)",
                (device_id, command, status)
            )
            self.conn.commit()
            log_id = cursor.lastrowid
            logger.info(f"Log inserido: Device {device_id} - {command} - {status} (ID: {log_id})")
            return log_id
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao inserir log: {e}")
            raise
    
    def get_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retorna os logs de comandos mais recentes.
        NOVA FUNCIONALIDADE: Logs de comandos da Camada 3
        
        Args:
            limit (int): Número máximo de logs a retornar
            
        Returns:
            List[Dict[str, Any]]: Lista de logs
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT dl.id, dl.device_id, d.device_type, d.ip_address, 
                       dl.command, dl.timestamp, dl.status
                FROM device_logs dl
                JOIN devices d ON dl.device_id = d.id
                ORDER BY dl.timestamp DESC
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            
            return [
                {
                    "id": row[0],
                    "device_id": row[1],
                    "device_type": row[2],
                    "ip_address": row[3],
                    "command": row[4],
                    "timestamp": row[5],
                    "status": row[6]
                }
                for row in rows
            ]
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar logs: {e}")
            raise
    
    def get_protection_status(self) -> bool:
        """
        Retorna o status atual da proteção.
        NOVA FUNCIONALIDADE: Controle de proteção da Camada 3
        
        Returns:
            bool: True se a proteção estiver ativa, False caso contrário
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT protection_enabled FROM protection_config WHERE id = 1")
            row = cursor.fetchone()
            return bool(row[0]) if row else True
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar status de proteção: {e}")
            return True  # Por padrão, proteção ativa
    
    def set_protection_status(self, enabled: bool) -> None:
        """
        Define o status da proteção.
        NOVA FUNCIONALIDADE: Controle de proteção da Camada 3
        
        Args:
            enabled (bool): True para ativar, False para desativar
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE protection_config SET protection_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                (1 if enabled else 0,)
            )
            self.conn.commit()
            status = "ativada" if enabled else "desativada"
            logger.info(f"Proteção {status}")
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao atualizar status de proteção: {e}")
            raise
    
    def toggle_protection(self) -> bool:
        """
        Alterna o status da proteção.
        NOVA FUNCIONALIDADE: Controle de proteção da Camada 3
        
        Returns:
            bool: Novo status da proteção
        """
        current_status = self.get_protection_status()
        new_status = not current_status
        self.set_protection_status(new_status)
        return new_status

# Instância global do gerenciador de banco
db_manager = DatabaseManager()

# Funções de conveniência para uso direto
def init_db() -> None:
    """Inicializa o banco de dados unificado."""
    db_manager.init_database()

def insert_device_log(device_id: int, command: str, status: str = "pending") -> int:
    """Insere um log de comando."""
    return db_manager.insert_log(device_id, command, status)

def get_device_by_id(device_id: int) -> Optional[Dict[str, Any]]:
    """Busca um dispositivo pelo ID."""
    return db_manager.get_device(device_id)

def get_protection_enabled() -> bool:
    """Retorna se a proteção está ativa."""
    return db_manager.get_protection_status()

if __name__ == "__main__":
    # Teste da inicialização do banco
    print("Inicializando banco de dados IOTRAC UNIFICADO...")
    print(f"Banco de dados: {DATABASE_PATH}")
    init_db()
    print("Banco de dados unificado inicializado com sucesso!")
    
    # Exemplo de uso
    try:
        # Inserir dispositivo de teste
        device_id = db_manager.insert_device("drone", "192.168.1.100")
        print(f"Dispositivo inserido com ID: {device_id}")
        
        # Inserir log de teste
        log_id = db_manager.insert_log(device_id, "move_up", "success")
        print(f"Log inserido com ID: {log_id}")
        
        # Verificar status de proteção
        protection = db_manager.get_protection_status()
        print(f"Proteção ativa: {protection}")
        
        # Listar dispositivos
        devices = db_manager.get_all_devices()
        print(f"Dispositivos registrados: {len(devices)}")
        
    except Exception as e:
        print(f"Erro durante teste: {e}")
