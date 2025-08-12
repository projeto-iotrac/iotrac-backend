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
from fastapi import HTTPException

# Configuração de logging centralizada
setup_logging()
logger = logging.getLogger(__name__)

# Caminho absoluto do banco de dados na raiz do projeto
DATABASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'database', 'iotrac.db'))
VALID_STATUSES = {"pending", "success", "error", "blocked"}

class DatabaseManager:
    """
    Classe para gerenciar o banco de dados SQLite da aplicação IOTRAC.
    Responsável pela criação de tabelas, inserção de logs e consultas.
    UNIFICADO: Usa o mesmo banco de dados que device_manager.py (iotrac.db)
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
        Habilita WAL mode para melhor performance e concorrência.
        
        Returns:
            sqlite3.Connection: Conexão com o banco SQLite
        """
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        
        # Habilitar WAL mode para melhor performance
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=memory")
            conn.commit()
            logger.debug("WAL mode habilitado no SQLite")
        except Exception as e:
            logger.warning(f"Erro ao configurar WAL mode: {e}")
        
        return conn
    
    def init_database(self) -> None:
        """
        Inicializa o banco de dados criando as tabelas necessárias se não existirem.
        Cria as tabelas: devices (se não existir), device_logs e protection_config
        UNIFICADO: Mantém compatibilidade com device_manager.py
        """
        try:
            cursor = self.conn.cursor()
            
            # Tabela de dispositivos registrados (compatível com device_manager.py + Bluetooth)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_type TEXT NOT NULL,
                    ip_address TEXT UNIQUE,
                    mac_address TEXT UNIQUE,
                    connection_type TEXT NOT NULL DEFAULT 'wifi',
                    device_name TEXT,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    protection_enabled BOOLEAN DEFAULT 1,
                    is_connected BOOLEAN DEFAULT 0,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CHECK (connection_type IN ('wifi', 'bluetooth')),
                    CHECK ((connection_type = 'wifi' AND ip_address IS NOT NULL) OR 
                           (connection_type = 'bluetooth' AND mac_address IS NOT NULL))
                )
            ''')
            
            # Adicionar colunas Bluetooth se não existirem (para compatibilidade)
            bluetooth_columns = [
                ("mac_address", "TEXT UNIQUE"),
                ("connection_type", "TEXT NOT NULL DEFAULT 'wifi'"),
                ("device_name", "TEXT"),
                ("protection_enabled", "BOOLEAN DEFAULT 1"),
                ("is_connected", "BOOLEAN DEFAULT 0"),
                ("last_seen", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            ]
            
            for column_name, column_definition in bluetooth_columns:
                try:
                    cursor.execute(f"ALTER TABLE devices ADD COLUMN {column_name} {column_definition}")
                except sqlite3.OperationalError:
                    # Coluna já existe, ignorar erro
                    pass
            
            # Atualizar constraint para permitir ip_address NULL para dispositivos Bluetooth
            # SQLite não suporta ALTER CONSTRAINT, então vamos garantir via validação no código
            
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
                """SELECT id, device_type, ip_address, mac_address, device_name, 
                          connection_type, is_connected, last_seen, registered_at, protection_enabled 
                   FROM devices WHERE id = ?""",
                (device_id,)
            )
            row = cursor.fetchone()
            
            if row:
                return {
                    "id": row[0],
                    "device_type": row[1],
                    "ip_address": row[2],
                    "mac_address": row[3],
                    "device_name": row[4],
                    "connection_type": row[5],
                    "is_connected": bool(row[6]) if row[6] is not None else False,
                    "last_seen": row[7],
                    "registered_at": row[8],
                    "protection_enabled": bool(row[9]) if row[9] is not None else True
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
                "SELECT id, device_type, ip_address, registered_at, protection_enabled FROM devices ORDER BY id"
            )
            rows = cursor.fetchall()
            
            return [
                {
                    "id": row[0],
                    "device_type": row[1],
                    "ip_address": row[2],
                    "registered_at": row[3],
                    "protection_enabled": bool(row[4]) if row[4] is not None else True
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

    def add_device(self, device_data: Dict[str, Any]) -> int:
        """
        Adiciona um novo dispositivo ao banco de dados.
        
        Args:
            device_data (Dict[str, Any]): Dados do dispositivo a ser adicionado
            
        Returns:
            int: ID do dispositivo inserido
        """
        try:
            return self.insert_device(device_data["device_type"], device_data["ip_address"])
        except sqlite3.IntegrityError:
            logger.warning(f"IP {device_data['ip_address']} já está registrado")
            raise HTTPException(status_code=400, detail=f"IP {device_data['ip_address']} já está registrado")
        except Exception as e:
            logger.error(f"Erro ao adicionar dispositivo: {e}")
            raise HTTPException(status_code=500, detail=f"Erro ao adicionar dispositivo: {str(e)}")

    def get_device_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Busca um dispositivo pelo endereço IP.
        
        Args:
            ip_address (str): Endereço IP do dispositivo
            
        Returns:
            Optional[Dict[str, Any]]: Dados do dispositivo ou None se não encontrado
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id, device_type, ip_address, registered_at FROM devices WHERE ip_address = ?",
                (ip_address,)
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
            logger.error(f"Erro ao buscar dispositivo por IP: {e}")
            raise

    def delete_device(self, device_id: int) -> None:
        """
        Remove um dispositivo do banco de dados.
        
        Args:
            device_id (int): ID do dispositivo a ser removido
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            self.conn.commit()
            
            if cursor.rowcount == 0:
                raise ValueError(f"Dispositivo {device_id} não encontrado")
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao remover dispositivo: {e}")
            raise

    def get_device_protection_status(self, device_id: int) -> bool:
        """
        Retorna o status de proteção de um dispositivo específico.
        
        Args:
            device_id (int): ID do dispositivo
            
        Returns:
            bool: True se a proteção estiver ativa, False caso contrário
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT protection_enabled FROM devices WHERE id = ?", (device_id,))
            row = cursor.fetchone()
            return bool(row[0]) if row and row[0] is not None else True
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar status de proteção do dispositivo {device_id}: {e}")
            return True  # Por padrão, proteção ativa
    
    def toggle_device_protection(self, device_id: int) -> bool:
        """
        Alterna o status de proteção de um dispositivo específico.
        
        Args:
            device_id (int): ID do dispositivo
            
        Returns:
            bool: Novo status da proteção
        """
        try:
            current_status = self.get_device_protection_status(device_id)
            new_status = not current_status
            
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE devices SET protection_enabled = ? WHERE id = ?",
                (1 if new_status else 0, device_id)
            )
            self.conn.commit()
            
            status = "ativada" if new_status else "desativada"
            logger.info(f"Proteção do dispositivo {device_id} {status}")
            
            return new_status
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao alternar proteção do dispositivo {device_id}: {e}")
            raise

    # ===== MÉTODOS ESPECÍFICOS PARA BLUETOOTH =====
    
    def insert_bluetooth_device(self, device_type: str, mac_address: str, device_name: Optional[str] = None) -> int:
        """
        Insere um novo dispositivo Bluetooth na tabela devices.
        
        Args:
            device_type (str): Tipo do dispositivo (ex: "lâmpada", "sensor", "speaker")
            mac_address (str): Endereço MAC do dispositivo Bluetooth
            device_name (Optional[str]): Nome do dispositivo (opcional)
            
        Returns:
            int: ID do dispositivo inserido
            
        Raises:
            sqlite3.IntegrityError: Se o MAC address já estiver registrado
        """
        if not device_type or not mac_address:
            logger.error("Campos obrigatórios para dispositivo Bluetooth não informados")
            raise ValueError("Campos obrigatórios: device_type e mac_address")
            
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """INSERT INTO devices (device_type, mac_address, connection_type, device_name, is_connected, last_seen) 
                   VALUES (?, ?, 'bluetooth', ?, 0, CURRENT_TIMESTAMP)""",
                (device_type, mac_address, device_name)
            )
            self.conn.commit()
            device_id = cursor.lastrowid
            logger.info(f"Dispositivo Bluetooth registrado: {device_type} - {mac_address} (ID: {device_id})")
            return device_id
                
        except sqlite3.IntegrityError:
            logger.warning(f"MAC address {mac_address} já está registrado")
            raise
        except sqlite3.Error as e:
            logger.error(f"Erro ao inserir dispositivo Bluetooth: {e}")
            raise

    def get_bluetooth_devices(self) -> List[Dict[str, Any]]:
        """
        Retorna todos os dispositivos Bluetooth registrados.
        
        Returns:
            List[Dict[str, Any]]: Lista de dispositivos Bluetooth
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """SELECT id, device_type, mac_address, device_name, registered_at, 
                          protection_enabled, is_connected, last_seen 
                   FROM devices WHERE connection_type = 'bluetooth' ORDER BY registered_at DESC"""
            )
            rows = cursor.fetchall()
            
            devices = []
            for row in rows:
                device = {
                    "id": row[0],
                    "device_type": row[1],
                    "mac_address": row[2],
                    "device_name": row[3],
                    "registered_at": row[4],
                    "protection_enabled": bool(row[5]),
                    "is_connected": bool(row[6]),
                    "last_seen": row[7],
                    "connection_type": "bluetooth"
                }
                devices.append(device)
            
            return devices
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar dispositivos Bluetooth: {e}")
            raise

    def get_device_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """
        Busca um dispositivo pelo endereço MAC.
        
        Args:
            mac_address (str): Endereço MAC do dispositivo
            
        Returns:
            Optional[Dict[str, Any]]: Dados do dispositivo ou None se não encontrado
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """SELECT id, device_type, mac_address, device_name, registered_at, 
                          protection_enabled, is_connected, last_seen, connection_type
                   FROM devices WHERE mac_address = ?""",
                (mac_address,)
            )
            row = cursor.fetchone()
            
            if row:
                return {
                    "id": row[0],
                    "device_type": row[1],
                    "mac_address": row[2],
                    "device_name": row[3],
                    "registered_at": row[4],
                    "protection_enabled": bool(row[5]),
                    "is_connected": bool(row[6]),
                    "last_seen": row[7],
                    "connection_type": row[8]
                }
            return None
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar dispositivo por MAC: {e}")
            raise

    def update_device_connection_status(self, device_id: int, is_connected: bool) -> None:
        """
        Atualiza o status de conexão de um dispositivo.
        
        Args:
            device_id (int): ID do dispositivo
            is_connected (bool): Status da conexão
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE devices SET is_connected = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if is_connected else 0, device_id)
            )
            self.conn.commit()
            
            status = "conectado" if is_connected else "desconectado"
            logger.info(f"Dispositivo {device_id} {status}")
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao atualizar status de conexão do dispositivo {device_id}: {e}")
            raise

    def get_connected_bluetooth_devices(self) -> List[Dict[str, Any]]:
        """
        Retorna todos os dispositivos Bluetooth atualmente conectados.
        
        Returns:
            List[Dict[str, Any]]: Lista de dispositivos Bluetooth conectados
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """SELECT id, device_type, mac_address, device_name, registered_at, 
                          protection_enabled, is_connected, last_seen 
                   FROM devices WHERE connection_type = 'bluetooth' AND is_connected = 1
                   ORDER BY last_seen DESC"""
            )
            rows = cursor.fetchall()
            
            devices = []
            for row in rows:
                device = {
                    "id": row[0],
                    "device_type": row[1],
                    "mac_address": row[2],
                    "device_name": row[3],
                    "registered_at": row[4],
                    "protection_enabled": bool(row[5]),
                    "is_connected": bool(row[6]),
                    "last_seen": row[7],
                    "connection_type": "bluetooth"
                }
                devices.append(device)
            
            return devices
                
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar dispositivos Bluetooth conectados: {e}")
            raise
    
    def cleanup_old_logs(self, retention_days: int = 30) -> int:
        """
        Remove logs antigos do banco de dados.
        
        Args:
            retention_days (int): Dias de retenção (padrão: 30)
            
        Returns:
            int: Número de logs removidos
        """
        try:
            cursor = self.conn.cursor()
            cutoff_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            cutoff_date = cutoff_date.replace(day=cutoff_date.day - retention_days)
            cutoff_str = cutoff_date.isoformat()
            
            # Limpar device_logs
            cursor.execute("SELECT COUNT(*) FROM device_logs WHERE timestamp < ?", (cutoff_str,))
            device_logs_count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM device_logs WHERE timestamp < ?", (cutoff_str,))
            
            # Limpar simple_logs (se existir)
            try:
                cursor.execute("SELECT COUNT(*) FROM simple_logs WHERE timestamp < ?", (cutoff_str,))
                simple_logs_count = cursor.fetchone()[0]
                cursor.execute("DELETE FROM simple_logs WHERE timestamp < ?", (cutoff_str,))
            except sqlite3.OperationalError:
                simple_logs_count = 0
            
            # Limpar advanced_logs (se existir)
            try:
                cursor.execute("SELECT COUNT(*) FROM advanced_logs WHERE timestamp < ?", (cutoff_str,))
                advanced_logs_count = cursor.fetchone()[0]
                cursor.execute("DELETE FROM advanced_logs WHERE timestamp < ?", (cutoff_str,))
            except sqlite3.OperationalError:
                advanced_logs_count = 0
            
            # Limpar security_events resolvidos (se existir)
            try:
                cursor.execute(
                    "SELECT COUNT(*) FROM security_events WHERE timestamp < ? AND resolved = 1", 
                    (cutoff_str,)
                )
                security_events_count = cursor.fetchone()[0]
                cursor.execute(
                    "DELETE FROM security_events WHERE timestamp < ? AND resolved = 1", 
                    (cutoff_str,)
                )
            except sqlite3.OperationalError:
                security_events_count = 0
            
            self.conn.commit()
            
            total_removed = device_logs_count + simple_logs_count + advanced_logs_count + security_events_count
            
            if total_removed > 0:
                logger.info(f"Limpeza de logs concluída: {total_removed} registros removidos "
                           f"(device_logs: {device_logs_count}, simple_logs: {simple_logs_count}, "
                           f"advanced_logs: {advanced_logs_count}, security_events: {security_events_count})")
            
            # Executar VACUUM para recuperar espaço
            if total_removed > 100:
                cursor.execute("VACUUM")
                logger.info("VACUUM executado para recuperar espaço em disco")
            
            return total_removed
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao limpar logs antigos: {e}")
            raise

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
    """Retorna o status da proteção."""
    return db_manager.get_protection_status()

def cleanup_old_logs(retention_days: int = 30) -> int:
    """Remove logs antigos do banco de dados."""
    return db_manager.cleanup_old_logs(retention_days)

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
