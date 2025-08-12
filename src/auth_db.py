# auth_db.py
# Extensão do banco de dados para sistema de autenticação com 2FA
# Dependências: sqlite3, bcrypt, datetime

import sqlite3
import bcrypt
import secrets
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging
from src.config import setup_logging
from src.db_setup import DatabaseManager, DATABASE_PATH

# Configuração de logging
setup_logging()
logger = logging.getLogger(__name__)

class AuthDatabaseManager(DatabaseManager):
    """
    Extensão do DatabaseManager para funcionalidades de autenticação.
    Herda todas as funcionalidades de dispositivos e adiciona usuários/2FA.
    """
    
    def __init__(self, db_path: str = DATABASE_PATH):
        super().__init__(db_path)
        self.init_auth_tables()
    
    def init_auth_tables(self) -> None:
        """
        Inicializa as tabelas de autenticação.
        """
        try:
            cursor = self.conn.cursor()
            
            # Tabela de usuários
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    phone TEXT,
                    role TEXT NOT NULL DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    two_fa_enabled BOOLEAN DEFAULT 1,
                    two_fa_secret TEXT,
                    two_fa_backup_codes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    email_verified BOOLEAN DEFAULT 0,
                    phone_verified BOOLEAN DEFAULT 0
                )
            ''')
            
            # Tabela de códigos 2FA temporários
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS two_fa_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    code TEXT NOT NULL,
                    code_type TEXT NOT NULL DEFAULT 'login',
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Tabela de tokens temporários (para login e reset de senha)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS temp_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    token_type TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Tabela de refresh tokens
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Tabela de verificações biométricas removida - sistema simplificado
            
            # Tabela de logs de autenticação
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    success BOOLEAN NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Índices para performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_two_fa_codes_user_id ON two_fa_codes(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_temp_tokens_token ON temp_tokens(token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_logs_user_id ON auth_logs(user_id)')
            
            self.conn.commit()
            logger.info("Tabelas de autenticação inicializadas com sucesso")
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao inicializar tabelas de autenticação: {e}")
            raise
    
    # ===== MÉTODOS DE USUÁRIO =====
    
    def create_user(self, email: str, password: str, full_name: str, 
                   phone: Optional[str] = None, role: str = "user") -> int:
        """
        Cria um novo usuário no sistema.
        
        Args:
            email (str): Email do usuário
            password (str): Senha em texto plano
            full_name (str): Nome completo
            phone (Optional[str]): Telefone (opcional)
            role (str): Role do usuário
            
        Returns:
            int: ID do usuário criado
        """
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO users (email, password_hash, full_name, phone, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (email, password_hash, full_name, phone, role))
            
            self.conn.commit()
            user_id = cursor.lastrowid
            
            logger.info(f"Usuário criado: {email} (ID: {user_id})")
            return user_id
            
        except sqlite3.IntegrityError:
            logger.warning(f"Email {email} já está registrado")
            raise ValueError("Email já está registrado")
        except sqlite3.Error as e:
            logger.error(f"Erro ao criar usuário: {e}")
            raise
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Busca um usuário pelo email.
        
        Args:
            email (str): Email do usuário
            
        Returns:
            Optional[Dict[str, Any]]: Dados do usuário ou None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id, email, password_hash, full_name, phone, role, 
                       is_active, two_fa_enabled, created_at, last_login,
                       failed_login_attempts, locked_until, email_verified, phone_verified
                FROM users WHERE email = ?
            ''', (email.lower(),))
            
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "email": row[1],
                    "password_hash": row[2],
                    "full_name": row[3],
                    "phone": row[4],
                    "role": row[5],
                    "is_active": bool(row[6]),
                    "two_fa_enabled": bool(row[7]),
                    "created_at": row[8],
                    "last_login": row[9],
                    "failed_login_attempts": row[10],
                    "locked_until": row[11],
                    "email_verified": bool(row[12]),
                    "phone_verified": bool(row[13])
                }
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar usuário por email: {e}")
            raise
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Busca um usuário pelo ID.
        
        Args:
            user_id (int): ID do usuário
            
        Returns:
            Optional[Dict[str, Any]]: Dados do usuário ou None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id, email, full_name, phone, role, is_active, 
                       two_fa_enabled, created_at, last_login, email_verified, phone_verified
                FROM users WHERE id = ?
            ''', (user_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "email": row[1],
                    "full_name": row[2],
                    "phone": row[3],
                    "role": row[4],
                    "is_active": bool(row[5]),
                    "two_fa_enabled": bool(row[6]),
                    "created_at": row[7],
                    "last_login": row[8],
                    "email_verified": bool(row[9]),
                    "phone_verified": bool(row[10])
                }
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao buscar usuário por ID: {e}")
            raise
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verifica se a senha está correta.
        
        Args:
            password (str): Senha em texto plano
            password_hash (str): Hash da senha armazenado
            
        Returns:
            bool: True se a senha estiver correta
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.error(f"Erro ao verificar senha: {e}")
            return False
    
    def update_last_login(self, user_id: int) -> None:
        """
        Atualiza o último login do usuário.
        
        Args:
            user_id (int): ID do usuário
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0
                WHERE id = ?
            ''', (user_id,))
            self.conn.commit()
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao atualizar último login: {e}")
            raise
    
    def increment_failed_login(self, user_id: int) -> int:
        """
        Incrementa tentativas de login falhadas.
        
        Args:
            user_id (int): ID do usuário
            
        Returns:
            int: Número atual de tentativas falhadas
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                UPDATE users SET failed_login_attempts = failed_login_attempts + 1
                WHERE id = ?
            ''', (user_id,))
            
            cursor.execute('SELECT failed_login_attempts FROM users WHERE id = ?', (user_id,))
            attempts = cursor.fetchone()[0]
            
            # Bloquear usuário após 5 tentativas
            if attempts >= 5:
                lock_until = datetime.now() + timedelta(minutes=30)
                cursor.execute('''
                    UPDATE users SET locked_until = ? WHERE id = ?
                ''', (lock_until, user_id))
                
            self.conn.commit()
            return attempts
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao incrementar tentativas de login: {e}")
            raise
    
    def is_user_locked(self, user_id: int) -> bool:
        """
        Verifica se o usuário está bloqueado.
        
        Args:
            user_id (int): ID do usuário
            
        Returns:
            bool: True se o usuário estiver bloqueado
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT locked_until FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            
            if row and row[0]:
                lock_until = datetime.fromisoformat(row[0])
                return datetime.now() < lock_until
            return False
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao verificar bloqueio do usuário: {e}")
            return False
    
    # ===== MÉTODOS DE 2FA =====
    
    def generate_2fa_code(self, user_id: int, code_type: str = "login") -> str:
        """
        Gera um código 2FA de 6 dígitos.
        
        Args:
            user_id (int): ID do usuário
            code_type (str): Tipo do código (login, device_registration, etc.)
            
        Returns:
            str: Código de 6 dígitos
        """
        try:
            # Gerar código de 6 dígitos
            code = str(secrets.randbelow(1000000)).zfill(6)
            expires_at = datetime.now() + timedelta(minutes=10)  # Expira em 10 minutos
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO two_fa_codes (user_id, code, code_type, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, code, code_type, expires_at))
            
            self.conn.commit()
            
            logger.info(f"Código 2FA gerado para usuário {user_id} (tipo: {code_type})")
            return code
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao gerar código 2FA: {e}")
            raise
    
    def verify_2fa_code(self, user_id: int, code: str, code_type: str = "login") -> bool:
        """
        Verifica um código 2FA.
        
        Args:
            user_id (int): ID do usuário
            code (str): Código a ser verificado
            code_type (str): Tipo do código
            
        Returns:
            bool: True se o código estiver correto e válido
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id FROM two_fa_codes 
                WHERE user_id = ? AND code = ? AND code_type = ? 
                AND expires_at > CURRENT_TIMESTAMP AND used = 0
            ''', (user_id, code, code_type))
            
            row = cursor.fetchone()
            if row:
                # Marcar código como usado
                cursor.execute('UPDATE two_fa_codes SET used = 1 WHERE id = ?', (row[0],))
                self.conn.commit()
                
                logger.info(f"Código 2FA verificado com sucesso para usuário {user_id}")
                return True
            
            logger.warning(f"Código 2FA inválido para usuário {user_id}")
            return False
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao verificar código 2FA: {e}")
            return False
    
    # ===== MÉTODOS DE TOKENS =====
    
    def create_temp_token(self, user_id: int, token_type: str, expires_minutes: int = 15) -> str:
        """
        Cria um token temporário.
        
        Args:
            user_id (int): ID do usuário
            token_type (str): Tipo do token (temp_login, password_reset, etc.)
            expires_minutes (int): Minutos até expiração
            
        Returns:
            str: Token gerado
        """
        try:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(minutes=expires_minutes)
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO temp_tokens (user_id, token, token_type, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, token, token_type, expires_at))
            
            self.conn.commit()
            
            logger.info(f"Token temporário criado para usuário {user_id} (tipo: {token_type})")
            return token
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao criar token temporário: {e}")
            raise
    
    def verify_temp_token(self, token: str, token_type: str) -> Optional[int]:
        """
        Verifica um token temporário.
        
        Args:
            token (str): Token a ser verificado
            token_type (str): Tipo do token esperado
            
        Returns:
            Optional[int]: ID do usuário se válido, None caso contrário
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT user_id, id FROM temp_tokens 
                WHERE token = ? AND token_type = ? 
                AND expires_at > CURRENT_TIMESTAMP AND used = 0
            ''', (token, token_type))
            
            row = cursor.fetchone()
            if row:
                # Marcar token como usado
                cursor.execute('UPDATE temp_tokens SET used = 1 WHERE id = ?', (row[1],))
                self.conn.commit()
                
                return row[0]  # user_id
            
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao verificar token temporário: {e}")
            return None
    
    def create_refresh_token(self, user_id: int) -> str:
        """
        Cria um refresh token.
        
        Args:
            user_id (int): ID do usuário
            
        Returns:
            str: Refresh token
        """
        try:
            token = secrets.token_urlsafe(64)
            token_hash = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            expires_at = datetime.now() + timedelta(days=30)  # Expira em 30 dias
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, token_hash, expires_at))
            
            self.conn.commit()
            
            logger.info(f"Refresh token criado para usuário {user_id}")
            return token
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao criar refresh token: {e}")
            raise
    
    def verify_refresh_token(self, token: str) -> Optional[int]:
        """
        Verifica um refresh token.
        
        Args:
            token (str): Refresh token
            
        Returns:
            Optional[int]: ID do usuário se válido, None caso contrário
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT user_id, token_hash, id FROM refresh_tokens 
                WHERE expires_at > CURRENT_TIMESTAMP AND is_active = 1
            ''')
            
            rows = cursor.fetchall()
            for row in rows:
                user_id, token_hash, token_id = row
                if bcrypt.checkpw(token.encode('utf-8'), token_hash.encode('utf-8')):
                    # Atualizar último uso
                    cursor.execute('''
                        UPDATE refresh_tokens SET last_used = CURRENT_TIMESTAMP WHERE id = ?
                    ''', (token_id,))
                    self.conn.commit()
                    
                    return user_id
            
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao verificar refresh token: {e}")
            return None
    
    # ===== MÉTODOS DE LOG =====
    
    def log_auth_event(self, user_id: Optional[int], action: str, success: bool, 
                      ip_address: Optional[str] = None, user_agent: Optional[str] = None, 
                      details: Optional[str] = None) -> None:
        """
        Registra evento de autenticação.
        
        Args:
            user_id (Optional[int]): ID do usuário (pode ser None para tentativas falhadas)
            action (str): Ação realizada
            success (bool): Se a ação foi bem-sucedida
            ip_address (Optional[str]): IP do cliente
            user_agent (Optional[str]): User agent
            details (Optional[str]): Detalhes adicionais
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO auth_logs (user_id, action, success, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, action, success, ip_address, user_agent, details))
            
            self.conn.commit()
            
        except sqlite3.Error as e:
            logger.error(f"Erro ao registrar log de autenticação: {e}")

# Instância global do gerenciador de autenticação
auth_db_manager = AuthDatabaseManager() 