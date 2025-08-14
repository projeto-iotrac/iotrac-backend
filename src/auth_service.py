# auth_service.py
# Serviço de autenticação com JWT e 2FA
# Dependências: fastapi, jose, bcrypt

import hashlib
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
from src.config import setup_logging
from src.crypto_utils import JWTAuth
from src.auth_db import AuthDatabaseManager, auth_db_manager
from src.notification_service import NotificationService, notification_service
from src.auth_models import UserRole

# Configuração de logging
setup_logging()
logger = logging.getLogger(__name__)

# Configuração JWT - usando JWTAuth do crypto_utils
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # 15 minutos conforme requisito
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Security scheme
security = HTTPBearer()

class AuthService:
    """
    Serviço de autenticação com suporte a 2FA, JWT e biometria simulada.
    """
    
    def __init__(self, db_manager: AuthDatabaseManager, notification_service: NotificationService):
        self.db = db_manager
        self.notification_service = notification_service
        self.jwt_auth = JWTAuth()
    
    def register_user(self, email: str, password: str, full_name: str, 
                     phone: Optional[str] = None, role: str = "user") -> Dict[str, Any]:
        """
        Registra um novo usuário no sistema.
        
        Args:
            email (str): Email do usuário
            password (str): Senha em texto plano
            full_name (str): Nome completo
            phone (Optional[str]): Telefone (opcional)
            role (str): Role do usuário
            
        Returns:
            Dict[str, Any]: Resultado do registro
        """
        try:
            # Verificar se o email já existe
            existing_user = self.db.get_user_by_email(email)
            if existing_user:
                raise HTTPException(status_code=400, detail="Email já está registrado")
            
            # Validar força da senha
            if not self._validate_password_strength(password):
                raise HTTPException(
                    status_code=400, 
                    detail="Senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula, número e símbolo"
                )
            
            # Criar usuário
            user_id = self.db.create_user(email, password, full_name, phone, role)
            
            # Gerar código de verificação por email
            verification_code = self.db.generate_2fa_code(user_id, "email_verification")
            
            # Enviar email de verificação
            email_sent = self.notification_service.send_2fa_email(
                email, verification_code, full_name
            )
            
            # Log do evento
            self.db.log_auth_event(
                user_id, "user_registration", True, 
                details=f"Usuário registrado com role {role}"
            )
            
            logger.info(f"Usuário registrado: {email} (ID: {user_id})")
            
            return {
                "success": True,
                "message": "Usuário registrado com sucesso",
                "user_id": user_id,
                "requires_verification": True,
                "verification_sent": email_sent
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro ao registrar usuário: {e}")
            raise HTTPException(status_code=500, detail="Erro interno do servidor")
    
    def login_step1(self, email: str, password: str, request: Optional[Request] = None) -> Dict[str, Any]:
        """
        Primeira etapa do login - verifica credenciais e envia código 2FA.
        
        Args:
            email (str): Email do usuário
            password (str): Senha
            request (Optional[Request]): Request HTTP para logs
            
        Returns:
            Dict[str, Any]: Resultado da primeira etapa
        """
        try:
            ip_address = request.client.host if request else None
            user_agent = request.headers.get("user-agent") if request else None
            
            # Buscar usuário
            user = self.db.get_user_by_email(email)
            if not user:
                self.db.log_auth_event(
                    None, "login_attempt", False, ip_address, user_agent,
                    f"Tentativa de login com email inexistente: {email}"
                )
                raise HTTPException(status_code=401, detail="Credenciais inválidas")
            
            # Verificar se usuário está bloqueado
            if self.db.is_user_locked(user["id"]):
                self.db.log_auth_event(
                    user["id"], "login_attempt", False, ip_address, user_agent,
                    "Tentativa de login com usuário bloqueado"
                )
                raise HTTPException(
                    status_code=423, 
                    detail="Usuário temporariamente bloqueado devido a muitas tentativas de login"
                )
            
            # Verificar se usuário está ativo
            if not user["is_active"]:
                self.db.log_auth_event(
                    user["id"], "login_attempt", False, ip_address, user_agent,
                    "Tentativa de login com usuário inativo"
                )
                raise HTTPException(status_code=401, detail="Usuário inativo")
            
            # Verificar senha
            if not self.db.verify_password(password, user["password_hash"]):
                attempts = self.db.increment_failed_login(user["id"])
                self.db.log_auth_event(
                    user["id"], "login_attempt", False, ip_address, user_agent,
                    f"Senha incorreta - tentativa {attempts}"
                )
                raise HTTPException(status_code=401, detail="Credenciais inválidas")
            
            # Senha correta - gerar código 2FA
            code = self.db.generate_2fa_code(user["id"], "login")
            
            # Criar token temporário para o processo de 2FA
            temp_token = self.db.create_temp_token(user["id"], "temp_login", 15)
            
            # Enviar código por email
            notification_sent = False
            notification_method = "email"
            
            if user.get("email"):
                notification_sent = self.notification_service.send_2fa_email(
                    user["email"], code, user["full_name"]
                )
            
            if not notification_sent:
                logger.error(f"Não foi possível enviar código 2FA para usuário {user['email']}")
                raise HTTPException(
                    status_code=500,
                    detail="Erro ao enviar código de verificação. Verifique se o email está configurado."
                )
            
            # Log do evento
            self.db.log_auth_event(
                user["id"], "login_step1", True, ip_address, user_agent,
                f"Primeira etapa do login concluída - código enviado via {notification_method}"
            )
            
            logger.info(f"Login etapa 1 concluída para usuário {user['id']}")
            
            return {
                "success": True,
                "message": f"Código de verificação enviado via {notification_method}",
                "requires_2fa": True,
                "temp_token": temp_token,
                "user_id": user["id"],
                "notification_sent": notification_sent,
                "notification_method": notification_method
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro na etapa 1 do login: {e}")
            raise HTTPException(status_code=500, detail="Erro interno do servidor")
    
    def login_step2(self, temp_token: str, code: str, request: Optional[Request] = None) -> Dict[str, Any]:
        """
        Segunda etapa do login - verifica código 2FA e gera tokens JWT.
        
        Args:
            temp_token (str): Token temporário da primeira etapa
            code (str): Código 2FA
            request (Optional[Request]): Request HTTP para logs
            
        Returns:
            Dict[str, Any]: Tokens JWT e dados do usuário
        """
        try:
            ip_address = request.client.host if request else None
            user_agent = request.headers.get("user-agent") if request else None
            
            # Verificar token temporário
            user_id = self.db.verify_temp_token(temp_token, "temp_login")
            if not user_id:
                raise HTTPException(
                    status_code=401, 
                    detail="Token temporário inválido ou expirado"
                )
            
            # Verificar código 2FA
            if not self.db.verify_2fa_code(user_id, code, "login"):
                self.db.log_auth_event(
                    user_id, "login_2fa", False, ip_address, user_agent,
                    "Código 2FA inválido"
                )
                raise HTTPException(status_code=401, detail="Código de verificação inválido")
            
            # Buscar dados do usuário
            user = self.db.get_user_by_id(user_id)
            if not user:
                raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
            # Gerar tokens JWT
            access_token = self.generate_access_token(user)
            refresh_token = self.db.create_refresh_token(user_id)
            
            # Atualizar último login
            self.db.update_last_login(user_id)
            
            # Log do evento
            self.db.log_auth_event(
                user_id, "login_success", True, ip_address, user_agent,
                "Login concluído com sucesso"
            )
            
            logger.info(f"Login concluído com sucesso para usuário {user_id}")
            
            return {
                "success": True,
                "message": "Login realizado com sucesso",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "full_name": user["full_name"],
                    "role": user["role"],
                    "two_fa_enabled": user["two_fa_enabled"]
                }
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro na etapa 2 do login: {e}")
            raise HTTPException(status_code=500, detail="Erro interno do servidor")
    
    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Renova o access token usando refresh token.
        
        Args:
            refresh_token (str): Refresh token
            
        Returns:
            Dict[str, Any]: Novos tokens
        """
        try:
            # Verificar refresh token
            user_id = self.db.verify_refresh_token(refresh_token)
            if not user_id:
                raise HTTPException(
                    status_code=401, 
                    detail="Refresh token inválido ou expirado"
                )
            
            # Buscar usuário
            user = self.db.get_user_by_id(user_id)
            if not user or not user["is_active"]:
                raise HTTPException(status_code=401, detail="Usuário inativo")
            
            # Gerar novo access token
            access_token = self.generate_access_token(user)
            
            logger.info(f"Access token renovado para usuário {user_id}")
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro ao renovar token: {e}")
            raise HTTPException(status_code=500, detail="Erro interno do servidor")
    
    def setup_totp(self, user_id: int) -> Dict[str, Any]:
        """
        Configura TOTP para um usuário.
        
        Args:
            user_id (int): ID do usuário
            
        Returns:
            Dict[str, Any]: Dados para configuração do TOTP
        """
        try:
            # Verificar se usuário existe
            user = self.db.get_user_by_id(user_id)
            if not user:
                raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
            # Verificar se TOTP já está configurado
            existing_secret = user.get("two_fa_secret")
            if existing_secret and user.get("two_fa_enabled"):
                # TOTP já configurado e ativado - retornar dados existentes
                totp = pyotp.TOTP(existing_secret)
                provisioning_uri = totp.provisioning_uri(
                    name=user["email"],
                    issuer_name="IOTRAC"
                )
                
                # Gerar QR Code com secret existente
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                buffer.seek(0)
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                qr_code_url = f"data:image/png;base64,{qr_code_base64}"
                
                logger.info(f"TOTP já configurado para usuário {user_id} - retornando configuração existente")
                
                return {
                    "secret": existing_secret,
                    "qr_code_url": qr_code_url,
                    "backup_codes": user.get("two_fa_backup_codes", "").split(",") if user.get("two_fa_backup_codes") else [],
                    "app_name": "IOTRAC",
                    "account_name": user["email"],
                    "already_configured": True
                }
            
            # TOTP não configurado ou não ativado - gerar novo
            if not existing_secret:
                # Gerar chave secreta apenas se não existir
                secret = pyotp.random_base32()
                
                # Criar URL para QR Code
                totp = pyotp.TOTP(secret)
                provisioning_uri = totp.provisioning_uri(
                    name=user["email"],
                    issuer_name="IOTRAC"
                )
                
                # Gerar QR Code
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                
                # Converter QR Code para base64
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                buffer.seek(0)
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                qr_code_url = f"data:image/png;base64,{qr_code_base64}"
                
                # Gerar códigos de backup
                backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
                backup_codes_json = ",".join(backup_codes)
                
                # Salvar no banco de dados
                cursor = self.db.conn.cursor()
                cursor.execute('''
                    UPDATE users SET 
                        two_fa_secret = ?,
                        two_fa_backup_codes = ?,
                        two_fa_enabled = 0
                    WHERE id = ?
                ''', (secret, backup_codes_json, user_id))
                self.db.conn.commit()
                
                # Log do evento
                self.db.log_auth_event(
                    user_id, "totp_setup", True,
                    details="TOTP configurado - aguardando primeira verificação"
                )
                
                logger.info(f"TOTP configurado para usuário {user_id}")
                
                return {
                    "secret": secret,
                    "qr_code_url": qr_code_url,
                    "backup_codes": backup_codes,
                    "app_name": "IOTRAC",
                    "account_name": user["email"],
                    "already_configured": False
                }
            else:
                # Secret existe mas 2FA não ativado - retornar configuração para ativação
                totp = pyotp.TOTP(existing_secret)
                provisioning_uri = totp.provisioning_uri(
                    name=user["email"],
                    issuer_name="IOTRAC"
                )
                
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(provisioning_uri)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                buffer.seek(0)
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
                qr_code_url = f"data:image/png;base64,{qr_code_base64}"
                
                logger.info(f"TOTP configurado mas não ativado para usuário {user_id} - retornando para ativação")
                
                return {
                    "secret": existing_secret,
                    "qr_code_url": qr_code_url,
                    "backup_codes": user.get("two_fa_backup_codes", "").split(",") if user.get("two_fa_backup_codes") else [],
                    "app_name": "IOTRAC",
                    "account_name": user["email"],
                    "already_configured": False
                }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro ao configurar TOTP: {e}")
            raise HTTPException(status_code=500, detail="Erro interno do servidor")
    
    def verify_totp_and_enable(self, user_id: int, code: str) -> Dict[str, Any]:
        """
        Verifica código TOTP e ativa o 2FA se correto.
        
        Args:
            user_id (int): ID do usuário
            code (str): Código de 6 dígitos
            
        Returns:
            Dict[str, Any]: Resultado da verificação
        """
        try:
            # Verificar se usuário existe
            user = self.db.get_user_by_id(user_id)
            if not user:
                raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
            secret = user.get("two_fa_secret")
            if not secret:
                raise HTTPException(
                    status_code=400, 
                    detail="TOTP não configurado. Configure primeiro."
                )
            
            # Verificar código TOTP
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(code, valid_window=1)  # Aceita 1 janela de tempo anterior/posterior
            
            if is_valid:
                # Ativar 2FA
                cursor = self.db.conn.cursor()
                cursor.execute('''
                    UPDATE users SET two_fa_enabled = 1 WHERE id = ?
                ''', (user_id,))
                self.db.conn.commit()
                
                # Gerar tokens de acesso
                access_token = self.generate_access_token(user)
                refresh_token = self.generate_refresh_token(user)
                
                message = "TOTP ativado com sucesso! 2FA está agora habilitado."
            else:
                message = "Código TOTP inválido ou expirado"
            
            # Log do evento
            self.db.log_auth_event(
                user_id, "totp_verification", is_valid,
                details=f"Verificação TOTP para ativação: {'aprovada' if is_valid else 'rejeitada'}"
            )
            
            logger.info(f"Verificação TOTP para usuário {user_id}: {'✓' if is_valid else '✗'}")
            
            result = {
                "success": is_valid,
                "message": message
            }
            
            if is_valid:
                result.update({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": 900
                })
            
            return result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro na verificação TOTP: {e}")
            raise HTTPException(status_code=500, detail="Erro interno do servidor")
    
    def verify_totp_login(self, user_id: int, code: str) -> Dict[str, Any]:
        """
        Verifica código TOTP durante o login.
        
        Args:
            user_id (int): ID do usuário
            code (str): Código de 6 dígitos
            
        Returns:
            Dict[str, Any]: Resultado da verificação
        """
        try:
            # Verificar se usuário existe
            user = self.db.get_user_by_id(user_id)
            if not user:
                raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
            secret = user.get("two_fa_secret")
            if not secret or not user.get("two_fa_enabled"):
                raise HTTPException(
                    status_code=400, 
                    detail="TOTP não está configurado ou ativado"
                )
            
            # Verificar se é código de backup
            backup_codes = user.get("two_fa_backup_codes", "").split(",")
            is_backup_code = code.upper() in [bc.strip() for bc in backup_codes if bc.strip()]
            
            is_valid = False
            used_backup = False
            
            if is_backup_code:
                # Usar código de backup
                is_valid = True
                used_backup = True
                
                # Remover código de backup usado
                backup_codes = [bc.strip() for bc in backup_codes if bc.strip() and bc.strip() != code.upper()]
                new_backup_codes = ",".join(backup_codes)
                
                cursor = self.db.conn.cursor()
                cursor.execute('''
                    UPDATE users SET two_fa_backup_codes = ? WHERE id = ?
                ''', (new_backup_codes, user_id))
                self.db.conn.commit()
                
                logger.warning(f"Código de backup usado por usuário {user_id}")
                
            else:
                # Verificar código TOTP normal
                totp = pyotp.TOTP(secret)
                is_valid = totp.verify(code, valid_window=1)
            
            if is_valid:
                # Gerar tokens de acesso
                access_token = self.generate_access_token(user)
                refresh_token = self.generate_refresh_token(user)
                
                if used_backup:
                    message = f"Login realizado com código de backup. Restam {len(backup_codes)} códigos."
                else:
                    message = "Login realizado com sucesso via TOTP"
            else:
                message = "Código TOTP inválido ou expirado"
            
            # Log do evento
            self.db.log_auth_event(
                user_id, "totp_login", is_valid,
                details=f"Login TOTP: {'aprovado' if is_valid else 'rejeitado'} {'(código backup)' if used_backup else ''}"
            )
            
            logger.info(f"Login TOTP para usuário {user_id}: {'✓' if is_valid else '✗'}")
            
            result = {
                "success": is_valid,
                "message": message
            }
            
            if is_valid:
                result.update({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": 900
                })
            
            return result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Erro na verificação TOTP de login: {e}")
            raise HTTPException(status_code=500, detail="Erro interno do servidor")
    
    def generate_access_token(self, user: Dict[str, Any]) -> str:
        """
        Gera um access token JWT.
        
        Args:
            user (Dict[str, Any]): Dados do usuário
            
        Returns:
            str: Access token JWT
        """
        payload = {
            "user_id": user["id"],
            "email": user["email"],
            "role": user["role"],
            "type": "access"
        }
        
        return self.jwt_auth.generate_token(payload, ACCESS_TOKEN_EXPIRE_MINUTES)
    
    def generate_refresh_token(self, user: Dict[str, Any]) -> str:
        """Gera e retorna um refresh token persistido para o usuário."""
        return self.db.create_refresh_token(user["id"])
    
    def verify_access_token(self, token: str) -> Dict[str, Any]:
        """
        Verifica e decodifica um access token.
        
        Args:
            token (str): Access token JWT
            
        Returns:
            Dict[str, Any]: Payload do token
        """
        try:
            payload = self.jwt_auth.verify_token(token)
            
            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Tipo de token inválido")
            
            return payload
            
        except Exception as e:
            logger.error(f"Erro ao verificar access token: {e}")
            raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    
    def _validate_password_strength(self, password: str) -> bool:
        """
        Valida a força da senha.
        
        Args:
            password (str): Senha a ser validada
            
        Returns:
            bool: True se a senha for forte
        """
        if len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        return has_upper and has_lower and has_digit and has_symbol

# Instância global do serviço de autenticação
auth_service = AuthService(auth_db_manager, notification_service)

# Dependency para verificar autenticação
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Dependency para verificar se o usuário está autenticado.
    
    Args:
        credentials: Credenciais HTTP Bearer
        
    Returns:
        Dict[str, Any]: Dados do usuário autenticado
    """
    try:
        payload = auth_service.verify_access_token(credentials.credentials)
        user = auth_db_manager.get_user_by_id(payload["user_id"])
        
        if not user or not user["is_active"]:
            raise HTTPException(status_code=401, detail="Usuário inativo")
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erro ao verificar usuário atual: {e}")
        raise HTTPException(status_code=401, detail="Token inválido")

# Dependency para verificar role de admin
async def get_current_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Dependency para verificar se o usuário é admin.
    
    Args:
        current_user: Usuário atual
        
    Returns:
        Dict[str, Any]: Dados do usuário admin
    """
    if current_user["role"] not in [UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Acesso negado - privilégios de admin necessários")
    
    return current_user

# Dependency para verificar role de operador de dispositivos
async def get_current_device_operator(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Dependency para verificar se o usuário pode operar dispositivos.
    
    Args:
        current_user: Usuário atual
        
    Returns:
        Dict[str, Any]: Dados do usuário operador
    """
    if current_user["role"] not in [UserRole.ADMIN, UserRole.DEVICE_OPERATOR]:
        raise HTTPException(status_code=403, detail="Acesso negado - privilégios de operador necessários")
    
    return current_user 