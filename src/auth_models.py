# auth_models.py
# Modelos Pydantic para sistema de autenticação com 2FA
# Dependências: pydantic, typing

from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    """Roles de usuário no sistema."""
    ADMIN = "admin"
    USER = "user"
    DEVICE_OPERATOR = "device_operator"

class LoginRequest(BaseModel):
    """Modelo para requisição de login."""
    email: str = Field(..., description="Email do usuário")
    password: str = Field(..., min_length=8, description="Senha do usuário")
    
    @validator('email')
    @staticmethod
    def validate_email(v):
        if '@' not in v or '.' not in v:
            raise ValueError("Email inválido")
        return v.lower()

class LoginResponse(BaseModel):
    """Modelo para resposta de login (primeira etapa)."""
    success: bool
    message: str
    requires_2fa: bool
    temp_token: Optional[str] = None
    user_id: Optional[int] = None

class TwoFARequest(BaseModel):
    """Modelo para requisição de código 2FA."""
    temp_token: str = Field(..., description="Token temporário do login")
    code: str = Field(..., min_length=6, max_length=6, description="Código 2FA de 6 dígitos")
    
    @validator('code')
    @staticmethod
    def validate_code(v):
        if not v.isdigit():
            raise ValueError("Código deve conter apenas números")
        return v

class TwoFAResponse(BaseModel):
    """Modelo para resposta de verificação 2FA."""
    success: bool
    message: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    user: Optional[Dict[str, Any]] = None

class RegisterRequest(BaseModel):
    """Modelo para registro de novo usuário."""
    email: str = Field(..., description="Email do usuário")
    password: str = Field(..., min_length=8, description="Senha (mínimo 8 caracteres)")
    confirm_password: str = Field(..., description="Confirmação da senha")
    full_name: str = Field(..., min_length=2, description="Nome completo")
    phone: Optional[str] = Field(None, description="Telefone (opcional)")
    role: UserRole = Field(UserRole.USER, description="Role do usuário")
    
    @validator('email')
    @staticmethod
    def validate_email(v):
        if '@' not in v or '.' not in v:
            raise ValueError("Email inválido")
        return v.lower()
    
    @validator('confirm_password')
    @staticmethod
    def validate_passwords_match(v, values):
        if 'password' in values and v != values['password']:
            raise ValueError("Senhas não coincidem")
        return v
    
    @validator('phone')
    @staticmethod
    def validate_phone(v):
        if v and (len(v) < 10 or not v.replace('+', '').replace('-', '').replace(' ', '').isdigit()):
            raise ValueError("Telefone inválido")
        return v

class RegisterResponse(BaseModel):
    """Modelo para resposta de registro."""
    success: bool
    message: str
    user_id: Optional[int] = None
    requires_verification: bool = True

class EmailVerificationRequest(BaseModel):
    """Modelo para verificação de email após registro."""
    email: str = Field(..., description="Email do usuário")
    code: str = Field(..., min_length=6, max_length=6, description="Código de verificação enviado por email")

    @validator('email')
    @staticmethod
    def validate_email(v):
        if '@' not in v or '.' not in v:
            raise ValueError("Email inválido")
        return v.lower()

    @validator('code')
    @staticmethod
    def validate_code(v):
        if not v.isdigit():
            raise ValueError("Código deve conter apenas números")
        return v

class EmailVerificationResponse(BaseModel):
    """Resposta da verificação de email."""
    success: bool
    message: str

class EmailResendRequest(BaseModel):
    """Requisição para reenviar código de verificação de email."""
    email: str = Field(..., description="Email do usuário")

    @validator('email')
    @staticmethod
    def validate_email(v):
        if '@' not in v or '.' not in v:
            raise ValueError("Email inválido")
        return v.lower()

class UserInfo(BaseModel):
    """Modelo para informações do usuário."""
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: str
    last_login: Optional[str] = None
    phone: Optional[str] = None
    two_fa_enabled: bool = False

class TokenResponse(BaseModel):
    """Modelo para resposta de token."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutos em segundos

class TOTPSetupRequest(BaseModel):
    """Modelo para configuração inicial do TOTP."""
    pass  # Não precisa de parâmetros, usa o usuário autenticado

class TOTPSetupResponse(BaseModel):
    """Modelo para resposta da configuração TOTP."""
    secret: str = Field(..., description="Chave secreta para configurar no app")
    qr_code_url: str = Field(..., description="URL do QR Code")
    backup_codes: List[str] = Field(..., description="Códigos de backup")
    app_name: str = "IOTRAC"
    account_name: str = Field(..., description="Nome da conta (email do usuário)")

class TOTPVerifyRequest(BaseModel):
    """Modelo para verificação de código TOTP."""
    code: str = Field(..., min_length=6, max_length=6, description="Código de 6 dígitos do app")
    
    @validator('code')
    @classmethod
    def validate_code(cls, v):
        if not v.isdigit():
            raise ValueError("Código deve conter apenas números")
        return v

class TOTPVerifyResponse(BaseModel):
    """Modelo para resposta da verificação TOTP."""
    success: bool
    message: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: int = 900  # 15 minutos

class TwoFAResendRequest(BaseModel):
    """Reenvio do código 2FA da etapa de login."""
    temp_token: str = Field(..., description="Token temporário da etapa 1 do login")

class SimpleResponse(BaseModel):
    """Resposta simples de sucesso/mensagem."""
    success: bool
    message: str

class RefreshTokenRequest(BaseModel):
    """Modelo para renovação de token."""
    refresh_token: str = Field(..., description="Token de renovação")

class PasswordResetRequest(BaseModel):
    """Modelo para solicitação de reset de senha."""
    email: str = Field(..., description="Email do usuário")

class PasswordResetConfirm(BaseModel):
    """Modelo para confirmação de reset de senha."""
    token: str = Field(..., description="Token de reset")
    new_password: str = Field(..., min_length=8, description="Nova senha")
    confirm_password: str = Field(..., description="Confirmação da nova senha")
    
    @validator('confirm_password')
    @staticmethod
    def validate_passwords_match(v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError("Senhas não coincidem")
        return v

class DeviceRegistrationRequest(BaseModel):
    """Modelo para registro de dispositivo com 2FA."""
    device_type: str = Field(..., description="Tipo do dispositivo")
    ip_address: Optional[str] = Field(None, description="IP do dispositivo (WiFi)")
    mac_address: Optional[str] = Field(None, description="MAC do dispositivo (Bluetooth)")
    connection_type: str = Field("wifi", description="Tipo de conexão (wifi/bluetooth)")
    device_name: Optional[str] = Field(None, description="Nome do dispositivo")
    requires_2fa: bool = Field(True, description="Se requer 2FA para registro")
    
    @validator('connection_type')
    @staticmethod
    def validate_connection_type(v):
        if v not in ['wifi', 'bluetooth']:
            raise ValueError("Tipo de conexão deve ser 'wifi' ou 'bluetooth'")
        return v
    
    @validator('ip_address')
    @staticmethod
    def validate_ip_for_wifi(v, values):
        if values.get('connection_type') == 'wifi' and not v:
            raise ValueError("IP obrigatório para dispositivos WiFi")
        return v
    
    @validator('mac_address')
    @staticmethod
    def validate_mac_for_bluetooth(v, values):
        if values.get('connection_type') == 'bluetooth' and not v:
            raise ValueError("MAC obrigatório para dispositivos Bluetooth")
        return v

class DeviceRegistrationResponse(BaseModel):
    """Modelo para resposta de registro de dispositivo."""
    success: bool
    message: str
    device_id: Optional[int] = None
    requires_2fa_verification: bool = True
    verification_method: str = "email"  # Método de verificação 