# Guia de Autenticação IOTRAC

Este guia documenta o sistema de autenticação multifatorial (2FA) implementado no backend IOTRAC, incluindo todos os endpoints, fluxos e configurações necessárias.

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Configuração](#configuração)
3. [Endpoints de Autenticação](#endpoints-de-autenticação)
4. [Fluxos de Autenticação](#fluxos-de-autenticação)
5. [Roles e Permissões](#roles-e-permissões)
6. [Testes](#testes)
7. [Integração com Frontend](#integração-com-frontend)

## 🔒 Visão Geral

O sistema implementa:

- **Autenticação multifatorial (2FA)** via SMS/Email
- **Tokens JWT** com expiração de 15 minutos
- **Refresh tokens** com expiração de 30 dias
- **Biometria simulada** para verificação adicional
- **Sistema de roles** (admin, user, device_operator)
- **Logs de auditoria** para todas as ações
- **Proteção contra força bruta** (bloqueio após 5 tentativas)

## ⚙️ Configuração

### 1. Variáveis de Ambiente

Copie o arquivo de exemplo e configure:

```bash
cp config/env.example config/.env
```

Configure as seguintes variáveis no arquivo `.env`:

#### Chaves de Segurança (OBRIGATÓRIAS)
```env
AES_KEY=sua_chave_aes_de_32_bytes_aqui
HMAC_KEY=sua_chave_hmac_de_32_bytes_aqui
JWT_SECRET=sua_chave_jwt_secreta_aqui
```

#### Email (2FA)
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
EMAIL_USER=seu_email@gmail.com
EMAIL_PASSWORD=sua_senha_de_app
EMAIL_FROM=IOTRAC <seu_email@gmail.com>
```

#### SMS (2FA) - Opcional
```env
# Twilio
TWILIO_ACCOUNT_SID=seu_account_sid
TWILIO_AUTH_TOKEN=seu_auth_token
TWILIO_PHONE_NUMBER=+1234567890

# Ou API genérica
SMS_API_URL=https://api.seuprovedor.com/sms/send
SMS_API_KEY=sua_chave_api
```

### 2. Dependências

Instale as novas dependências:

```bash
pip install -r requirements.txt
```

### 3. Banco de Dados

O banco será automaticamente inicializado com as novas tabelas na primeira execução.

## 🔗 Endpoints de Autenticação

### POST /auth/register
Registra um novo usuário no sistema.

**Request:**
```json
{
  "email": "usuario@exemplo.com",
  "password": "MinhaSenh@123",
  "confirm_password": "MinhaSenh@123",
  "full_name": "Nome Completo",
  "phone": "+5511999999999",
  "role": "user"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Usuário registrado com sucesso",
  "user_id": 1,
  "requires_verification": true
}
```

### POST /auth/login
Primeira etapa do login - verifica credenciais e envia código 2FA.

**Request:**
```json
{
  "email": "usuario@exemplo.com",
  "password": "MinhaSenh@123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Código de verificação enviado via email",
  "requires_2fa": true,
  "temp_token": "token_temporario_aqui",
  "user_id": 1
}
```

### POST /auth/2fa/verify
Segunda etapa do login - verifica código 2FA e retorna tokens JWT.

**Request:**
```json
{
  "temp_token": "token_temporario_aqui",
  "code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login realizado com sucesso",
  "access_token": "jwt_access_token_aqui",
  "refresh_token": "refresh_token_aqui",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "id": 1,
    "email": "usuario@exemplo.com",
    "full_name": "Nome Completo",
    "role": "user",
    "two_fa_enabled": true
  }
}
```

### POST /auth/refresh
Renova o access token usando refresh token.

**Request:**
```json
{
  "refresh_token": "refresh_token_aqui"
}
```

**Response:**
```json
{
  "access_token": "novo_jwt_access_token",
  "token_type": "bearer",
  "expires_in": 900
}
```

### GET /auth/me
Retorna informações do usuário autenticado.

**Headers:**
```
Authorization: Bearer jwt_access_token_aqui
```

**Response:**
```json
{
  "id": 1,
  "email": "usuario@exemplo.com",
  "full_name": "Nome Completo",
  "role": "user",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00",
  "last_login": "2024-01-01T12:00:00",
  "phone": "+5511999999999",
  "two_fa_enabled": true
}
```

### POST /auth/biometric/verify
Verifica dados biométricos simulados.

**Headers:**
```
Authorization: Bearer jwt_access_token_aqui
```

**Request:**
```json
{
  "user_id": 1,
  "biometric_data": "hash_dados_biometricos_simulados",
  "device_info": "iPhone 15 Pro"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Biometria verificada com sucesso",
  "verified": true,
  "timestamp": "2024-01-01T12:00:00"
}
```

## 🔄 Fluxos de Autenticação

### Fluxo Completo de Login

```mermaid
sequenceDiagram
    participant F as Frontend
    participant B as Backend
    participant E as Email/SMS
    
    F->>B: POST /auth/login (email, password)
    B->>B: Verificar credenciais
    B->>B: Gerar código 2FA
    B->>E: Enviar código por email/SMS
    B->>F: temp_token + requires_2fa
    
    Note over F: Usuário insere código 2FA
    
    F->>B: POST /auth/2fa/verify (temp_token, code)
    B->>B: Verificar código 2FA
    B->>B: Gerar JWT tokens
    B->>F: access_token + refresh_token
    
    Note over F: Login concluído
```

### Renovação de Token

```mermaid
sequenceDiagram
    participant F as Frontend
    participant B as Backend
    
    Note over F: Access token expirado
    
    F->>B: POST /auth/refresh (refresh_token)
    B->>B: Verificar refresh token
    B->>B: Gerar novo access token
    B->>F: novo access_token
    
    Note over F: Token renovado
```

## 👥 Roles e Permissões

### Roles Disponíveis

1. **admin**: Acesso total ao sistema
2. **device_operator**: Pode operar dispositivos e registrar novos
3. **user**: Acesso básico de leitura

### Matriz de Permissões

| Endpoint | admin | device_operator | user |
|----------|-------|-----------------|------|
| GET /auth/me | ✅ | ✅ | ✅ |
| GET /devices | ✅ | ✅ | ✅ |
| GET /logs | ✅ | ✅ | ✅ |
| POST /command | ✅ | ✅ | ❌ |
| POST /device/register | ✅ | ✅ | ❌ |
| POST /toggle_protection | ✅ | ❌ | ❌ |
| DELETE /devices/{id} | ✅ | ❌ | ❌ |

## 🧪 Testes

### Executar Testes Automatizados

```bash
# Iniciar o servidor
python src/main.py

# Em outro terminal, executar testes
python scripts/test_auth.py
```

### Teste Manual com cURL

```bash
# 1. Registrar usuário
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@iotrac.com",
    "password": "Admin123!@#",
    "confirm_password": "Admin123!@#",
    "full_name": "Admin IOTRAC",
    "role": "admin"
  }'

# 2. Login (etapa 1)
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@iotrac.com",
    "password": "Admin123!@#"
  }'

# 3. Verificar 2FA (etapa 2)
curl -X POST http://localhost:8000/auth/2fa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "temp_token": "TOKEN_TEMPORARIO_AQUI",
    "code": "123456"
  }'

# 4. Usar endpoint autenticado
curl -X GET http://localhost:8000/auth/me \
  -H "Authorization: Bearer JWT_TOKEN_AQUI"
```

## 🔗 Integração com Frontend

### 1. Configuração de Headers

Adicione o token JWT em todas as requisições autenticadas:

```typescript
const headers = {
  'Authorization': `Bearer ${accessToken}`,
  'Content-Type': 'application/json'
};
```

### 2. Gerenciamento de Tokens

```typescript
class AuthService {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  
  async login(email: string, password: string) {
    // Etapa 1: Login
    const response1 = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data1 = await response1.json();
    const tempToken = data1.temp_token;
    
    // Usuário insere código 2FA
    const code = await this.getTwoFactorCode();
    
    // Etapa 2: Verificação 2FA
    const response2 = await fetch('/auth/2fa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ temp_token: tempToken, code })
    });
    
    const data2 = await response2.json();
    this.accessToken = data2.access_token;
    this.refreshToken = data2.refresh_token;
    
    return data2.user;
  }
  
  async refreshAccessToken() {
    const response = await fetch('/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: this.refreshToken })
    });
    
    const data = await response.json();
    this.accessToken = data.access_token;
    
    return data.access_token;
  }
}
```

### 3. Interceptor para Renovação Automática

```typescript
// Interceptor para renovar token automaticamente
axios.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401) {
      try {
        await authService.refreshAccessToken();
        // Repetir requisição original
        return axios.request(error.config);
      } catch {
        // Redirecionar para login
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
```

## 📱 Implementação de Biometria

### Frontend (React Native)

```typescript
import TouchID from 'react-native-touch-id';

const verifyBiometric = async () => {
  try {
    const biometricData = await TouchID.authenticate('Verificar identidade');
    
    // Simular hash dos dados biométricos
    const hash = await crypto.subtle.digest('SHA-256', 
      new TextEncoder().encode(biometricData)
    );
    
    const response = await fetch('/auth/biometric/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user_id: currentUser.id,
        biometric_data: Array.from(new Uint8Array(hash))
          .map(b => b.toString(16).padStart(2, '0')).join(''),
        device_info: 'iPhone 15 Pro'
      })
    });
    
    const result = await response.json();
    return result.verified;
  } catch (error) {
    console.error('Erro na verificação biométrica:', error);
    return false;
  }
};
```

## 🔍 Logs de Auditoria

Todas as ações de autenticação são registradas na tabela `auth_logs`:

- Tentativas de login (sucesso/falha)
- Verificações 2FA
- Renovações de token
- Verificações biométricas
- Ações administrativas

Para consultar logs:

```sql
SELECT * FROM auth_logs 
WHERE user_id = 1 
ORDER BY created_at DESC 
LIMIT 50;
```

## 🚨 Segurança

### Medidas Implementadas

1. **Hash de senhas** com bcrypt
2. **Tokens JWT** com expiração curta (15 min)
3. **Refresh tokens** com hash seguro
4. **Rate limiting** (5 tentativas de login)
5. **Bloqueio temporário** (30 min após 5 falhas)
6. **Logs de auditoria** completos
7. **Validação rigorosa** de entrada
8. **CORS** configurado adequadamente

### Recomendações de Produção

1. Use HTTPS sempre
2. Configure domínios específicos no CORS
3. Use Redis para cache de sessões
4. Implemente rate limiting por IP
5. Configure monitoramento de logs
6. Use secrets manager para chaves
7. Ative alertas de segurança

## 📞 Suporte

Para dúvidas ou problemas:

1. Verifique os logs do servidor
2. Execute o script de teste: `python scripts/test_auth.py`
3. Consulte a documentação automática: `http://localhost:8000/docs`
4. Verifique as configurações no arquivo `.env`

---

**Implementado com ❤️ para IOTRAC**
*Sistema de autenticação multifatorial com JWT e biometria simulada* 