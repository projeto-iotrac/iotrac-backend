# IoT Security Module

Este módulo fornece funções e classes para segurança em aplicações IoT, incluindo:
- Criptografia e autenticação de pacotes com AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
- Geração e verificação de tokens JWT para autenticação
- Geração e verificação de assinaturas HMAC-SHA256 para comandos

## Principais Classes e Funções

- **AESCipher**: Criptografa e autentica dados usando AES-256-CBC e HMAC-SHA256. Permite especificar o comprimento da chave HMAC e garante integridade dos dados (Encrypt-then-MAC).
- **JWTAuth**: Gera e verifica tokens JWT para autenticação, usando segredo seguro de variável de ambiente.
- **generate_hmac_key(length=32)**: Gera uma chave HMAC aleatória de comprimento seguro (NUNCA use chaves previsíveis!).
- **generate_hmac(key, message)**: Gera uma assinatura HMAC-SHA256 para uma mensagem.
- **verify_hmac(key, message, signature_hex)**: Verifica a assinatura HMAC-SHA256 de uma mensagem.
- **get_env_var(name)**: Obtém uma variável de ambiente, lançando exceção se não definida.
- **setup_logging(level, log_file)**: Configura o sistema de logging do Python para o módulo.

## Instalação

Requer as bibliotecas:
- cryptography
- pyjwt

Instale com:
```
pip install cryptography pyjwt
```

## Configuração de Logging

Você pode configurar o logging para diferentes níveis e/ou para um arquivo:
```python
from iot_security import setup_logging
setup_logging(level=logging.DEBUG, log_file="iot_security.log")
```

## Variáveis de Ambiente e Exemplos de Chaves

**Nunca armazene segredos (chaves, senhas) no código-fonte!**

O módulo espera que as chaves estejam em variáveis de ambiente:
- `AES_KEY`: Chave AES de 32 bytes (256 bits), codificada em UTF-8 ou base64.
  - Exemplo (32 bytes em UTF-8): `b'0123456789abcdef0123456789abcdef'`
  - Exemplo (base64): `'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='`
- `HMAC_KEY`: Chave HMAC de pelo menos 16 bytes, recomendável 32 bytes, codificada em UTF-8 ou base64.
  - Exemplo (32 bytes em UTF-8): `b'supersecretkeyforhmac1234567890!!'`
  - Exemplo (base64): `'c3VwZXJzZWNyZXRrZXlmb3JobWFjMTIzNDU2Nzg5MCEh'`
- `JWT_SECRET`: Segredo para assinatura de tokens JWT (string forte, pelo menos 16 caracteres).
  - Exemplo: `'minha_senha_super_secreta_123'`

> **Importante:** Sempre gere suas chaves com um gerador criptograficamente seguro, como `os.urandom` ou ferramentas de gerenciamento de segredos. **NUNCA use exemplos, palavras do dicionário ou padrões previsíveis!**

Exemplo de definição no Linux/Mac:
```
export AES_KEY="0123456789abcdef0123456789abcdef"
export HMAC_KEY="supersecretkeyforhmac1234567890!!"
export JWT_SECRET="minha_senha_super_secreta_123"
```
No Windows (cmd):
```
set AES_KEY=0123456789abcdef0123456789abcdef
set HMAC_KEY=supersecretkeyforhmac1234567890!!
set JWT_SECRET=minha_senha_super_secreta_123
```

## Exemplo de Uso Básico

```python
from iot_security import setup_logging, get_env_var, AESCipher, JWTAuth, generate_hmac, verify_hmac
setup_logging(level=logging.INFO)

# Carregar chaves
aes_key = get_env_var('AES_KEY').encode('utf-8')
hmac_key = get_env_var('HMAC_KEY').encode('utf-8')

# Criptografia e autenticação
cipher = AESCipher(aes_key, hmac_key)
mensagem = b"Mensagem IoT confidencial"
iv, ct, mac = cipher.encrypt(mensagem)
plaintext = cipher.decrypt(iv, ct, mac)

# JWT
token = JWTAuth().generate_token({"device_id": 123})
payload = JWTAuth().verify_token(token)

# HMAC simples
sig = generate_hmac(hmac_key, b"comando importante")
valid = verify_hmac(hmac_key, b"comando importante", sig)
```

## Exemplos Avançados e Casos de Uso

### 1. Comunicação Segura entre Dispositivos IoT
```python
# Dispositivo A: envia comando criptografado e autenticado
iv, ciphertext, mac = cipher.encrypt(b"ligar_motor")
# Envia (iv, ciphertext, mac) para o Dispositivo B

# Dispositivo B: recebe e valida
try:
    comando = cipher.decrypt(iv, ciphertext, mac)
    # Executa comando se válido
except Exception as e:
    # Loga tentativa de manipulação ou erro
    logger.warning(f"Falha na validação do comando: {e}")
```

### 2. Autenticação de API com JWT
```python
# Backend gera token JWT para dispositivo autenticado
jwt_auth = JWTAuth()
token = jwt_auth.generate_token({"device_id": "abc123", "role": "sensor"})

# Dispositivo envia token em cada requisição
# Backend valida token antes de processar
try:
    claims = jwt_auth.verify_token(token)
    # Permite acesso se claims válidas
except Exception:
    # Rejeita requisição
    pass
```

### 3. Assinatura e Verificação de Comandos
```python
# Central envia comando assinado
cmd = b"resetar"
sig = generate_hmac(hmac_key, cmd)
# Dispositivo verifica assinatura antes de executar
if verify_hmac(hmac_key, cmd, sig):
    # Executa comando
    pass
else:
    # Rejeita comando
    pass
```

## Testes Unitários e Integração

O módulo inclui testes unitários para todas as funções e classes. Para rodar os testes, altere o bloco final do arquivo para:
```python
if __name__ == "__test__":
    # ...
```
E execute:
```
python iot_security.py
```

> **Recomendação:** Implemente também **testes de integração** para garantir que diferentes partes do sistema (criptografia, autenticação, comunicação entre dispositivos) funcionam corretamente em conjunto no seu ambiente real.

## Práticas Recomendadas de Segurança

- **Gere chaves de forma segura**: Use `os.urandom`, ferramentas de gerenciamento de segredos ou bibliotecas especializadas. Nunca use exemplos ou padrões previsíveis.
- **Rotacione chaves periodicamente**: Troque as chaves de criptografia e HMAC em intervalos regulares ou após suspeita de comprometimento.
- **Valide todos os dados recebidos**: Sempre verifique a integridade e autenticidade dos dados antes de processá-los.
- **Restrinja acesso às chaves**: Armazene chaves em variáveis de ambiente protegidas ou cofres de segredos.
- **Nunca exponha chaves ou payloads sensíveis em logs ou prints.**
- **Monitore e trate exceções**: Implemente logs e alertas para tentativas de uso inválido ou falhas de autenticação.

## Como Contribuir

Contribuições são bem-vindas! Para contribuir:
- Abra um *issue* descrevendo o problema ou sugestão.
- Faça um *fork* do repositório e crie uma branch para sua feature/correção.
- Envie um *pull request* detalhando as mudanças e o motivo.
- Certifique-se de que todos os testes unitários passam antes de enviar o PR.
- Siga o padrão de código PEP8 e mantenha docstrings claras.

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.

## Referências
- [Documentação oficial do PyJWT](https://pyjwt.readthedocs.io/en/stable/)
- [Documentação oficial do cryptography](https://cryptography.io/en/latest/)
- [OWASP: Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)

# IOTRAC - Sistema de Segurança IoT

## 📋 Visão Geral

O IOTRAC é um sistema completo de segurança para aplicações IoT, composto por múltiplas camadas que trabalham em conjunto para fornecer proteção, autenticação e gerenciamento de dispositivos IoT.

## 🏗️ Arquitetura do Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                    IOTRAC - Sistema Completo                │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 1: Crypto Utils (crypto_utils.py)                  │
│  ├── AES-256-CBC Encryption                                │
│  ├── HMAC-SHA256 Authentication                            │
│  └── JWT Token Management                                   │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 2: Device Manager (device_manager.py)              │
│  ├── Registro de Dispositivos                              │
│  ├── Validação de IPs                                      │
│  └── Gerenciamento de Tipos                                │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 3: API Central (main.py + db_setup.py)             │
│  ├── FastAPI Server                                        │
│  ├── Gerenciamento de Comandos                             │
│  ├── Sistema de Logs                                       │
│  └── Controle de Proteção                                  │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 4: Device Interceptor (device_interceptor.py)      │
│  ├── UDP Communication (Drones)                            │
│  └── TCP Communication (Vehicles)                          │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Instalação e Configuração

### 1. Instalar Dependências

```bash
pip install -r requirements.txt
```

### 2. Configurar Variáveis de Ambiente

Copie o arquivo de exemplo e configure suas variáveis:

```bash
cp env.example .env
```

Edite o arquivo `.env` com suas configurações:

```env
# Configurações do servidor
SERVER_PORT=8000
SERVER_HOST=0.0.0.0

# Chaves de segurança (IMPORTANTE: Use chaves seguras em produção)
AES_KEY=your_32_byte_aes_key_here_replace_this
HMAC_KEY=your_32_byte_hmac_key_here_replace_this
JWT_SECRET=your_jwt_secret_key_here_replace_this

# Configurações de logging
LOG_LEVEL=INFO
LOG_FILE=iotrac.log
```

### 3. Inicializar Banco de Dados

```bash
python src/db_setup.py
```

### 4. Executar Testes

```bash
python -m pytest tests/
```

## 🏃‍♂️ Executando a Aplicação

### Iniciar o Servidor Principal (Camada 3)

```bash
python src/main.py
```

O servidor estará disponível em: `http://localhost:8000`

### Interface Swagger

Acesse a documentação interativa da API:
`http://localhost:8000/docs`

## 📡 Endpoints da API (Camada 3)

### 1. Status da Proteção
```http
GET /status
```
**Resposta:**
```json
{
  "protection_enabled": true,
  "timestamp": "2024-01-15T10:30:00"
}
```

### 2. Alternar Proteção
```http
POST /toggle_protection
```
**Resposta:**
```json
{
  "protection_enabled": false,
  "message": "Proteção desativada com sucesso",
  "timestamp": "2024-01-15T10:30:00"
}
```

### 3. Listar Logs
```http
GET /logs?limit=100
```
**Resposta:**
```json
[
  {
    "id": 1,
    "device_id": 1,
    "device_type": "drone",
    "ip_address": "192.168.1.100",
    "command": "move_up",
    "timestamp": "2024-01-15T10:30:00",
    "status": "success"
  }
]
```

### 4. Enviar Comando
```http
POST /command
Content-Type: application/json

{
  "device_id": 1,
  "command": "move_up"
}
```
**Resposta:**
```json
{
  "success": true,
  "message": "Comando 'move_up' enviado para drone com proteção ativa",
  "device_id": 1,
  "command": "move_up",
  "timestamp": "2024-01-15T10:30:00",
  "protection_enabled": true
}
```

### 5. Listar Dispositivos
```http
GET /devices
```
**Resposta:**
```json
[
  {
    "id": 1,
    "device_type": "drone",
    "ip_address": "192.168.1.100",
    "registered_at": "2024-01-15T10:00:00"
  }
]
```

### 6. Registrar Dispositivo (Camada 2)
```http
POST /device/register
Content-Type: application/json

{
  "device_type": "drone",
  "ip_address": "192.168.1.100"
}
```

## 🔐 Sistema de Segurança (Camada 1)

### Criptografia AES-256-CBC
- **Algoritmo:** AES-256 em modo CBC
- **Padding:** PKCS7
- **IV:** Gerado aleatoriamente para cada operação

### Autenticação HMAC-SHA256
- **Função:** HMAC-SHA256 para verificação de integridade
- **Implementação:** Encrypt-then-MAC para máxima segurança

### Comandos Válidos
```python
allowed_commands = [
    "move_up", "move_down", "move_left", "move_right",
    "move_forward", "move_backward", "turn_on", "turn_off",
    "set_speed", "get_status", "emergency_stop"
]
```

## 🗄️ Estrutura do Banco de Dados

### Tabela: `devices`
```sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_type TEXT NOT NULL,
    ip_address TEXT NOT NULL UNIQUE,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Tabela: `device_logs`
```sql
CREATE TABLE device_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    command TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'pending',
    FOREIGN KEY (device_id) REFERENCES devices (id)
);
```

### Tabela: `protection_config`
```sql
CREATE TABLE protection_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protection_enabled BOOLEAN DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔧 Configuração de Dispositivos

### Tipos de Dispositivo Suportados
- **drone:** Comunicação via UDP (porta 5000)
- **veículo:** Comunicação via TCP (porta 5001)
- **outros:** Comunicação via TCP (porta 5002)

### Exemplo de Registro de Dispositivo
```python
from src.db_setup import db_manager

# Registrar drone
device_id = db_manager.insert_device("drone", "192.168.1.100")

# Registrar veículo
vehicle_id = db_manager.insert_device("veículo", "192.168.1.101")
```

## 📊 Logs e Monitoramento

### Níveis de Log
- **INFO:** Operações normais
- **WARNING:** Avisos de segurança
- **ERROR:** Erros críticos

### Logs de Comando
- **success:** Comando executado com sucesso
- **blocked:** Comando bloqueado pela proteção
- **error:** Erro na execução do comando
- **device_not_found:** Dispositivo não encontrado

## 🧪 Testes

### Executar Todos os Testes
```bash
python -m pytest tests/
```

### Executar Testes Específicos
```bash
# Testes da Camada 1 (Crypto)
python -m pytest tests/test_iot.py::TestCryptoUtils

# Testes da Camada 2 (Device Manager)
python -m pytest tests/test_iot.py::TestDeviceRegistration

# Testes da Camada 3 (API)
python -m pytest tests/test_iot.py::TestAPIEndpoints
```

### Testes Manuais via Swagger
1. Acesse: `http://localhost:8000/docs`
2. Teste cada endpoint individualmente
3. Verifique respostas e códigos de status

## 🔒 Considerações de Segurança

### Em Produção
1. **Use chaves seguras:** Gere chaves AES e HMAC aleatórias
2. **Configure HTTPS:** Use certificados SSL/TLS
3. **Implemente autenticação:** Adicione JWT ou OAuth2
4. **Monitore logs:** Configure alertas de segurança
5. **Backup regular:** Faça backup do banco de dados

### Validações Implementadas
- Validação de comandos permitidos
- Verificação de existência de dispositivos
- Criptografia de comandos sensíveis
- Logs de todas as operações
- Tratamento de erros robusto

## 🚨 Tratamento de Erros

### Códigos de Status HTTP
- **200:** Sucesso
- **400:** Requisição inválida
- **404:** Dispositivo não encontrado
- **500:** Erro interno do servidor

### Exemplos de Erro
```json
{
  "detail": "Dispositivo com ID 999 não encontrado"
}
```

## 📈 Monitoramento e Métricas

### Métricas Disponíveis
- Número de dispositivos registrados
- Comandos enviados por período
- Taxa de sucesso de comandos
- Status da proteção ao longo do tempo

### Logs de Performance
- Tempo de resposta de cada endpoint
- Uso de recursos do sistema
- Erros de comunicação com dispositivos

## 🔄 Integração entre Camadas

### Camada 1 → Camada 3
- Criptografia e descriptografia de comandos
- Geração e verificação de HMAC
- Gerenciamento de tokens JWT

### Camada 2 → Camada 3
- Validação de dispositivos registrados
- Gerenciamento de tipos de dispositivo

### Camada 3 → Camada 4
- Envio de comandos via UDP/TCP
- Comunicação com dispositivos físicos

## 📝 Exemplos de Uso

### Python Client
```python
import requests

# Verificar status
response = requests.get("http://localhost:8000/status")
print(response.json())

# Enviar comando
command = {"device_id": 1, "command": "move_up"}
response = requests.post("http://localhost:8000/command", json=command)
print(response.json())
```

### cURL
```bash
# Verificar status
curl -X GET "http://localhost:8000/status"

# Enviar comando
curl -X POST "http://localhost:8000/command" \
  -H "Content-Type: application/json" \
  -d '{"device_id": 1, "command": "move_up"}'
```

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature
3. Implemente suas mudanças
4. Adicione testes
5. Faça commit e push
6. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

## 🆘 Suporte

Para suporte técnico ou dúvidas:
- Abra uma issue no GitHub
- Consulte a documentação da API em `/docs`
- Verifique os logs da aplicação

---

## 📚 Documentação Detalhada por Camada

### Camada 1: Crypto Utils
Este módulo fornece funções e classes para segurança em aplicações IoT, incluindo:
- Criptografia e autenticação de pacotes com AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
- Geração e verificação de tokens JWT para autenticação
- Geração e verificação de assinaturas HMAC-SHA256 para comandos

#### Principais Classes e Funções

- **AESCipher**: Criptografa e autentica dados usando AES-256-CBC e HMAC-SHA256. Permite especificar o comprimento da chave HMAC e garante integridade dos dados (Encrypt-then-MAC).
- **JWTAuth**: Gera e verifica tokens JWT para autenticação, usando segredo seguro de variável de ambiente.
- **generate_hmac_key(length=32)**: Gera uma chave HMAC aleatória de comprimento seguro (NUNCA use chaves previsíveis!).
- **generate_hmac(key, message)**: Gera uma assinatura HMAC-SHA256 para uma mensagem.
- **verify_hmac(key, message, signature_hex)**: Verifica a assinatura HMAC-SHA256 de uma mensagem.
- **get_env_var(name)**: Obtém uma variável de ambiente, lançando exceção se não definida.
- **setup_logging(level, log_file)**: Configura o sistema de logging do Python para o módulo.

#### Exemplo de Uso Básico

```python
from src.crypto_utils import setup_logging, get_env_var, AESCipher, JWTAuth, generate_hmac, verify_hmac
setup_logging(level=logging.INFO)

# Carregar chaves
aes_key = get_env_var('AES_KEY').encode('utf-8')
hmac_key = get_env_var('HMAC_KEY').encode('utf-8')

# Criptografia e autenticação
cipher = AESCipher(aes_key, hmac_key)
mensagem = b"Mensagem IoT confidencial"
iv, ct, mac = cipher.encrypt(mensagem)
plaintext = cipher.decrypt(iv, ct, mac)

# JWT
token = JWTAuth().generate_token({"device_id": 123})
payload = JWTAuth().verify_token(token)

# HMAC simples
sig = generate_hmac(hmac_key, b"comando importante")
valid = verify_hmac(hmac_key, b"comando importante", sig)
```

### Camada 2: Device Manager
Sistema de registro e gerenciamento de dispositivos IoT com validação de IPs e tipos de dispositivo.

### Camada 3: API Central
Servidor FastAPI completo para gerenciamento centralizado de dispositivos IoT, incluindo controle de comandos, logs de atividades e sistema de proteção com criptografia.

### Camada 4: Device Interceptor
Sistema de comunicação com dispositivos físicos via UDP (drones) e TCP (veículos e outros dispositivos). 