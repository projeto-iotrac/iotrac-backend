# 🚀 IOTRAC Backend - Sistema de Segurança IoT

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-50%20passed-brightgreen.svg)](https://pytest.org/)

## 📋 Visão Geral

Sistema de segurança IoT com **criptografia AES-256**, **autenticação JWT** e **proteção individual por dispositivo**. Garante que seus dispositivos IoT estejam protegidos contra ataques com múltiplas camadas de segurança.

### ✨ Funcionalidades

- 🔐 **Criptografia AES-256-CBC** com HMAC-SHA256
- 🛡️ **Sistema de Proteção** ativa/desativa por dispositivo
- 📱 **Gerenciamento de Dispositivos** IoT com proteção individual
- 📊 **Logs Detalhados** de comandos e auditoria
- 🌐 **API REST** com documentação automática
- 🧪 **50 Testes Unificados** organizados por camadas
- 🚁 **Simulador de Drone** para testes
- 🔍 **Verificação de Estrutura** automática
- 🚨 **Bloqueio de Comandos** não criptografados

## 🚀 Instalação Rápida

### 1. Clone e Configure
```bash
git clone https://github.com/seu-usuario/iotrac-backend.git
cd iotrac-backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

### 2. Configure as Chaves
```bash
# Gerar chaves automaticamente:
./scripts/generate_keys.sh

# Ou copie o exemplo e configure manualmente
cp config/env.example config/.env
# Edite config/.env com suas chaves
```

### 3. Verifique a Estrutura
```bash
python scripts/verify_structure.py
```

### 4. Execute
```bash
python scripts/start_server.py
```

**Servidor disponível em:** `http://localhost:8000`  
**Documentação:** `http://localhost:8000/docs`

## 🧪 Testes

### Executar Todos os Testes
```bash
pytest tests/test_iot.py -v
```

### 📊 Resumo: 50 Testes Passando ✅

| Camada | Testes | Foco |
|--------|--------|------|
| 🔐 **Criptografia** | 12 | AES-256, HMAC, JWT |
| 🔧 **Registro** | 3 | Validação de dispositivos |
| 🗄️ **Banco de Dados** | 8 | CRUD, logs, índices |
| 🌐 **API Endpoints** | 12 | Segurança, proteção |
| 📡 **Interceptação** | 10 | UDP/TCP, timeouts |
| 🔗 **Integração** | 2 | Fluxos completos |
| ⚡ **Performance** | 2 | Otimização |
| 🔒 **Segurança** | 2 | Ataques, SQL Injection |

### 🛡️ Testes de Segurança em Destaque

**Ataques BLOQUEADOS:**
- ❌ SQL Injection: `"DROP TABLE devices"`
- ❌ XSS: `"<script>alert('hack')</script>"`
- ❌ Command Injection: `"rm -rf /"`
- ❌ Path Traversal: `"../../../etc/passwd"`
- ❌ Comandos não criptografados quando proteção ativa

**Proteções Ativas:**
- ✅ Comandos não criptografados bloqueados
- ✅ Proteção individual por dispositivo
- ✅ Logs de auditoria completos
- ✅ Validação robusta de entrada
- ✅ Verificação HMAC para dispositivos protegidos

## 📡 API Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/` | Informações básicas da API |
| `GET` | `/status` | Status da proteção global |
| `POST` | `/toggle_protection` | Alternar proteção global |
| `GET` | `/devices` | Listar dispositivos |
| `GET` | `/devices/{device_id}` | Detalhes de dispositivo específico |
| `POST` | `/device/register` | Registrar dispositivo |
| `DELETE` | `/devices/{device_id}` | Remover dispositivo |
| `POST` | `/command` | Enviar comando |
| `GET` | `/logs` | Logs do sistema |
| `GET` | `/devices/{device_id}/protection` | Status de proteção do dispositivo |
| `POST` | `/devices/{device_id}/protection/toggle` | Alternar proteção do dispositivo |

### Exemplos de Uso

```bash
# Registrar dispositivo
curl -X POST "http://localhost:8000/device/register" \
     -H "Content-Type: application/json" \
     -d '{"device_type": "drone", "ip_address": "192.168.1.100"}'

# Enviar comando
curl -X POST "http://localhost:8000/command" \
     -H "Content-Type: application/json" \
     -d '{"device_id": 1, "command": "move_up"}'

# Alternar proteção de dispositivo
curl -X POST "http://localhost:8000/devices/1/protection/toggle"

# Verificar status de proteção
curl -X GET "http://localhost:8000/devices/1/protection"
```

## 🚁 Simulador de Drone

Teste a conectividade e segurança do sistema:

```bash
python tests/drone-simulator.py
```

**Testa:** Registro, proteção JWT/HMAC, criptografia AES-256, comunicação UDP/TCP

## 📁 Estrutura do Projeto

```
iotrac-backend/
├── src/                    # Código fonte principal
│   ├── main.py            # Aplicação FastAPI principal
│   ├── config.py          # Configurações
│   ├── crypto_utils.py    # Utilitários de criptografia
│   ├── db_setup.py        # Configuração do banco de dados
│   ├── device_manager.py  # Gerenciador de dispositivos
│   └── device_interceptor.py # Interceptador de dispositivos
├── scripts/               # Scripts utilitários
│   ├── start_server.py    # Script de inicialização
│   ├── clear_devices.py   # Limpeza de dispositivos
│   ├── generate_keys.sh   # Gerador de chaves
│   └── verify_structure.py # Verificação de estrutura
├── config/                # Arquivos de configuração
│   ├── env.example        # Exemplo de configuração
│   ├── .env              # Configuração atual (não commitar)
│   └── pytest.ini        # Configuração de testes
├── database/              # Arquivos de banco de dados
│   └── iotrac.db         # Banco SQLite (não commitar)
├── tests/                 # Testes automatizados
│   ├── test_iot.py       # Testes principais
│   ├── conftest.py       # Configuração de testes
│   ├── pytest.ini        # Configuração pytest
│   └── drone-simulator.py # Simulador de drone
├── venv/                  # Ambiente virtual Python
├── requirements.txt       # Dependências Python
└── README.md             # Este arquivo
```

## 🔧 Scripts Úteis

### Verificação de Estrutura
```bash
python scripts/verify_structure.py
```
Verifica se todos os arquivos estão nos lugares corretos e se as referências estão atualizadas.

### Limpeza de Dispositivos
```bash
python scripts/clear_devices.py
```
Remove todos os dispositivos registrados do banco de dados.

### Geração de Chaves
```bash
./scripts/generate_keys.sh
```
Gera automaticamente chaves AES e HMAC seguras.

## 🔐 Configuração de Segurança

### Variáveis de Ambiente Obrigatórias

```bash
# Chave AES de 32 bytes (256 bits) para criptografia
AES_KEY=sua_chave_aes_de_32_bytes_aqui

# Chave HMAC de 32 bytes para autenticação
HMAC_KEY=sua_chave_hmac_de_32_bytes_aqui

# Chave JWT para autenticação (opcional, tem valor padrão)
JWT_SECRET=sua_chave_jwt_secreta_aqui
```

### Tipos de Dispositivos Suportados

- `drone` - Comunicação UDP na porta 5000
- `veículo` - Comunicação TCP na porta 5001
- `smart-lamp` - Comunicação TCP na porta 5002
- `smart-lock` - Comunicação TCP na porta 5002
- `security-camera` - Comunicação TCP na porta 5002
- `smart-tv` - Comunicação TCP na porta 5002
- `smart-thermostat` - Comunicação TCP na porta 5002

### Comandos Válidos

- `move_up`, `move_down`, `move_left`, `move_right`
- `move_forward`, `move_backward`
- `turn_on`, `turn_off`
- `set_speed`, `get_status`
- `emergency_stop`

## 🛡️ Sistema de Proteção

### Proteção Global
- Controla a proteção para todos os dispositivos
- Endpoint: `/toggle_protection`

### Proteção Individual por Dispositivo
- Cada dispositivo pode ter proteção independente
- Endpoints: `/devices/{id}/protection/toggle`
- Quando ativa, bloqueia comandos não criptografados

### Criptografia de Comandos
- Comandos são criptografados com AES-256-CBC
- HMAC-SHA256 para integridade
- Formato: `{"iv": "...", "ciphertext": "...", "hmac": "..."}`

## 📊 Logs e Auditoria

O sistema mantém logs detalhados de:
- Comandos enviados
- Status de proteção
- Tentativas de acesso bloqueadas
- Erros de criptografia
- Registro/remoção de dispositivos

## 🚨 Tratamento de Erros

- **400**: Dados inválidos ou comandos não permitidos
- **401**: Comando não criptografado quando proteção ativa
- **404**: Dispositivo não encontrado
- **500**: Erro interno do servidor
- **503**: Falha na comunicação com dispositivo

## 🔄 Dependências

```
fastapi
uvicorn
pytest
pytest-asyncio
httpx
cryptography
python-jose[cryptography]
pydantic
python-dotenv
pyjwt
```

## 📝 Licença

Este projeto é parte do sistema IOTRAC para segurança IoT.