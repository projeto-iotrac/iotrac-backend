# 🚀 IOTRAC Backend - Sistema de Segurança IoT

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-47%20passed-brightgreen.svg)](https://pytest.org/)

## 📋 Visão Geral

O **IOTRAC Backend** é um sistema de segurança IoT que oferece proteção criptográfica, autenticação e gerenciamento de dispositivos. Com múltiplas camadas de segurança (AES-256, HMAC-SHA256), garante que seus dispositivos IoT estejam protegidos contra ataques.

### ✨ Funcionalidades Principais

- 🔐 **Criptografia AES-256-CBC** com HMAC-SHA256
- 🛡️ **Sistema de Proteção** ativa/desativa por dispositivo
- 📱 **Gerenciamento de Dispositivos** IoT
- 📊 **Logs Detalhados** de comandos
- 🌐 **API REST** com documentação automática
- 🧪 **Simulador de Drone** para testes

## 🚀 Instalação Rápida

### Pré-requisitos
- Python 3.8+
- pip

### Passo a Passo

1. **Clone e entre no diretório**
```bash
git clone https://github.com/seu-usuario/iotrac-backend.git
cd iotrac-backend
```

2. **Crie ambiente virtual**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

3. **Instale dependências**
```bash
pip install -r requirements.txt
```

4. **Configure variáveis de ambiente**
```bash
cp env.example .env
# Edite .env com suas chaves seguras
```

## ⚙️ Configuração

### Variáveis de Ambiente (.env)

```env
# Chaves de Segurança (OBRIGATÓRIAS)
AES_KEY=sua_chave_aes_de_32_bytes_aqui
HMAC_KEY=sua_chave_hmac_de_32_bytes_aqui

# Configurações do Servidor (OPCIONAIS)
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
```

### Gerando Chaves Seguras

```python
import os
import base64

aes_key = base64.b64encode(os.urandom(32)).decode()
hmac_key = base64.b64encode(os.urandom(32)).decode()

print(f"AES_KEY={aes_key}")
print(f"HMAC_KEY={hmac_key}")
```

## 🎮 Como Usar

### Iniciando o Servidor

#### Opção A: Script Automático (Recomendado)
```bash
python start_server.py
```

#### Opção B: Manual
```bash
python src/main.py
```

O servidor estará disponível em: `http://localhost:8000`

### Documentação da API

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Exemplos de Uso

#### Registrar Dispositivo
```bash
curl -X POST "http://localhost:8000/device/register" \
     -H "Content-Type: application/json" \
     -d '{"device_type": "drone", "ip_address": "192.168.1.100"}'
```

#### Enviar Comando
```bash
curl -X POST "http://localhost:8000/command" \
     -H "Content-Type: application/json" \
     -d '{"device_id": 1, "command": "move_up"}'
```

#### Verificar Status
```bash
curl -X GET "http://localhost:8000/status"
```

## 📊 Endpoints Principais

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/status` | Status da proteção global |
| `POST` | `/toggle_protection` | Alternar proteção global |
| `GET` | `/devices` | Listar dispositivos |
| `POST` | `/device/register` | Registrar dispositivo |
| `POST` | `/command` | Enviar comando |
| `GET` | `/logs` | Logs do sistema |

## 🧪 Testes

### Testes Unitários
```bash
# Todos os testes
pytest tests/ -v

# Testes específicos
pytest tests/test_crypto_utils.py -v
pytest tests/test_iot.py -v
```

### Simulador de Drone
O projeto inclui um simulador de drone para testar a conectividade e segurança:

```bash
# Executar simulador
python tests/drone-simulator.py
```

**O que o simulador testa:**
- ✅ Registro do drone no sistema
- 🔐 Proteção JWT e HMAC
- 🔒 Criptografia AES-256
- 📡 Comunicação UDP/TCP
- 🛡️ Sistema de proteção individual

## 📁 Estrutura do Projeto

```
iotrac-backend/
├── src/
│   ├── main.py              # API principal
│   ├── crypto_utils.py      # Criptografia
│   ├── device_manager.py    # Gerenciamento de dispositivos
│   ├── device_interceptor.py # Interceptação de comandos
│   ├── db_setup.py          # Configuração do banco
│   └── config.py            # Configurações
├── tests/
│   ├── test_crypto_utils.py # Testes de criptografia
│   ├── test_iot.py          # Testes de IoT
│   ├── test_server.py       # Testes do servidor
│   └── drone-simulator.py   # Simulador de drone
├── start_server.py          # Script de inicialização
├── requirements.txt         # Dependências
└── env.example             # Exemplo de configuração
```

## 🔧 Scripts Úteis

- `start_server.py` - Inicia o servidor com monitoramento automático
- `drone-simulator.py` - Testa conectividade e segurança do sistema

---

**Desenvolvido com ❤️ para revolucionar a segurança IoT** 🚀 