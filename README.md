# 🚀 IOTRAC - Sistema de Segurança IoT

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-47%20passed-brightgreen.svg)](https://pytest.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Visão Geral

O **IOTRAC** é um sistema completo de segurança para aplicações IoT que oferece proteção, autenticação e gerenciamento inteligente de dispositivos. Com múltiplas camadas de segurança, o sistema garante que seus dispositivos IoT estejam protegidos contra ataques e funcionem de forma confiável.

### ✨ Principais Funcionalidades

- 🔐 **Criptografia Avançada**: AES-256-CBC com HMAC-SHA256
- 🛡️ **Proteção Inteligente**: Sistema de proteção ativa/desativa
- 📱 **Gerenciamento de Dispositivos**: Registro e controle de IoT
- 📊 **Logs Detalhados**: Rastreamento completo de comandos
- 🌐 **API REST**: Interface moderna e fácil de usar
- ⚡ **Performance Otimizada**: Resposta rápida e eficiente

## 🏗️ Arquitetura do Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                    IOTRAC - Sistema Completo                │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 1: Crypto Utils (crypto_utils.py)                  │
│  ├── 🔐 AES-256-CBC Encryption                             │
│  ├── 🔑 HMAC-SHA256 Authentication                         │
│  └── 🎫 JWT Token Management                               │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 2: Device Manager (device_manager.py)              │
│  ├── 📱 Registro de Dispositivos                           │
│  ├── 🌐 Validação de IPs                                   │
│  └── 📋 Gerenciamento de Tipos                             │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 3: API Central (main.py)                           │
│  ├── 🛡️ Sistema de Proteção                               │
│  ├── 📊 Logs de Comandos                                   │
│  └── 🎮 Controle de Dispositivos                           │
├─────────────────────────────────────────────────────────────┤
│  CAMADA 4: Device Interceptor (device_interceptor.py)      │
│  ├── 📡 Comunicação UDP/TCP                                │
│  ├── ⏱️ Timeout Management                                 │
│  └── 🔍 Validação de Dados                                 │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Instalação Rápida

### Pré-requisitos
- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Passo a Passo

1. **Clone o repositório**
```bash
git clone https://github.com/seu-usuario/iotrac-backend.git
cd iotrac-backend
```

2. **Crie um ambiente virtual**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

3. **Instale as dependências**
```bash
pip install -r requirements.txt
```

4. **Configure as variáveis de ambiente**
```bash
cp env.example .env
# Edite o arquivo .env com suas chaves seguras
```

5. **Execute os testes**
```bash
pytest tests/ -v
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

# Gerar chaves seguras
aes_key = base64.b64encode(os.urandom(32)).decode()
hmac_key = base64.b64encode(os.urandom(32)).decode()

print(f"AES_KEY={aes_key}")
print(f"HMAC_KEY={hmac_key}")
```

## 🎮 Como Usar

### 1. Iniciando o Servidor

```bash
python src/main.py
```

O servidor estará disponível em: `http://localhost:8000`

### 2. Documentação da API

Acesse a documentação interativa:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### 3. Exemplos de Uso

#### Registrando um Dispositivo
```bash
curl -X POST "http://localhost:8000/device/register" \
     -H "Content-Type: application/json" \
     -d '{"device_type": "drone", "ip_address": "192.168.1.100"}'
```

#### Enviando um Comando
```bash
curl -X POST "http://localhost:8000/command" \
     -H "Content-Type: application/json" \
     -d '{"device_id": 1, "command": "move_up"}'
```

#### Verificando Status da Proteção
```bash
curl -X GET "http://localhost:8000/status"
```

#### Alternando Proteção Global
```bash
curl -X POST "http://localhost:8000/toggle_protection"
```

#### Verificando Proteção de um Dispositivo
```bash
curl -X GET "http://localhost:8000/devices/1/protection"
```

#### Alternando Proteção de um Dispositivo
```bash
curl -X POST "http://localhost:8000/devices/1/protection/toggle"
```

#### Removendo um Dispositivo
```bash
curl -X DELETE "http://localhost:8000/devices/1"
```

## 📊 Endpoints da API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/` | Informações básicas da API |
| `GET` | `/status` | Status da proteção global |
| `POST` | `/toggle_protection` | Alternar proteção global |
| `GET` | `/devices` | Listar todos os dispositivos |
| `GET` | `/devices/{id}` | Detalhes de um dispositivo específico |
| `POST` | `/device/register` | Registrar novo dispositivo |
| `DELETE` | `/devices/{id}` | Remover dispositivo |
| `GET` | `/devices/{id}/protection` | Status de proteção de um dispositivo |
| `POST` | `/devices/{id}/protection/toggle` | Alternar proteção de um dispositivo |
| `POST` | `/command` | Enviar comando para dispositivo |
| `GET` | `/logs` | Logs de comandos do sistema |

## 🧪 Testes

O projeto inclui **47 testes abrangentes** que cobrem todas as funcionalidades:

### Executando os Testes

```bash
# Todos os testes
pytest tests/ -v

# Testes específicos
pytest tests/test_crypto_utils.py -v
pytest tests/test_iot.py -v

# Com cobertura
pytest tests/ --cov=src --cov-report=html
```

### Cobertura dos Testes

- ✅ **Criptografia**: 12 testes (AES, HMAC, JWT)
- ✅ **Dispositivos**: 35 testes (registro, comandos, proteção)
- ✅ **Integração**: Fluxo completo do sistema
- ✅ **Performance**: Testes de velocidade
- ✅ **Segurança**: Validação de entrada e proteção

## 🔧 Desenvolvimento

### Estrutura do Projeto

```
iotrac-backend/
├── src/
│   ├── main.py              # API principal
│   ├── crypto_utils.py      # Criptografia e segurança
│   ├── device_manager.py    # Gerenciamento de dispositivos
│   ├── device_interceptor.py # Comunicação com dispositivos
│   ├── db_setup.py          # Banco de dados
│   └── config.py            # Configurações
├── tests/
│   ├── test_crypto_utils.py # Testes de criptografia
│   └── test_iot.py          # Testes do sistema
├── requirements.txt         # Dependências
├── .env                     # Variáveis de ambiente
└── README.md               # Este arquivo
```

### Comandos Úteis

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt

# Executar servidor em modo desenvolvimento
python src/main.py

# Executar testes
pytest tests/ -v

# Verificar qualidade do código
flake8 src/
black src/
```

## 🛡️ Segurança

### Medidas Implementadas

- **Criptografia AES-256-CBC**: Proteção de dados sensíveis
- **Autenticação HMAC-SHA256**: Verificação de integridade
- **Tokens JWT**: Autenticação segura
- **Validação de Entrada**: Prevenção de ataques
- **Logs de Segurança**: Rastreamento de atividades
- **Proteção Ativa**: Sistema de bloqueio inteligente

### Boas Práticas

- ✅ Nunca exponha chaves no código
- ✅ Use variáveis de ambiente para segredos
- ✅ Valide sempre os dados de entrada
- ✅ Mantenha logs de segurança
- ✅ Atualize dependências regularmente

## 📈 Performance

### Métricas dos Testes

- **Tempo de Execução**: ~0.4 segundos para 47 testes
- **Taxa de Sucesso**: 100% (47/47 testes passando)
- **Cobertura**: Testes abrangentes em todas as camadas
- **Memória**: Uso otimizado de recursos

## 🤝 Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. **Fork** o projeto
2. **Crie** uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. **Push** para a branch (`git push origin feature/AmazingFeature`)
5. **Abra** um Pull Request

### Padrões de Código

- Siga o padrão PEP 8
- Adicione testes para novas funcionalidades
- Mantenha a documentação atualizada
- Use type hints quando possível

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🆘 Suporte

### Problemas Comuns

**Erro: "AES_KEY não definida"**
- Verifique se o arquivo `.env` existe
- Confirme se as chaves estão definidas corretamente

**Erro: "Banco de dados readonly"**
- Verifique as permissões do arquivo `iotrac.db`
- Certifique-se de que o diretório tem permissão de escrita

**Testes falhando**
- Ative o ambiente virtual: `source venv/bin/activate`
- Reinstale as dependências: `pip install -r requirements.txt`

### Obtendo Ajuda

- 📖 **Documentação**: `/docs` (quando o servidor estiver rodando)
- 🐛 **Issues**: Abra uma issue no GitHub
- 💬 **Discussões**: Use as discussões do GitHub

## 🎯 Roadmap

- [ ] Interface web para gerenciamento
- [ ] Suporte a múltiplos protocolos IoT
- [ ] Dashboard de monitoramento em tempo real
- [ ] Integração com sistemas de alerta
- [ ] Suporte a clusters de dispositivos
- [ ] API GraphQL

---

**IOTRAC** - Protegendo o futuro da IoT, um dispositivo por vez! 🚀

*Desenvolvido com ❤️ para a comunidade IoT* 