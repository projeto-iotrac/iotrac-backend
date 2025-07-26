# Testes das Funcionalidades Bluetooth - IOTRAC

## 📋 Visão Geral

Este diretório contém scripts de teste completos para verificar todas as funcionalidades Bluetooth implementadas no backend IOTRAC, incluindo simulação de dispositivos e verificação de segurança.

## 🧪 Scripts de Teste Disponíveis

### 1. `test_bluetooth_integration.py`
Script principal que executa todos os testes das funcionalidades Bluetooth:

- **Módulo Bluetooth Interceptor**: Testa escaneamento, conexão, envio de comandos
- **Integração com Banco de Dados**: Verifica inserção, busca e atualização de dispositivos
- **Funcionalidades de Segurança**: Testa criptografia AES, HMAC e detecção de tampering
- **Simulação de Endpoints**: Valida estrutura e resposta dos endpoints da API
- **Tratamento de Erros**: Verifica validação de dados e rejeição de entradas inválidas

### 2. `run_bluetooth_tests.sh`
Script shell que facilita a execução dos testes:

- Verifica dependências automaticamente
- Configura ambiente de teste
- Executa bateria completa de testes
- Gera relatório final com estatísticas

## 🚀 Como Executar os Testes

### Método 1: Script Shell (Recomendado)

```bash
# Navegar para o diretório do backend
cd iotrac-backend

# Executar script de teste
./tests/run_bluetooth_tests.sh
```

### Método 2: Python Direto

```bash
# Navegar para o diretório do backend
cd iotrac-backend

# Configurar variáveis de ambiente
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"
export AES_KEY="test_aes_key_32_bytes_long_12345678"
export HMAC_KEY="test_hmac_key_32_bytes_long_1234567"
export JWT_SECRET="test_jwt_secret_key"

# Executar testes
python3 tests/test_bluetooth_integration.py
```

## 📊 O Que os Testes Verificam

### ✅ Funcionalidades Testadas

#### 1. **Bluetooth Interceptor**
- ✅ Inicialização do interceptor
- ✅ Escaneamento de dispositivos (simulado)
- ✅ Conexão com dispositivos
- ✅ Envio de comandos
- ✅ Desconexão de dispositivos

#### 2. **Banco de Dados**
- ✅ Inserção de dispositivos Bluetooth
- ✅ Busca por endereço MAC
- ✅ Listagem de dispositivos
- ✅ Atualização de status de conexão
- ✅ Controle de proteção individual

#### 3. **Segurança**
- ✅ Criptografia AES-256 de comandos
- ✅ Descriptografia correta
- ✅ Geração e verificação HMAC
- ✅ Detecção de tampering
- ✅ Validação de integridade

#### 4. **API Endpoints**
- ✅ Validação de dados de entrada
- ✅ Estrutura de resposta correta
- ✅ Campos obrigatórios presentes
- ✅ Códigos de status apropriados

#### 5. **Tratamento de Erros**
- ✅ Rejeição de MAC addresses inválidos
- ✅ Validação de tipos de dispositivos
- ✅ Limites de timeout respeitados
- ✅ Mensagens de erro apropriadas

### 🎯 Simulação de Dispositivos

Os testes incluem um **simulador completo de dispositivos Bluetooth** que replica:

- **4 dispositivos diferentes**: Lâmpada, Speaker, Fechadura, Fitness Tracker
- **Endereços MAC realistas**: Formato válido AA:BB:CC:DD:EE:XX
- **Características GATT**: Simulação de serviços e características
- **Estados de conexão**: Conectado/desconectado/descoberto
- **Respostas de comandos**: Sucesso/erro/não conectado

## 📈 Interpretação dos Resultados

### ✅ Taxa de Sucesso >= 90%
```
🎉 EXCELENTE! Implementação Bluetooth está funcionando perfeitamente.
```
**Significado**: Todas as funcionalidades principais estão operacionais e a implementação está pronta para produção.

### ✅ Taxa de Sucesso 70-89%
```
👍 BOM! Implementação funcional com alguns pontos de atenção.
```
**Significado**: Funcionalidades core funcionam, mas há alguns pontos que podem ser melhorados.

### ❌ Taxa de Sucesso < 70%
```
⚠️ ATENÇÃO! Implementação precisa de correções.
```
**Significado**: Há problemas significativos que precisam ser corrigidos antes do uso.

## 🔧 Dependências dos Testes

### Obrigatórias (sempre necessárias)
- Python 3.8+
- Bibliotecas padrão: `asyncio`, `sqlite3`, `json`, `os`, `sys`, `tempfile`, `logging`, `datetime`, `unittest.mock`, `typing`

### Opcionais (para testes avançados)
- `bleak>=0.20.0`: Para testes com dispositivos Bluetooth reais

**Nota**: Os testes funcionam mesmo sem `bleak` instalado, usando simulação completa.

## 📝 Exemplo de Saída dos Testes

```
🚀 EXECUTANDO TESTES BLUETOOTH - IOTRAC BACKEND
==================================================
🔍 Verificando dependências...
⚠️ Biblioteca bleak não encontrada (modo simulação)
✅ Dependências verificadas

🧪 Iniciando bateria de testes...
Modo: simulation

============================================================
🧪 TESTANDO MÓDULO BLUETOOTH_INTERCEPTOR
============================================================
✅ PASSOU - Inicialização BluetoothInterceptor: Interceptor inicializado com sucesso
✅ PASSOU - Escaneamento de dispositivos: 4 dispositivos encontrados
✅ PASSOU - Conexão com dispositivo: Conexão com AA:BB:CC:DD:EE:01: sucesso

============================================================
🗄️ TESTANDO INTEGRAÇÃO COM BANCO DE DADOS
============================================================
✅ PASSOU - Inserção dispositivo Bluetooth: Dispositivo inserido com ID: 1
✅ PASSOU - Busca por MAC address: Dispositivo encontrado: Lâmpada Teste

============================================================
📊 RELATÓRIO FINAL DOS TESTES
============================================================
📈 ESTATÍSTICAS:
   Total de testes: 25
   ✅ Passou: 24
   ❌ Falhou: 1
   📊 Taxa de sucesso: 96.0%

🎯 CONCLUSÃO:
   🎉 EXCELENTE! Implementação Bluetooth está funcionando perfeitamente.
```

## 🐛 Solução de Problemas

### Erro: "Módulo não encontrado"
```bash
# Verificar se está no diretório correto
cd iotrac-backend

# Verificar estrutura de arquivos
ls src/bluetooth_interceptor.py src/main.py src/db_setup.py
```

### Erro: "Permissão negada"
```bash
# Dar permissão de execução
chmod +x tests/run_bluetooth_tests.sh
```

### Erro: "Dependências não encontradas"
```bash
# Instalar dependências
pip install -r requirements.txt
```

### Testes falhando consistentemente
1. Verificar se não há outros processos usando a porta 8000
2. Verificar permissões de escrita no diretório temporário
3. Verificar se todas as variáveis de ambiente estão configuradas

## 🎯 Próximos Passos Após Testes

Se os testes passarem com sucesso:

1. **Instalar dependências completas**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Iniciar servidor**:
   ```bash
   python src/main.py
   ```

3. **Testar endpoints reais** usando Postman ou curl:
   ```bash
   curl -X POST http://localhost:8000/bluetooth/scan \
        -H "Content-Type: application/json" \
        -d '{"timeout": 10.0}'
   ```

4. **Integrar com frontend** usando a documentação em `docs/BLUETOOTH_API.md`

## 📞 Suporte

Se encontrar problemas durante os testes:

1. Verifique os logs detalhados na saída do terminal
2. Consulte a documentação em `docs/BLUETOOTH_API.md`
3. Verifique se todas as dependências estão instaladas corretamente
4. Certifique-se de que está executando a partir do diretório `iotrac-backend`

---

**Os testes foram projetados para funcionar mesmo sem dispositivos Bluetooth reais, usando simulação completa para verificar toda a lógica implementada.** 🎯 