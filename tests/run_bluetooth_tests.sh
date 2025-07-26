#!/bin/bash

# Script para executar testes das funcionalidades Bluetooth do IOTRAC
# Uso: ./run_bluetooth_tests.sh

echo "🚀 EXECUTANDO TESTES BLUETOOTH - IOTRAC BACKEND"
echo "=================================================="

# Verificar se estamos no diretório correto
if [ ! -f "src/main.py" ]; then
    echo "❌ Erro: Execute este script a partir do diretório iotrac-backend/"
    exit 1
fi

# Verificar se Python está disponível
if ! command -v python3 &> /dev/null; then
    echo "❌ Erro: Python3 não encontrado. Instale Python 3.8+ para continuar."
    exit 1
fi

# Verificar dependências
echo "🔍 Verificando dependências..."

# Verificar se as dependências estão instaladas
python3 -c "import asyncio, sqlite3, json, os, sys, tempfile, logging, datetime, unittest.mock, typing" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Erro: Dependências Python básicas não encontradas."
    exit 1
fi

# Verificar se bleak está instalado (opcional para simulação)
python3 -c "import bleak" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ Biblioteca bleak encontrada (modo real)"
    BLUETOOTH_MODE="real"
else
    echo "⚠️ Biblioteca bleak não encontrada (modo simulação)"
    echo "   Para instalar: pip install bleak>=0.20.0"
    BLUETOOTH_MODE="simulation"
fi

echo "✅ Dependências verificadas"
echo ""

# Configurar variáveis de ambiente para teste
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"
export AES_KEY="test_aes_key_32_bytes_long_12345678"
export HMAC_KEY="test_hmac_key_32_bytes_long_1234567"
export JWT_SECRET="test_jwt_secret_key"

# Verificar se o diretório src existe
if [ ! -d "src" ]; then
    echo "❌ Erro: Diretório src não encontrado em $(pwd)"
    exit 1
fi

echo "✅ PYTHONPATH configurado: $PYTHONPATH"

echo "🧪 Iniciando bateria de testes..."
echo "Modo: $BLUETOOTH_MODE"
echo ""

# Executar os testes
python3 tests/test_bluetooth_integration.py

# Capturar código de saída
TEST_RESULT=$?

echo ""
echo "=================================================="

if [ $TEST_RESULT -eq 0 ]; then
    echo "🎉 TODOS OS TESTES PASSARAM COM SUCESSO!"
    echo "✅ Implementação Bluetooth está funcionando corretamente"
    echo ""
    echo "📋 Próximos passos:"
    echo "   1. Instalar dependências: pip install -r requirements.txt"
    echo "   2. Iniciar servidor: python src/main.py"
    echo "   3. Testar endpoints via frontend ou Postman"
else
    echo "❌ ALGUNS TESTES FALHARAM"
    echo "⚠️ Verifique os logs acima para detalhes"
    echo ""
    echo "🔧 Possíveis soluções:"
    echo "   1. Verificar se todas as dependências estão instaladas"
    echo "   2. Verificar permissões de escrita no diretório"
    echo "   3. Verificar se não há conflitos de importação"
fi

echo "=================================================="

exit $TEST_RESULT 