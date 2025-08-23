#!/bin/bash

# Script para gerar chaves AES e HMAC para IOTRAC
set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[IOTRAC]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Resolver Python (python3 ou python)
resolve_python() {
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN=$(command -v python3)
    elif command -v python >/dev/null 2>&1; then
        PYTHON_BIN=$(command -v python)
    else
        print_error "❌ Python não encontrado! Instale Python3 ou Python."
        exit 1
    fi
}

# Função para gerar chaves
generate_keys() {
    print_status "🔑 Gerando chaves de segurança para IOTRAC..."
    
    # Verificar se Python está disponível
    resolve_python
    
    # Verificar se env.example existe
    if [ ! -f "../config/env.example" ]; then
        print_error "❌ Arquivo env.example não encontrado!"
        exit 1
    fi
    
    # Gerar chaves usando Python
    print_status "🔐 Gerando AES_KEY..."
    local aes_key=$("$PYTHON_BIN" -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
    if [ $? -ne 0 ]; then
        print_error "❌ Erro ao gerar AES_KEY!"
        exit 1
    fi
    
    print_status "🔐 Gerando HMAC_KEY..."
    local hmac_key=$("$PYTHON_BIN" -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
    if [ $? -ne 0 ]; then
        print_error "❌ Erro ao gerar HMAC_KEY!"
        exit 1
    fi
    
    # Fazer backup do .env se existir
    if [ -f "../config/.env" ]; then
        print_status "📋 Fazendo backup do arquivo .env atual..."
        cp ../config/.env ../config/.env.backup.$(date +%Y%m%d_%H%M%S)
        print_success "✅ Backup criado: ../config/.env.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Copiar env.example para .env se não existir
    if [ ! -f "../config/.env" ]; then
        print_status "📋 Copiando env.example para .env..."
        cp ../config/env.example ../config/.env
    fi
    
    # Atualizar as chaves no arquivo .env
    print_status "📝 Atualizando chaves no arquivo .env..."
    
    # Atualizar AES_KEY
    sed -i "s/^AES_KEY=.*/AES_KEY=$aes_key/" ../config/.env
    if [ $? -eq 0 ]; then
        print_success "✅ AES_KEY atualizada"
    else
        print_error "❌ Erro ao atualizar AES_KEY!"
        exit 1
    fi
    
    # Atualizar HMAC_KEY
    sed -i "s/^HMAC_KEY=.*/HMAC_KEY=$hmac_key/" ../config/.env
    if [ $? -eq 0 ]; then
        print_success "✅ HMAC_KEY atualizada"
    else
        print_error "❌ Erro ao atualizar HMAC_KEY!"
        exit 1
    fi
    
    # Verificar se as chaves foram salvas corretamente
    print_status "🔍 Verificando chaves salvas..."
    
    local saved_aes=$(grep "^AES_KEY=" ../config/.env | cut -d'=' -f2-)
    local saved_hmac=$(grep "^HMAC_KEY=" ../config/.env | cut -d'=' -f2-)
    
    if [ "$saved_aes" = "$aes_key" ] && [ "$saved_hmac" = "$hmac_key" ]; then
        print_success "✅ Chaves verificadas e salvas corretamente!"
    else
        print_error "❌ Erro na verificação das chaves!"
        exit 1
    fi
    
    # Mostrar resumo
    print_success "🎉 Chaves geradas com sucesso!"
    print_status "📁 Arquivo: ../config/.env"
    print_status "🔐 AES_KEY: ${aes_key:0:20}..."
    print_status "🔐 HMAC_KEY: ${hmac_key:0:20}..."
    print_status ""
    print_status "🚀 Agora você pode iniciar o IOTRAC com:"
    print_status "   cd ../iotrac-frontend && ./start-iotrac.sh"
}

# Função para verificar chaves existentes
check_keys() {
    print_status "🔍 Verificando chaves existentes..."
    
    if [ ! -f "../config/.env" ]; then
        print_warning "⚠️  Arquivo .env não encontrado"
        return 1
    fi
    
    local aes_key=$(grep "^AES_KEY=" ../config/.env | cut -d'=' -f2-)
    local hmac_key=$(grep "^HMAC_KEY=" ../config/.env | cut -d'=' -f2-)
    
    local aes_valid=false
    local hmac_valid=false
    
    if [ -n "$aes_key" ] && [ "$aes_key" != "sua_chave_aes_de_32_bytes_aqui_substitua_esta_chave" ]; then
        local aes_length=$(echo -n "$aes_key" | wc -c)
        if [ "$aes_length" -ge 32 ]; then
            aes_valid=true
        fi
    fi
    
    if [ -n "$hmac_key" ] && [ "$hmac_key" != "sua_chave_hmac_de_32_bytes_aqui_substitua_esta_chave" ]; then
        local hmac_length=$(echo -n "$hmac_key" | wc -c)
        if [ "$hmac_length" -ge 32 ]; then
            hmac_valid=true
        fi
    fi
    
    if [ "$aes_valid" = true ] && [ "$hmac_valid" = true ]; then
        print_success "✅ Chaves AES e HMAC estão configuradas corretamente!"
        print_status "🔐 AES_KEY: ${aes_key:0:20}..."
        print_status "🔐 HMAC_KEY: ${hmac_key:0:20}..."
        return 0
    else
        print_warning "⚠️  Chaves não configuradas ou inválidas"
        if [ "$aes_valid" = false ]; then
            print_warning "   - AES_KEY: inválida ou não configurada"
        fi
        if [ "$hmac_valid" = false ]; then
            print_warning "   - HMAC_KEY: inválida ou não configurada"
        fi
        return 1
    fi
}

# Função principal
main() {
    print_status "🔑 Gerador de Chaves IOTRAC"
    print_status "================================"
    
    # Verificar se estamos no diretório correto
    if [ ! -f "../config/env.example" ]; then
        print_error "❌ Execute este script dentro do diretório iotrac-backend"
        print_status "Certifique-se de que o arquivo env.example existe"
        exit 1
    fi
    
    # Verificar argumentos
    if [ "$1" = "check" ]; then
        check_keys
        exit $?
    elif [ "$1" = "generate" ] || [ -z "$1" ]; then
        # Verificar se já existem chaves válidas
        if check_keys > /dev/null 2>&1; then
            print_warning "⚠️  Chaves já estão configuradas!"
            read -p "Deseja gerar novas chaves? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_status "Operação cancelada"
                exit 0
            fi
        fi
        
        generate_keys
    else
        print_error "❌ Argumento inválido: $1"
        print_status "Uso: $0 [check|generate]"
        print_status "  check    - Verificar chaves existentes"
        print_status "  generate - Gerar novas chaves (padrão)"
        exit 1
    fi
}

# Executar script
main "$@" 