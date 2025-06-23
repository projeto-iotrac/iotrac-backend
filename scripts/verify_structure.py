#!/usr/bin/env python3
"""
Script de verificação da estrutura organizada do IOTRAC Backend
Verifica se todos os arquivos estão nos lugares corretos e se as referências estão atualizadas
"""

import os
import sys
from pathlib import Path

def print_status(message, status="INFO"):
    """Imprime mensagem com status colorido"""
    colors = {
        "INFO": "\033[94m",    # Azul
        "SUCCESS": "\033[92m", # Verde
        "WARNING": "\033[93m", # Amarelo
        "ERROR": "\033[91m"    # Vermelho
    }
    reset = "\033[0m"
    print(f"{colors.get(status, '')}[{status}]{reset} {message}")

def check_directory_structure():
    """Verifica se a estrutura de diretórios está correta"""
    print_status("🔍 Verificando estrutura de diretórios...")
    
    expected_dirs = [
        "src",
        "scripts", 
        "config",
        "database",
        "tests",
        "venv"
    ]
    
    missing_dirs = []
    for dir_name in expected_dirs:
        if not os.path.exists(dir_name):
            missing_dirs.append(dir_name)
        else:
            print_status(f"✅ Diretório {dir_name}/ encontrado", "SUCCESS")
    
    if missing_dirs:
        print_status(f"❌ Diretórios ausentes: {', '.join(missing_dirs)}", "ERROR")
        return False
    
    return True

def check_script_files():
    """Verifica se os scripts estão na pasta correta"""
    print_status("🔍 Verificando scripts...")
    
    expected_scripts = [
        "scripts/start_server.py",
        "scripts/clear_devices.py", 
        "scripts/generate_keys.sh"
    ]
    
    missing_scripts = []
    for script in expected_scripts:
        if not os.path.exists(script):
            missing_scripts.append(script)
        else:
            print_status(f"✅ Script {script} encontrado", "SUCCESS")
    
    if missing_scripts:
        print_status(f"❌ Scripts ausentes: {', '.join(missing_scripts)}", "ERROR")
        return False
    
    return True

def check_config_files():
    """Verifica se os arquivos de configuração estão na pasta correta"""
    print_status("🔍 Verificando arquivos de configuração...")
    
    expected_configs = [
        "config/env.example",
        "config/pytest.ini"
    ]
    
    missing_configs = []
    for config in expected_configs:
        if not os.path.exists(config):
            missing_configs.append(config)
        else:
            print_status(f"✅ Config {config} encontrado", "SUCCESS")
    
    # Verificar se .env existe (opcional)
    if os.path.exists("config/.env"):
        print_status("✅ Arquivo config/.env encontrado", "SUCCESS")
    else:
        print_status("⚠️ Arquivo config/.env não encontrado (normal se não configurado)", "WARNING")
    
    if missing_configs:
        print_status(f"❌ Configs ausentes: {', '.join(missing_configs)}", "ERROR")
        return False
    
    return True

def check_database_files():
    """Verifica se os arquivos de banco de dados estão na pasta correta"""
    print_status("🔍 Verificando arquivos de banco de dados...")
    
    if os.path.exists("database/iotrac.db"):
        print_status("✅ Banco de dados database/iotrac.db encontrado", "SUCCESS")
        return True
    else:
        print_status("⚠️ Banco de dados não encontrado (normal se não inicializado)", "WARNING")
        return True

def check_source_files():
    """Verifica se os arquivos fonte estão na pasta correta"""
    print_status("🔍 Verificando arquivos fonte...")
    
    expected_sources = [
        "src/main.py",
        "src/config.py",
        "src/crypto_utils.py", 
        "src/db_setup.py",
        "src/device_manager.py",
        "src/device_interceptor.py"
    ]
    
    missing_sources = []
    for source in expected_sources:
        if not os.path.exists(source):
            missing_sources.append(source)
        else:
            print_status(f"✅ Source {source} encontrado", "SUCCESS")
    
    if missing_sources:
        print_status(f"❌ Sources ausentes: {', '.join(missing_sources)}", "ERROR")
        return False
    
    return True

def check_path_references():
    """Verifica se as referências de caminho estão corretas"""
    print_status("🔍 Verificando referências de caminho...")
    
    # Verificar se clear_devices.py tem o caminho correto do banco
    try:
        with open("scripts/clear_devices.py", "r") as f:
            content = f.read()
            if "database" in content and "iotrac.db" in content:
                print_status("✅ clear_devices.py tem caminho correto do banco", "SUCCESS")
            else:
                print_status("❌ clear_devices.py tem caminho incorreto do banco", "ERROR")
                return False
    except FileNotFoundError:
        print_status("❌ scripts/clear_devices.py não encontrado", "ERROR")
        return False
    
    # Verificar se start_server.py tem os caminhos corretos
    try:
        with open("scripts/start_server.py", "r") as f:
            content = f.read()
            if "../src/main.py" in content and "../venv/bin/python" in content:
                print_status("✅ start_server.py tem caminhos corretos", "SUCCESS")
            else:
                print_status("❌ start_server.py tem caminhos incorretos", "ERROR")
                return False
    except FileNotFoundError:
        print_status("❌ scripts/start_server.py não encontrado", "ERROR")
        return False
    
    return True

def main():
    """Função principal de verificação"""
    print_status("🚀 Iniciando verificação da estrutura do IOTRAC Backend", "INFO")
    print_status("=" * 60, "INFO")
    
    checks = [
        check_directory_structure,
        check_script_files,
        check_config_files,
        check_database_files,
        check_source_files,
        check_path_references
    ]
    
    all_passed = True
    for check in checks:
        if not check():
            all_passed = False
        print()
    
    print_status("=" * 60, "INFO")
    if all_passed:
        print_status("🎉 Todas as verificações passaram! Estrutura organizada com sucesso!", "SUCCESS")
        print_status("📁 Estrutura final:", "INFO")
        print_status("   ├── src/           # Código fonte", "INFO")
        print_status("   ├── scripts/       # Scripts utilitários", "INFO")
        print_status("   ├── config/        # Arquivos de configuração", "INFO")
        print_status("   ├── database/      # Banco de dados", "INFO")
        print_status("   └── tests/         # Testes", "INFO")
        return 0
    else:
        print_status("❌ Algumas verificações falharam. Verifique os erros acima.", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 