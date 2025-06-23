import pytest
import os
import sys

# Configurar variáveis de ambiente para os testes
os.environ['AES_KEY'] = 'ION3dg3B/v/GZmBIv4R1G3Zar/Ua1lmTnxxTOtatliw='
os.environ['HMAC_KEY'] = 'RlPRtj+ni/2JaM/3SP9GeADjkSnrVA5mB7eDt7oLgnE='
os.environ['JWT_SECRET'] = 'iotrac_secret_key_for_tests'
os.environ['SERVER_PORT'] = '8000'
os.environ['SERVER_HOST'] = '0.0.0.0'

def pytest_configure(config):
    """Configurar pytest para mostrar output detalhado"""
    config.option.verbose = 2
    config.option.capture = "no"
    config.option.tbstyle = "short"
    config.option.disable_warnings = True
    config.option.showlocals = False
    
    # Configurar asyncio para evitar warnings
    config.option.asyncio_mode = "auto"
    config.option.asyncio_default_fixture_loop_scope = "function"
    config.option.asyncio_default_test_loop_scope = "function"
    
    # Forçar stdout para mostrar prints
    sys.stdout.flush()

def pytest_collection_modifyitems(config, items):
    """Modificar a coleta de items para forçar output detalhado"""
    pass  # Removido marker inexistente

def pytest_runtest_setup(item):
    """Forçar prints durante a execução dos tests"""
    pass

def pytest_runtest_teardown(item, nextitem):
    """Garantir que prints sejam mostrados após cada test"""
    sys.stdout.flush() 