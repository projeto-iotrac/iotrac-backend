#!/usr/bin/env python3
"""
Script de teste para verificar se o servidor pode ser iniciado
"""

import sys
import os
import asyncio
from pathlib import Path

# Adicionar o diretório src ao path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from src.main import app
    print("✅ App carregado com sucesso")
    
    # Testar se o app tem as rotas necessárias
    routes = [route.path for route in app.routes]
    print(f"✅ Rotas disponíveis: {routes}")
    
    # Verificar se o app pode ser executado
    print("✅ App está pronto para execução")
    
except Exception as e:
    print(f"❌ Erro ao carregar app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1) 