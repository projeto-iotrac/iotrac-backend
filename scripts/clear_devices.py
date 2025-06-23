#!/usr/bin/env python3
"""
Script para limpar todos os dispositivos do banco de dados IOTRAC
Uso: python clear_devices.py
"""

import sqlite3
import os
from datetime import datetime

# Caminho do banco de dados
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'database', 'iotrac.db'))

def clear_all_devices():
    """Remove todos os dispositivos do banco de dados"""
    
    if not os.path.exists(DB_PATH):
        print("❌ Banco de dados não encontrado!")
        return
    
    try:
        # Conecta ao banco
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Conta dispositivos antes
        cursor.execute("SELECT COUNT(*) FROM devices")
        count_before = cursor.fetchone()[0]
        
        if count_before == 0:
            print("✅ Nenhum dispositivo encontrado no banco de dados!")
            return
        
        # Remove todos os dispositivos
        cursor.execute("DELETE FROM devices")
        
        # Remove logs relacionados
        cursor.execute("DELETE FROM device_logs")
        
        # Confirma as mudanças
        conn.commit()
        
        # Conta dispositivos depois
        cursor.execute("SELECT COUNT(*) FROM devices")
        count_after = cursor.fetchone()[0]
        
        # Fecha conexão
        conn.close()
        
        print(f"🧹 Limpeza concluída!")
        print(f"📊 Dispositivos removidos: {count_before}")
        print(f"📊 Logs removidos: Todos")
        print(f"📊 Dispositivos restantes: {count_after}")
        print(f"⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except Exception as e:
        print(f"❌ Erro ao limpar dispositivos: {e}")

if __name__ == "__main__":
    print("🚀 IOTRAC - Limpeza de Dispositivos")
    print("=" * 40)
    
    print("🔄 Limpando todos os dispositivos...")
    clear_all_devices()
    print("\n✅ Limpeza concluída! Agora você pode adicionar apenas os dispositivos que desejar.") 