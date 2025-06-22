# iot_protection_app.py
# Módulo FastAPI para gerenciamento de dispositivos IoT
# Bibliotecas: fastapi, sqlite3, pydantic

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError
from typing import Annotated, List
from pydantic.types import StringConstraints
from ipaddress import ip_address, AddressValueError
import sqlite3
import os

# Caminho absoluto do banco de dados na raiz do projeto
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'iotrac.db'))

# Inicializa o app FastAPI
app = FastAPI(title="IoT Protection App")

# Define o modelo de dados para registro de dispositivo
class DeviceRegister(BaseModel):
    device_type: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]  # Ex: drone, vehicle, lamp
    ip_address: str  # Aceita como string

    def __init__(self, **data):
        try:
            # Valida e converte ip_address para garantir que é um IP válido
            ip_address(data.get("ip_address"))
            super().__init__(**data)
        except AddressValueError:
            raise ValueError("Formato de endereço IP inválido")

# Define o modelo de resposta para listagem de dispositivos
class DeviceOut(BaseModel):
    id: int
    device_type: str
    ip_address: str

# Função utilitária para inicializar o banco de dados SQLite e criar a tabela se não existir
def init_db():
    """Inicializa o banco de dados e cria as tabelas necessárias"""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cursor = conn.cursor()
        
        # Cria a tabela se não existir
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_type TEXT NOT NULL,
                ip_address TEXT NOT NULL UNIQUE,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Garante que as mudanças sejam salvas
        conn.commit()
        conn.close()
        
        print(f"Banco de dados inicializado: {DB_PATH}")
        
    except Exception as e:
        print(f"Erro ao inicializar banco de dados: {e}")
        raise

# Inicializa o banco ao importar o módulo
init_db()

# Endpoint para registrar um novo dispositivo IoT
@app.post("/device/register", response_model=DeviceOut)
def register_device(device: DeviceRegister):
    """Registra um novo dispositivo no banco de dados"""
    # Garante que o banco está inicializado
    init_db()
    
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    try:
        # Insere o dispositivo na tabela
        cursor.execute(
            "INSERT INTO devices (device_type, ip_address) VALUES (?, ?)",
            (device.device_type, device.ip_address)  # ip_address já é string
        )
        conn.commit()
        device_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="IP address already registered")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))
    conn.close()
    # Retorna os dados do dispositivo registrado
    return DeviceOut(id=device_id, device_type=device.device_type, ip_address=device.ip_address)

# Endpoint para listar todos os dispositivos registrados
@app.get("/devices", response_model=List[DeviceOut])
def list_devices():
    """Lista todos os dispositivos registrados"""
    # Garante que o banco está inicializado
    init_db()
    
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT id, device_type, ip_address FROM devices")
    rows = cursor.fetchall()
    conn.close()
    # Converte os resultados para o modelo de resposta
    return [DeviceOut(id=row[0], device_type=row[1], ip_address=row[2]) for row in rows]

# Endpoint para deletar dispositivo por Id
@app.delete("/device/{device_id}", response_model=DeviceOut)
def delete_device_by_id(device_id: int):
    """Exclui um dispositivo pelo ID"""
    init_db()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    # Busca o dispositivo antes de deletar para retornar os dados
    cursor.execute("SELECT id, device_type, ip_address FROM devices WHERE id = ?", (device_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    # Deleta o dispositivo
    cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return DeviceOut(id=row[0], device_type=row[1], ip_address=row[2])
# Para rodar: uvicorn src.device_manager:app --reload
