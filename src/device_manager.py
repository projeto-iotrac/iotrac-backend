# iot_protection_app.py
# Módulo FastAPI para gerenciamento de dispositivos IoT
# Bibliotecas: fastapi, sqlite3, pydantic

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, IPvAnyAddress
from typing import Annotated
from typing import List
from pydantic.types import StringConstraints
import sqlite3

# Inicializa o app FastAPI
app = FastAPI(title="IoT Protection App")

# Define o modelo de dados para registro de dispositivo
class DeviceRegister(BaseModel):
    device_type: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]  # Ex: drone, vehicle, lamp
    ip_address: IPvAnyAddress

# Define o modelo de resposta para listagem de dispositivos
class DeviceOut(BaseModel):
    id: int
    device_type: str
    ip_address: str

# Função utilitária para inicializar o banco de dados SQLite e criar a tabela se não existir
def init_db():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_type TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE
        )
    ''')
    conn.commit()
    conn.close()

# Inicializa o banco ao iniciar o app
init_db()
# Endpoint para registrar um novo dispositivo IoT
@app.post("/device/register", response_model=DeviceOut)
def register_device(device: DeviceRegister):
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    try:
        # Insere o dispositivo na tabela
        cursor.execute(
            "INSERT INTO devices (device_type, ip_address) VALUES (?, ?)",
            (device.device_type, str(device.ip_address))
        )
        conn.commit()
        device_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="IP address already registered")
    conn.close()
    # Retorna os dados do dispositivo registrado
    return DeviceOut(id=device_id, device_type=device.device_type, ip_address=str(device.ip_address))
# Endpoint para listar todos os dispositivos registrados
@app.get("/devices", response_model=List[DeviceOut])
def list_devices():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, device_type, ip_address FROM devices")
    rows = cursor.fetchall()
    conn.close()
    # Converte os resultados para o modelo de resposta
    return [DeviceOut(id=row[0], device_type=row[1], ip_address=row[2]) for row in rows]

# Para rodar: uvicorn iot_protection_app:app --reload
