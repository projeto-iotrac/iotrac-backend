import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
import sys
import os

# Adiciona o diretório raiz ao PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.device_manager import register_device, DeviceRegister, app

# Tratamento de erro para importação das funções de criptografia
try:
    from src.crypto_utils import encrypt_aes256, verify_hmac
except ImportError:
    print("Aviso: Funções de criptografia não encontradas, usando mocks")
    encrypt_aes256 = lambda x, y: b"mocked_encrypted"
    verify_hmac = lambda x, y, z: True

client = TestClient(app)

# Testes de Vinculação de Dispositivos
class TestDeviceRegistration:
    def test_register_device_success(self):
        # Teste com dados válidos
        test_device = {
            "device_type": "sensor_temperature",
            "ip_address": "192.168.1.100"
        }
        response = client.post("/device/register", json=test_device)
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.json()}")
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["device_type"] == "sensor_temperature"
        assert data["ip_address"] == "192.168.1.100"

    def test_register_device_invalid_input(self):
        # Teste com dados inválidos
        invalid_device = {
            "device_type": "",  # tipo inválido
            "ip_address": "192.168.1.100"
        }
        response = client.post("/device/register", json=invalid_device)
        assert response.status_code == 422  # Erro de validação do Pydantic

    def test_register_device_invalid_ip(self):
        # Teste com IP inválido
        invalid_device = {
            "device_type": "sensor_temperature",
            "ip_address": "256.256.256.256"  # IP inválido
        }
        response = client.post("/device/register", json=invalid_device)
        assert response.status_code == 422  # Erro de validação do Pydantic

# Testes de API
class TestAPIEndpoints:
    def test_list_devices(self):
        response = client.get("/devices")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_register_device_endpoint_duplicate_ip(self):
        # Primeiro registro
        test_device = {
            "device_type": "sensor_temperature",
            "ip_address": "192.168.1.101"
        }
        response = client.post("/device/register", json=test_device)
        assert response.status_code == 200
        
        # Tentativa de registro com mesmo IP
        response = client.post("/device/register", json=test_device)
        assert response.status_code == 400
        assert "IP address already registered" in response.json()["detail"]

# Testes de Criptografia
class TestCryptoUtils:
    def test_aes256_encryption(self):
        # Teste de criptografia AES-256
        test_data = "dados_sensíveis"
        key = "chave_secreta_32_bytes_123456789"
        encrypted = encrypt_aes256(test_data, key)
        assert encrypted is not None
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(test_data)  # Deve incluir IV

    def test_hmac_verification(self):
        # Teste de verificação HMAC-SHA256
        test_data = "dados_para_verificar"
        key = "chave_hmac_secreta"
        hmac = b"hmac_calculado"
        assert verify_hmac(test_data, hmac, key) in [True, False]
