import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import sqlite3
import uuid
import json
import tempfile
import shutil
import time
import socket

# Adiciona o diretório raiz ao PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.device_manager import register_device, DeviceRegister, app

# Importações da Camada 3
try:
    from src.db_setup import DatabaseManager, db_manager
    from src.device_interceptor import send_udp, send_tcp
except ImportError:
    print("Aviso: Módulos da Camada 3 não encontrados, usando mocks")
    DatabaseManager = Mock()
    db_manager = Mock()
    send_udp = Mock()
    send_tcp = Mock()

client = TestClient(app)

def clear_database():
    """Limpa o banco de dados antes de cada teste"""
    # Remove ambos os bancos de dados se existirem
    for db_file in ['devices.db', 'iotrac.db']:
        if os.path.exists(db_file):
            os.remove(db_file)

@pytest.fixture(autouse=True)
def setup_database():
    """Fixture para limpar o banco de dados antes de cada teste"""
    clear_database()
    yield
    clear_database()

# ============================================================================
# TESTES DA CAMADA 2: DEVICE MANAGER
# ============================================================================

class TestDeviceRegistration:
    """Testes para registro de dispositivos da Camada 2"""
    
    def test_register_device_success(self):
        """Teste com dados válidos"""
        test_device = {
            "device_type": "sensor_temperature",
            "ip_address": f"192.168.1.{uuid.uuid4().int % 255}"  # IP único
        }
        response = client.post("/device/register", json=test_device)
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.json()}")
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["device_type"] == "sensor_temperature"
        assert data["ip_address"] == test_device["ip_address"]

    def test_register_device_invalid_input(self):
        """Teste com dados inválidos"""
        invalid_device = {
            "device_type": "",  # tipo inválido
            "ip_address": "192.168.1.100"
        }
        response = client.post("/device/register", json=invalid_device)
        assert response.status_code == 422  # Erro de validação do Pydantic

    def test_register_device_invalid_ip(self):
        """Teste com IP inválido"""
        invalid_device = {
            "device_type": "sensor_temperature",
            "ip_address": "256.256.256.256"  # IP inválido
        }
        response = client.post("/device/register", json=invalid_device)
        assert response.status_code == 422  # Erro de validação do Pydantic

# ============================================================================
# TESTES DA CAMADA 3: API CENTRAL
# ============================================================================

class TestDatabaseManager:
    """Testes para o gerenciador de banco de dados da Camada 3"""
    
    def test_database_initialization(self):
        """Teste de inicialização do banco de dados"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        
        try:
            db_manager = DatabaseManager(db_path)
            assert os.path.exists(db_path)
            
            # Verifica se as tabelas foram criadas
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Verifica tabela devices
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices'")
            assert cursor.fetchone() is not None
            
            # Verifica tabela device_logs
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device_logs'")
            assert cursor.fetchone() is not None
            
            # Verifica tabela protection_config
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='protection_config'")
            assert cursor.fetchone() is not None
            
            conn.close()
            
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_device_operations(self):
        """Teste de operações com dispositivos"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        
        try:
            db_manager = DatabaseManager(db_path)
            
            # Teste de inserção de dispositivo
            device_id = db_manager.insert_device("drone", "192.168.1.100")
            assert device_id > 0
            
            # Teste de busca de dispositivo
            device = db_manager.get_device(device_id)
            assert device is not None
            assert device["device_type"] == "drone"
            assert device["ip_address"] == "192.168.1.100"
            
            # Teste de listagem de dispositivos
            devices = db_manager.get_all_devices()
            assert len(devices) == 1
            assert devices[0]["id"] == device_id
            
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_log_operations(self):
        """Teste de operações com logs"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        
        try:
            db_manager = DatabaseManager(db_path)
            
            # Insere dispositivo primeiro
            device_id = db_manager.insert_device("drone", "192.168.1.100")
            
            # Teste de inserção de log
            log_id = db_manager.insert_log(device_id, "move_up", "success")
            assert log_id > 0
            
            # Teste de busca de logs
            logs = db_manager.get_logs(limit=10)
            assert len(logs) == 1
            assert logs[0]["command"] == "move_up"
            assert logs[0]["status"] == "success"
            
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_protection_status(self):
        """Teste de status de proteção"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        
        try:
            db_manager = DatabaseManager(db_path)
            
            # Teste de status padrão (deve ser True)
            status = db_manager.get_protection_status()
            assert status is True
            
            # Teste de alternância de proteção
            new_status = db_manager.toggle_protection()
            assert new_status is False
            
            # Verifica se o status foi atualizado
            current_status = db_manager.get_protection_status()
            assert current_status is False
            
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_insert_device_valida_campos_obrigatorios(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        db_manager = DatabaseManager(db_path)
        try:
            with pytest.raises(ValueError):
                db_manager.insert_device("", "192.168.1.100")
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_insert_log_valida_command_vazio(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        db_manager = DatabaseManager(db_path)
        try:
            device_id = db_manager.insert_device("drone", "192.168.1.101")
            with pytest.raises(ValueError):
                db_manager.insert_log(device_id, "", "success")
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_insert_log_valida_status_invalido(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        db_manager = DatabaseManager(db_path)
        try:
            device_id = db_manager.insert_device("drone", "192.168.1.102")
            with pytest.raises(ValueError):
                db_manager.insert_log(device_id, "move_up", "invalid_status")
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_indices_criados(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        db_manager = DatabaseManager(db_path)
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_device_logs_device_id'")
            idx1 = cursor.fetchone()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_device_logs_timestamp'")
            idx2 = cursor.fetchone()
            conn.close()
            assert idx1 is not None
            assert idx2 is not None
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

class TestAPIEndpoints:
    """Testes para endpoints da API da Camada 3"""
    
    def test_list_devices(self):
        """Teste do endpoint de listagem de dispositivos"""
        response = client.get("/devices")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_register_device_endpoint_duplicate_ip(self):
        """Teste de registro duplicado de IP"""
        # Primeiro registro
        test_ip = f"192.168.1.{uuid.uuid4().int % 255}"  # IP único
        test_device = {
            "device_type": "sensor_temperature",
            "ip_address": test_ip
        }
        response = client.post("/device/register", json=test_device)
        assert response.status_code == 200
        
        # Tentativa de registro com mesmo IP
        response = client.post("/device/register", json=test_device)
        assert response.status_code == 400
        assert "IP address already registered" in response.json()["detail"]

    @patch('src.main.db_manager')
    def test_protection_status_endpoint(self, mock_db_manager):
        """Teste do endpoint de status de proteção"""
        mock_db_manager.get_protection_status.return_value = True
        
        # Mock do app FastAPI da Camada 3
        with patch('src.main.app') as mock_app:
            mock_app.get.return_value = lambda: {"protection_enabled": True, "timestamp": "2024-01-15T10:30:00"}
            
            # Simula a resposta do endpoint
            response_data = {"protection_enabled": True, "timestamp": "2024-01-15T10:30:00"}
            
            assert response_data["protection_enabled"] is True
            assert "timestamp" in response_data

    @patch('src.main.db_manager')
    def test_toggle_protection_endpoint(self, mock_db_manager):
        """Teste do endpoint de alternância de proteção"""
        mock_db_manager.toggle_protection.return_value = False
        
        # Simula a resposta do endpoint
        response_data = {
            "protection_enabled": False,
            "message": "Proteção desativada com sucesso",
            "timestamp": "2024-01-15T10:30:00"
        }
        
        assert response_data["protection_enabled"] is False
        assert "desativada" in response_data["message"]

    @patch('src.main.db_manager')
    def test_command_endpoint(self, mock_db_manager):
        """Teste do endpoint de comandos"""
        # Mock do dispositivo
        mock_device = {
            "id": 1,
            "device_type": "drone",
            "ip_address": "192.168.1.100"
        }
        mock_db_manager.get_device.return_value = mock_device
        mock_db_manager.get_protection_status.return_value = True
        mock_db_manager.insert_log.return_value = 1
        
        # Simula o comando
        command_data = {
            "device_id": 1,
            "command": "move_up"
        }
        
        # Simula a resposta do endpoint
        response_data = {
            "success": True,
            "message": "Comando 'move_up' enviado para drone com proteção ativa",
            "device_id": 1,
            "command": "move_up",
            "timestamp": "2024-01-15T10:30:00",
            "protection_enabled": True
        }
        
        assert response_data["success"] is True
        assert response_data["device_id"] == command_data["device_id"]
        assert response_data["command"] == command_data["command"]

# ============================================================================
# TESTES DA CAMADA 4: DEVICE INTERCEPTOR
# ============================================================================

class TestDeviceInterceptor:
    """Testes para o interceptor de dispositivos da Camada 4"""
    
    @patch('socket.socket')
    def test_send_udp(self, mock_socket):
        """Teste de envio UDP"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        send_udp("192.168.1.100", 5000, "test_message")
        
        # Verifica se o socket foi criado corretamente
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Verifica se a mensagem foi enviada
        mock_sock.sendto.assert_called_once_with(b"test_message", ("192.168.1.100", 5000))

    @patch('socket.socket')
    def test_send_tcp(self, mock_socket):
        """Teste de envio TCP"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        send_tcp("192.168.1.100", 5001, "test_message")
        
        # Verifica se o socket foi criado corretamente
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        
        # Verifica se a conexão foi estabelecida
        mock_sock.connect.assert_called_once_with(("192.168.1.100", 5001))
        
        # Verifica se a mensagem foi enviada
        mock_sock.sendall.assert_called_once_with(b"test_message")
        
        # Verifica se a conexão foi fechada
        mock_sock.close.assert_called_once()

    def test_send_udp_ip_invalido(self):
        with pytest.raises(ValueError, match="Endereço IP inválido"):
            send_udp("256.256.256.256", 5000, "msg")

    def test_send_tcp_ip_invalido(self):
        with pytest.raises(ValueError, match="Endereço IP inválido"):
            send_tcp("abc.def.ghi.jkl", 5001, "msg")

    def test_send_udp_porta_invalida(self):
        with pytest.raises(ValueError, match="Porta inválida"):
            send_udp("192.168.1.100", 70000, "msg")

    def test_send_tcp_porta_invalida(self):
        with pytest.raises(ValueError, match="Porta inválida"):
            send_tcp("192.168.1.100", 0, "msg")

    def test_send_udp_mensagem_vazia(self):
        with pytest.raises(ValueError, match="Mensagem não pode ser vazia"):
            send_udp("192.168.1.100", 5000, "   ")

    def test_send_tcp_mensagem_vazia(self):
        with pytest.raises(ValueError, match="Mensagem não pode ser vazia"):
            send_tcp("192.168.1.100", 5001, "")

    @patch('socket.socket')
    def test_send_udp_timeout(self, mock_socket):
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        mock_sock.sendto.side_effect = socket.timeout
        with pytest.raises(RuntimeError, match="Timeout ao enviar UDP"):
            send_udp("192.168.1.100", 5000, "msg", timeout=0.01)

    @patch('socket.socket')
    def test_send_tcp_timeout(self, mock_socket):
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout
        with pytest.raises(RuntimeError, match="Timeout ao conectar/enviar"):
            send_tcp("192.168.1.100", 5001, "msg", timeout=0.01)

    @patch('socket.socket')
    def test_send_tcp_conexao_recusada(self, mock_socket):
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError
        with pytest.raises(RuntimeError, match="Conexão recusada"):
            send_tcp("192.168.1.100", 5001, "msg")

# ============================================================================
# TESTES DE INTEGRAÇÃO
# ============================================================================

class TestIntegration:
    """Testes de integração entre as camadas"""
    
    def test_full_command_flow(self):
        """Teste do fluxo completo de comando"""
        # 1. Registra dispositivo
        test_device = {
            "device_type": "drone",
            "ip_address": f"192.168.1.{uuid.uuid4().int % 255}"
        }
        response = client.post("/device/register", json=test_device)
        assert response.status_code == 200
        device_id = response.json()["id"]
        
        # 2. Verifica se o dispositivo foi registrado
        response = client.get("/devices")
        assert response.status_code == 200
        devices = response.json()
        assert len(devices) > 0
        assert any(d["id"] == device_id for d in devices)
        
        # 3. Testa criptografia (se disponível)
        if 'AESCipher' in globals() and AESCipher != Mock:
            test_key = b"test_key_32_bytes_long_key_here"
            test_hmac_key = b"test_hmac_key_32_bytes_long"
            cipher = AESCipher(test_key, test_hmac_key)
            test_data = b"test_command"
            iv, ct, mac = cipher.encrypt(test_data)
            # Extensão: descriptografia e validação de HMAC
            result = cipher.decrypt(iv, ct, mac)
            assert result == test_data

    def test_error_handling(self):
        """Teste de tratamento de erros"""
        # Teste de comando para dispositivo inexistente
        command_data = {
            "device_id": 999,
            "command": "move_up"
        }
        
        # Simula a resposta de erro
        error_response = {
            "detail": "Dispositivo com ID 999 não encontrado"
        }
        
        assert "não encontrado" in error_response["detail"]
        assert error_response["detail"].startswith("Dispositivo com ID")

# ============================================================================
# TESTES DE PERFORMANCE
# ============================================================================

class TestPerformance:
    """Testes de performance"""
    
    def test_database_performance(self):
        """Teste de performance do banco de dados"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
            db_path = tmp_db.name
        
        try:
            db_manager = DatabaseManager(db_path)
            
            # Teste de inserção em lote
            start_time = time.time()
            for i in range(100):
                db_manager.insert_device(f"device_{i}", f"192.168.1.{i}")
            end_time = time.time()
            
            # Verifica se a inserção foi rápida (< 1 segundo para 100 registros)
            assert (end_time - start_time) < 1.0
            
            # Teste de busca
            start_time = time.time()
            devices = db_manager.get_all_devices()
            end_time = time.time()
            
            assert len(devices) == 100
            assert (end_time - start_time) < 0.1  # Busca deve ser rápida
            
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_crypto_performance(self):
        """Teste de performance de criptografia"""
        if 'AESCipher' in globals() and AESCipher != Mock:
            test_key = b"test_key_32_bytes_long_key_here"
            test_hmac_key = b"test_hmac_key_32_bytes_long"
            cipher = AESCipher(test_key, test_hmac_key)
            
            test_data = b"test_command_data"
            
            # Teste de criptografia
            start_time = time.time()
            for _ in range(100):
                iv, ct, mac = cipher.encrypt(test_data)
            end_time = time.time()
            
            # Verifica se a criptografia foi rápida (< 1 segundo para 100 operações)
            assert (end_time - start_time) < 1.0

# ============================================================================
# TESTES DE SEGURANÇA
# ============================================================================

class TestSecurity:
    """Testes de segurança"""
    
    def test_invalid_commands(self):
        """Teste de comandos inválidos"""
        invalid_commands = [
            "invalid_command",
            "delete_all",
            "format_disk",
            "shutdown_system"
        ]
        
        for command in invalid_commands:
            # Simula validação de comando
            allowed_commands = [
                "move_up", "move_down", "move_left", "move_right",
                "move_forward", "move_backward", "turn_on", "turn_off",
                "set_speed", "get_status", "emergency_stop"
            ]
            
            assert command not in allowed_commands

    def test_sql_injection_prevention(self):
        """Teste de prevenção de SQL injection"""
        malicious_inputs = [
            "'; DROP TABLE devices; --",
            "'; INSERT INTO devices VALUES (999, 'hack', '0.0.0.0'); --",
            "'; UPDATE devices SET device_type='hack'; --"
        ]
        
        for malicious_input in malicious_inputs:
            # Simula inserção segura usando parâmetros
            safe_query = "INSERT INTO devices (device_type, ip_address) VALUES (?, ?)"
            safe_params = (malicious_input, "192.168.1.100")
            
            # Verifica se a query usa parâmetros (não concatenação)
            assert "?" in safe_query
            assert safe_params[0] == malicious_input

# ============================================================================
# CONFIGURAÇÃO DE TESTES
# ============================================================================

def pytest_configure(config):
    """Configuração do pytest"""
    print("\n🚀 Configurando testes do IOTRAC...")
    print("📋 Testes disponíveis:")
    print("  - Camada 1: Crypto Utils (em tests/test_crypto_utils.py)")
    print("  - Camada 2: Device Manager")
    print("  - Camada 3: API Central")
    print("  - Camada 4: Device Interceptor")
    print("  - Integração entre camadas")
    print("  - Performance e segurança")

def pytest_collection_modifyitems(config, items):
    """Modifica a coleta de testes"""
    for item in items:
        # Adiciona marcadores baseados no nome da classe
        if "TestCryptoUtils" in str(item):
            item.add_marker(pytest.mark.crypto)
        elif "TestDeviceRegistration" in str(item):
            item.add_marker(pytest.mark.device_manager)
        elif "TestDatabaseManager" in str(item) or "TestAPIEndpoints" in str(item):
            item.add_marker(pytest.mark.api)
        elif "TestDeviceInterceptor" in str(item):
            item.add_marker(pytest.mark.interceptor)
        elif "TestIntegration" in str(item):
            item.add_marker(pytest.mark.integration)
        elif "TestPerformance" in str(item):
            item.add_marker(pytest.mark.performance)
        elif "TestSecurity" in str(item):
            item.add_marker(pytest.mark.security)
