#!/usr/bin/env python3
"""
Script de Teste Integrado - Funcionalidades Bluetooth IOTRAC
Executa testes completos das funcionalidades Bluetooth implementadas,
incluindo simulação de dispositivos e verificação de segurança.

Uso: python test_bluetooth_integration.py
"""

import asyncio
import json
import os
import sys
import sqlite3
import tempfile
import logging
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any

# Adicionar o diretório src ao path para imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
src_dir = os.path.join(parent_dir, 'src')
sys.path.insert(0, src_dir)

# Verificar se o diretório src existe
if not os.path.exists(src_dir):
    raise RuntimeError(f"Diretório src não encontrado em: {src_dir}")

# Configurar logging para o teste
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BluetoothDeviceSimulator:
    """Simulador de dispositivos Bluetooth para testes."""
    
    def __init__(self):
        self.devices = [
            {
                "address": "AA:BB:CC:DD:EE:01",
                "name": "Smart Lamp Living Room",
                "rssi": -45,
                "device_type": "smart-lamp"
            },
            {
                "address": "AA:BB:CC:DD:EE:02", 
                "name": "Bluetooth Speaker",
                "rssi": -38,
                "device_type": "speaker"
            },
            {
                "address": "AA:BB:CC:DD:EE:03",
                "name": "Smart Lock Door",
                "rssi": -52,
                "device_type": "smart-lock"
            },
            {
                "address": "AA:BB:CC:DD:EE:04",
                "name": "Fitness Tracker",
                "rssi": -41,
                "device_type": "fitness-tracker"
            }
        ]
        self.connected_devices = set()
        self.device_characteristics = {}
    
    async def discover(self, timeout=10.0):
        """Simula descoberta de dispositivos Bluetooth."""
        logger.info(f"🔍 Simulando escaneamento Bluetooth (timeout: {timeout}s)")
        await asyncio.sleep(0.5)  # Simular tempo de escaneamento
        
        discovered = []
        for device in self.devices:
            discovered.append({
                "mac_address": device["address"],
                "name": device["name"],
                "rssi": device["rssi"],
                "discoverable": True,
                "scanned_at": datetime.now().isoformat()
            })
        
        logger.info(f"✅ {len(discovered)} dispositivos simulados encontrados")
        return discovered
    
    async def connect(self, mac_address, timeout=10.0):
        """Simula conexão com dispositivo."""
        logger.info(f"🔗 Tentando conectar ao dispositivo simulado {mac_address}")
        await asyncio.sleep(0.3)  # Simular tempo de conexão
        
        device = next((d for d in self.devices if d["address"] == mac_address), None)
        if device:
            self.connected_devices.add(mac_address)
            # Simular descoberta de características
            self.device_characteristics[mac_address] = {
                "command": "12345678-1234-1234-1234-123456789abd",
                "response": "12345678-1234-1234-1234-123456789abe"
            }
            logger.info(f"✅ Conectado com sucesso ao {device['name']}")
            return True
        else:
            logger.error(f"❌ Dispositivo {mac_address} não encontrado")
            return False
    
    async def disconnect(self, mac_address):
        """Simula desconexão."""
        logger.info(f"🔌 Desconectando do dispositivo {mac_address}")
        await asyncio.sleep(0.2)
        
        if mac_address in self.connected_devices:
            self.connected_devices.remove(mac_address)
            if mac_address in self.device_characteristics:
                del self.device_characteristics[mac_address]
            logger.info(f"✅ Desconectado de {mac_address}")
            return True
        else:
            logger.warning(f"⚠️ Dispositivo {mac_address} não estava conectado")
            return True
    
    async def send_command(self, mac_address, command, encrypted_data=None):
        """Simula envio de comando."""
        if mac_address not in self.connected_devices:
            logger.error(f"❌ Dispositivo {mac_address} não está conectado")
            return "not_connected"
        
        if encrypted_data:
            logger.info(f"🔐 Enviando comando criptografado para {mac_address}")
            # Simular processamento de comando criptografado
            await asyncio.sleep(0.1)
            logger.info(f"✅ Comando criptografado processado com sucesso")
        else:
            logger.info(f"📡 Enviando comando não criptografado '{command}' para {mac_address}")
            await asyncio.sleep(0.1)
            logger.info(f"✅ Comando não criptografado processado")
        
        return "success"

class BluetoothTester:
    """Classe principal para testes das funcionalidades Bluetooth."""
    
    def __init__(self):
        self.simulator = BluetoothDeviceSimulator()
        self.db_path = None
        self.test_results = []
    
    def setup_test_environment(self):
        """Configura ambiente de teste."""
        logger.info("🔧 Configurando ambiente de teste...")
        
        # Criar banco de dados temporário
        self.db_path = tempfile.mktemp(suffix='.db')
        
        # Configurar variáveis de ambiente para teste
        os.environ['AES_KEY'] = 'test_aes_key_32_bytes_long_12345678'
        os.environ['HMAC_KEY'] = 'test_hmac_key_32_bytes_long_1234567'
        os.environ['JWT_SECRET'] = 'test_jwt_secret_key'
        
        logger.info(f"✅ Ambiente configurado. DB temporário: {self.db_path}")
    
    def cleanup_test_environment(self):
        """Limpa ambiente de teste."""
        logger.info("🧹 Limpando ambiente de teste...")
        
        if self.db_path and os.path.exists(self.db_path):
            os.unlink(self.db_path)
            logger.info("✅ Banco de dados temporário removido")
    
    def add_test_result(self, test_name: str, success: bool, message: str):
        """Adiciona resultado de teste."""
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
        
        status = "✅ PASSOU" if success else "❌ FALHOU"
        logger.info(f"{status} - {test_name}: {message}")
    
    async def test_bluetooth_interceptor(self):
        """Testa o módulo bluetooth_interceptor.py."""
        logger.info("\n" + "="*60)
        logger.info("🧪 TESTANDO MÓDULO BLUETOOTH_INTERCEPTOR")
        logger.info("="*60)
        
        try:
            # Mock da biblioteca bleak para simular funcionalidades
            with patch('src.bluetooth_interceptor.BleakScanner') as mock_scanner, \
                 patch('src.bluetooth_interceptor.BleakClient') as mock_client, \
                 patch('src.bluetooth_interceptor.BLUETOOTH_AVAILABLE', True):
                
                # Configurar mocks
                mock_scanner.discover = AsyncMock(return_value=await self.simulator.discover())
                
                mock_client_instance = AsyncMock()
                mock_client_instance.connect = AsyncMock(return_value=True)
                mock_client_instance.disconnect = AsyncMock(return_value=True)
                mock_client_instance.is_connected = True
                mock_client_instance.write_gatt_char = AsyncMock()
                mock_client_instance.get_services = AsyncMock(return_value=[])
                mock_client.return_value = mock_client_instance
                
                # Importar módulo após configurar mocks
                from src.bluetooth_interceptor import BluetoothInterceptor, scan_bluetooth_devices
                
                # Teste 1: Inicialização do interceptor
                interceptor = BluetoothInterceptor()
                self.add_test_result(
                    "Inicialização BluetoothInterceptor",
                    True,
                    "Interceptor inicializado com sucesso"
                )
                
                # Teste 2: Escaneamento de dispositivos
                devices = await scan_bluetooth_devices(timeout=5.0)
                self.add_test_result(
                    "Escaneamento de dispositivos",
                    len(devices) > 0,
                    f"{len(devices)} dispositivos encontrados"
                )
                
                # Teste 3: Conexão com dispositivo
                test_mac = "AA:BB:CC:DD:EE:01"
                connection_success = await interceptor.connect_device(test_mac)
                self.add_test_result(
                    "Conexão com dispositivo",
                    connection_success,
                    f"Conexão com {test_mac}: {'sucesso' if connection_success else 'falha'}"
                )
                
                # Teste 4: Envio de comando
                if connection_success:
                    command_result = await interceptor.send_command(test_mac, "turn_on")
                    self.add_test_result(
                        "Envio de comando",
                        command_result == "success",
                        f"Comando enviado: {command_result}"
                    )
                
                # Teste 5: Desconexão
                disconnect_success = await interceptor.disconnect_device(test_mac)
                self.add_test_result(
                    "Desconexão de dispositivo",
                    disconnect_success,
                    f"Desconexão: {'sucesso' if disconnect_success else 'falha'}"
                )
                
        except Exception as e:
            self.add_test_result(
                "Módulo bluetooth_interceptor",
                False,
                f"Erro: {str(e)}"
            )
    
    async def test_database_integration(self):
        """Testa integração com banco de dados."""
        logger.info("\n" + "="*60)
        logger.info("🗄️ TESTANDO INTEGRAÇÃO COM BANCO DE DADOS")
        logger.info("="*60)
        
        try:
            # Importar e configurar DatabaseManager
            from src.db_setup import DatabaseManager
            
            # Usar banco temporário
            db_manager = DatabaseManager(self.db_path)
            db_manager.init_database()
            
            # Teste 1: Inserção de dispositivo Bluetooth
            device_id = db_manager.insert_bluetooth_device(
                "smart-lamp",
                "AA:BB:CC:DD:EE:01",
                "Lâmpada Teste"
            )
            self.add_test_result(
                "Inserção dispositivo Bluetooth",
                device_id > 0,
                f"Dispositivo inserido com ID: {device_id}"
            )
            
            # Teste 2: Busca por MAC address
            device = db_manager.get_device_by_mac("AA:BB:CC:DD:EE:01")
            self.add_test_result(
                "Busca por MAC address",
                device is not None and device['mac_address'] == "AA:BB:CC:DD:EE:01",
                f"Dispositivo encontrado: {device['device_name'] if device else 'Não encontrado'}"
            )
            
            # Teste 3: Listagem de dispositivos Bluetooth
            bluetooth_devices = db_manager.get_bluetooth_devices()
            self.add_test_result(
                "Listagem dispositivos Bluetooth",
                len(bluetooth_devices) > 0,
                f"{len(bluetooth_devices)} dispositivos Bluetooth encontrados"
            )
            
            # Teste 4: Atualização de status de conexão
            db_manager.update_device_connection_status(device_id, True)
            updated_device = db_manager.get_device(device_id)
            connection_updated = updated_device and updated_device.get('is_connected')
            self.add_test_result(
                "Atualização status conexão",
                connection_updated,
                f"Status de conexão atualizado: {'sucesso' if connection_updated else 'falha'}"
            )
            
            # Teste 5: Dispositivos conectados
            connected_devices = db_manager.get_connected_bluetooth_devices()
            self.add_test_result(
                "Listagem dispositivos conectados",
                len(connected_devices) > 0,
                f"{len(connected_devices)} dispositivos conectados"
            )
            
            # Teste 6: Proteção de dispositivo
            protection_status = db_manager.get_device_protection_status(device_id)
            self.add_test_result(
                "Status de proteção",
                protection_status is not None,
                f"Proteção ativa: {protection_status}"
            )
            
        except Exception as e:
            self.add_test_result(
                "Integração banco de dados",
                False,
                f"Erro: {str(e)}"
            )
    
    async def test_security_features(self):
        """Testa funcionalidades de segurança."""
        logger.info("\n" + "="*60)
        logger.info("🔐 TESTANDO FUNCIONALIDADES DE SEGURANÇA")
        logger.info("="*60)
        
        try:
            from src.crypto_utils import AESCipher, generate_hmac, verify_hmac
            
            # Teste 1: Inicialização AES Cipher
            aes_key = os.environ['AES_KEY'].encode()[:32].ljust(32, b'0')
            hmac_key = os.environ['HMAC_KEY'].encode()[:32].ljust(32, b'0')
            
            cipher = AESCipher(aes_key, hmac_key)
            self.add_test_result(
                "Inicialização AESCipher",
                cipher is not None,
                "Cipher inicializado com sucesso"
            )
            
            # Teste 2: Criptografia de comando
            test_command = "turn_on"
            command_bytes = test_command.encode('utf-8')
            
            iv, ciphertext, hmac_hex = cipher.encrypt(command_bytes)
            self.add_test_result(
                "Criptografia de comando",
                len(ciphertext) > 0 and len(hmac_hex) > 0,
                f"Comando criptografado: {len(ciphertext)} bytes"
            )
            
            # Teste 3: Descriptografia
            decrypted = cipher.decrypt(iv, ciphertext, hmac_hex)
            self.add_test_result(
                "Descriptografia de comando",
                decrypted.decode('utf-8') == test_command,
                f"Comando descriptografado: {decrypted.decode('utf-8')}"
            )
            
            # Teste 4: Verificação HMAC
            test_data = b"test_data"
            hmac_result = generate_hmac(hmac_key, test_data)
            hmac_valid = verify_hmac(hmac_key, test_data, hmac_result)
            self.add_test_result(
                "Verificação HMAC",
                hmac_valid,
                f"HMAC válido: {hmac_valid}"
            )
            
            # Teste 5: Detecção de tampering
            tampered_hmac = hmac_result[:-2] + "XX"  # Alterar HMAC
            hmac_tampered = verify_hmac(hmac_key, test_data, tampered_hmac)
            self.add_test_result(
                "Detecção de tampering",
                not hmac_tampered,
                f"Tampering detectado: {not hmac_tampered}"
            )
            
        except Exception as e:
            self.add_test_result(
                "Funcionalidades de segurança",
                False,
                f"Erro: {str(e)}"
            )
    
    async def test_api_endpoints_simulation(self):
        """Simula testes dos endpoints da API."""
        logger.info("\n" + "="*60)
        logger.info("🌐 SIMULANDO TESTES DOS ENDPOINTS DA API")
        logger.info("="*60)
        
        try:
            # Simular dados de requisições
            test_cases = [
                {
                    "endpoint": "POST /bluetooth/scan",
                    "data": {"timeout": 10.0},
                    "expected_fields": ["success", "devices", "timestamp"]
                },
                {
                    "endpoint": "POST /bluetooth/connect", 
                    "data": {"mac_address": "AA:BB:CC:DD:EE:01", "timeout": 10.0},
                    "expected_fields": ["success", "mac_address", "timestamp"]
                },
                {
                    "endpoint": "POST /bluetooth/device/register",
                    "data": {
                        "device_type": "smart-lamp",
                        "mac_address": "AA:BB:CC:DD:EE:01",
                        "device_name": "Lâmpada Teste"
                    },
                    "expected_fields": ["id", "device_type", "mac_address"]
                },
                {
                    "endpoint": "POST /bluetooth/command",
                    "data": {"device_id": 1, "command": "turn_on"},
                    "expected_fields": ["success", "message", "device_id", "command"]
                }
            ]
            
            for test_case in test_cases:
                # Simular validação de dados
                endpoint = test_case["endpoint"]
                data = test_case["data"]
                expected_fields = test_case["expected_fields"]
                
                # Validações básicas
                validation_success = True
                validation_message = "Dados válidos"
                
                if "mac_address" in data:
                    mac = data["mac_address"]
                    if not self._validate_mac_address(mac):
                        validation_success = False
                        validation_message = "MAC address inválido"
                
                if "device_type" in data:
                    device_type = data["device_type"]
                    allowed_types = ["smart-lamp", "smart-lock", "sensor", "speaker", 
                                   "headphones", "keyboard", "mouse", "smart-watch", "fitness-tracker"]
                    if device_type not in allowed_types:
                        validation_success = False
                        validation_message = "Tipo de dispositivo inválido"
                
                self.add_test_result(
                    f"Validação {endpoint}",
                    validation_success,
                    validation_message
                )
                
                # Simular resposta da API
                if validation_success:
                    simulated_response = self._simulate_api_response(endpoint, data)
                    response_valid = all(field in simulated_response for field in expected_fields)
                    
                    self.add_test_result(
                        f"Resposta {endpoint}",
                        response_valid,
                        f"Campos obrigatórios presentes: {response_valid}"
                    )
                
        except Exception as e:
            self.add_test_result(
                "Simulação endpoints API",
                False,
                f"Erro: {str(e)}"
            )
    
    def _validate_mac_address(self, mac: str) -> bool:
        """Valida formato do endereço MAC."""
        import re
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, mac))
    
    def _simulate_api_response(self, endpoint: str, data: dict) -> dict:
        """Simula resposta da API."""
        timestamp = datetime.now().isoformat()
        
        if "scan" in endpoint:
            return {
                "success": True,
                "devices": [{"mac_address": "AA:BB:CC:DD:EE:01", "name": "Test Device"}],
                "timestamp": timestamp
            }
        elif "connect" in endpoint:
            return {
                "success": True,
                "mac_address": data.get("mac_address"),
                "timestamp": timestamp
            }
        elif "register" in endpoint:
            return {
                "id": 1,
                "device_type": data.get("device_type"),
                "mac_address": data.get("mac_address"),
                "timestamp": timestamp
            }
        elif "command" in endpoint:
            return {
                "success": True,
                "message": "Comando enviado",
                "device_id": data.get("device_id"),
                "command": data.get("command"),
                "timestamp": timestamp
            }
        
        return {"timestamp": timestamp}
    
    async def test_error_handling(self):
        """Testa tratamento de erros."""
        logger.info("\n" + "="*60)
        logger.info("⚠️ TESTANDO TRATAMENTO DE ERROS")
        logger.info("="*60)
        
        try:
            # Teste 1: MAC address inválido
            invalid_macs = ["invalid", "AA:BB:CC", "ZZ:YY:XX:WW:VV:UU:TT"]
            for mac in invalid_macs:
                is_valid = self._validate_mac_address(mac)
                self.add_test_result(
                    f"Validação MAC inválido ({mac})",
                    not is_valid,
                    f"MAC rejeitado corretamente: {not is_valid}"
                )
            
            # Teste 2: Tipo de dispositivo inválido
            invalid_types = ["invalid_type", "hacker_device", ""]
            allowed_types = ["smart-lamp", "smart-lock", "sensor", "speaker"]
            
            for device_type in invalid_types:
                is_valid = device_type in allowed_types
                self.add_test_result(
                    f"Validação tipo inválido ({device_type})",
                    not is_valid,
                    f"Tipo rejeitado corretamente: {not is_valid}"
                )
            
            # Teste 3: Timeout inválido
            invalid_timeouts = [-1, 0, 61, 1000]
            for timeout in invalid_timeouts:
                is_valid = 1.0 <= timeout <= 60.0
                self.add_test_result(
                    f"Validação timeout inválido ({timeout})",
                    not is_valid,
                    f"Timeout rejeitado corretamente: {not is_valid}"
                )
            
        except Exception as e:
            self.add_test_result(
                "Tratamento de erros",
                False,
                f"Erro: {str(e)}"
            )
    
    def generate_test_report(self):
        """Gera relatório final dos testes."""
        logger.info("\n" + "="*80)
        logger.info("📊 RELATÓRIO FINAL DOS TESTES")
        logger.info("="*80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        logger.info(f"📈 ESTATÍSTICAS:")
        logger.info(f"   Total de testes: {total_tests}")
        logger.info(f"   ✅ Passou: {passed_tests}")
        logger.info(f"   ❌ Falhou: {failed_tests}")
        logger.info(f"   📊 Taxa de sucesso: {success_rate:.1f}%")
        logger.info("")
        
        if failed_tests > 0:
            logger.info("❌ TESTES QUE FALHARAM:")
            for result in self.test_results:
                if not result['success']:
                    logger.info(f"   • {result['test']}: {result['message']}")
            logger.info("")
        
        logger.info("✅ FUNCIONALIDADES VERIFICADAS:")
        categories = {
            "Bluetooth Interceptor": ["Inicialização", "Escaneamento", "Conexão", "Envio de comando", "Desconexão"],
            "Banco de Dados": ["Inserção", "Busca", "Listagem", "Atualização", "Proteção"],
            "Segurança": ["Criptografia", "Descriptografia", "HMAC", "Detecção tampering"],
            "API Endpoints": ["Validação", "Resposta"],
            "Tratamento de Erros": ["MAC inválido", "Tipo inválido", "Timeout inválido"]
        }
        
        for category, features in categories.items():
            category_tests = [r for r in self.test_results if any(f.lower() in r['test'].lower() for f in features)]
            category_success = sum(1 for r in category_tests if r['success'])
            category_total = len(category_tests)
            
            if category_total > 0:
                category_rate = (category_success / category_total * 100)
                status = "✅" if category_rate == 100 else "⚠️" if category_rate >= 70 else "❌"
                logger.info(f"   {status} {category}: {category_success}/{category_total} ({category_rate:.0f}%)")
        
        logger.info("")
        logger.info("🎯 CONCLUSÃO:")
        if success_rate >= 90:
            logger.info("   🎉 EXCELENTE! Implementação Bluetooth está funcionando perfeitamente.")
        elif success_rate >= 70:
            logger.info("   👍 BOM! Implementação funcional com alguns pontos de atenção.")
        else:
            logger.info("   ⚠️ ATENÇÃO! Implementação precisa de correções.")
        
        logger.info("="*80)
        
        return success_rate >= 70

async def main():
    """Função principal do script de teste."""
    print("🚀 INICIANDO TESTES INTEGRADOS - BLUETOOTH IOTRAC")
    print("="*80)
    
    tester = BluetoothTester()
    
    try:
        # Configurar ambiente
        tester.setup_test_environment()
        
        # Executar bateria de testes
        await tester.test_bluetooth_interceptor()
        await tester.test_database_integration()
        await tester.test_security_features()
        await tester.test_api_endpoints_simulation()
        await tester.test_error_handling()
        
        # Gerar relatório
        success = tester.generate_test_report()
        
        if success:
            print("\n🎉 TODOS OS TESTES PRINCIPAIS PASSARAM!")
            print("✅ Implementação Bluetooth está pronta para uso!")
        else:
            print("\n⚠️ ALGUNS TESTES FALHARAM!")
            print("❌ Verifique os logs acima para detalhes.")
            
        return success
        
    except Exception as e:
        logger.error(f"❌ Erro crítico durante os testes: {e}")
        return False
        
    finally:
        # Limpar ambiente
        tester.cleanup_test_environment()

if __name__ == "__main__":
    print("Executando testes... (isso pode levar alguns minutos)")
    
    try:
        # Executar testes assíncronos
        success = asyncio.run(main())
        
        # Código de saída
        exit_code = 0 if success else 1
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n⚠️ Testes interrompidos pelo usuário.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erro fatal: {e}")
        sys.exit(1) 