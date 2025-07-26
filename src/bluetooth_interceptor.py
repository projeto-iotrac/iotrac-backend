# bluetooth_interceptor.py
# Módulo para interceptação e comunicação segura via Bluetooth
# Implementa proteção de camada para dispositivos IoT via Bluetooth
# Dependências: bleak, asyncio, logging

import asyncio
import logging
import json
import time
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.characteristic import BleakGATTCharacteristic
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False
    BleakClient = None
    BleakScanner = None
    BLEDevice = None
    BleakGATTCharacteristic = None

# Configuração de logging
logger = logging.getLogger(__name__)

# Configurações padrão
DEFAULT_SCAN_TIMEOUT = 10.0
DEFAULT_CONNECTION_TIMEOUT = 10.0
DEFAULT_COMMAND_TIMEOUT = 5.0

# UUIDs padrão para serviços IoT comuns
IOTRAC_SERVICE_UUID = "12345678-1234-1234-1234-123456789abc"
IOTRAC_COMMAND_CHAR_UUID = "12345678-1234-1234-1234-123456789abd"
IOTRAC_RESPONSE_CHAR_UUID = "12345678-1234-1234-1234-123456789abe"

class BluetoothInterceptor:
    """
    Classe principal para interceptação e proteção de comunicações Bluetooth.
    Implementa camada de segurança para dispositivos IoT conectados via Bluetooth.
    """
    
    def __init__(self):
        """Inicializa o interceptor Bluetooth."""
        if not BLUETOOTH_AVAILABLE:
            logger.error("Biblioteca bleak não disponível. Instale com: pip install bleak")
            raise RuntimeError("Bluetooth não disponível - biblioteca bleak não encontrada")
        
        self.connected_devices: Dict[str, BleakClient] = {}
        self.device_characteristics: Dict[str, Dict[str, str]] = {}
        logger.info("BluetoothInterceptor inicializado com sucesso")
    
    async def scan_devices(self, timeout: float = DEFAULT_SCAN_TIMEOUT) -> List[Dict[str, Any]]:
        """
        Escaneia dispositivos Bluetooth disponíveis.
        
        Args:
            timeout (float): Tempo limite para escaneamento em segundos
            
        Returns:
            List[Dict[str, Any]]: Lista de dispositivos encontrados
        """
        try:
            logger.info(f"Iniciando escaneamento Bluetooth (timeout: {timeout}s)")
            devices = await BleakScanner.discover(timeout=timeout)
            
            discovered_devices = []
            for device in devices:
                device_info = {
                    "mac_address": device.address,
                    "name": device.name or "Dispositivo Desconhecido",
                    "rssi": device.rssi if hasattr(device, 'rssi') else None,
                    "discoverable": True,
                    "scanned_at": datetime.now().isoformat()
                }
                discovered_devices.append(device_info)
                logger.debug(f"Dispositivo encontrado: {device_info}")
            
            logger.info(f"Escaneamento concluído. {len(discovered_devices)} dispositivos encontrados")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"Erro durante escaneamento Bluetooth: {e}")
            raise RuntimeError(f"Falha no escaneamento Bluetooth: {e}")
    
    async def connect_device(self, mac_address: str, timeout: float = DEFAULT_CONNECTION_TIMEOUT) -> bool:
        """
        Conecta a um dispositivo Bluetooth específico.
        
        Args:
            mac_address (str): Endereço MAC do dispositivo
            timeout (float): Tempo limite para conexão
            
        Returns:
            bool: True se conexão bem-sucedida, False caso contrário
        """
        try:
            if mac_address in self.connected_devices:
                logger.warning(f"Dispositivo {mac_address} já está conectado")
                return True
            
            logger.info(f"Conectando ao dispositivo {mac_address}")
            client = BleakClient(mac_address, timeout=timeout)
            
            await client.connect()
            
            if client.is_connected:
                self.connected_devices[mac_address] = client
                
                # Descobrir características disponíveis
                await self._discover_characteristics(mac_address, client)
                
                logger.info(f"Conexão estabelecida com {mac_address}")
                return True
            else:
                logger.error(f"Falha na conexão com {mac_address}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao conectar com {mac_address}: {e}")
            return False
    
    async def disconnect_device(self, mac_address: str) -> bool:
        """
        Desconecta de um dispositivo Bluetooth.
        
        Args:
            mac_address (str): Endereço MAC do dispositivo
            
        Returns:
            bool: True se desconexão bem-sucedida
        """
        try:
            if mac_address not in self.connected_devices:
                logger.warning(f"Dispositivo {mac_address} não está conectado")
                return True
            
            client = self.connected_devices[mac_address]
            await client.disconnect()
            
            del self.connected_devices[mac_address]
            if mac_address in self.device_characteristics:
                del self.device_characteristics[mac_address]
            
            logger.info(f"Dispositivo {mac_address} desconectado")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao desconectar {mac_address}: {e}")
            return False
    
    async def send_command(self, mac_address: str, command: str, encrypted_data: Optional[Dict] = None) -> str:
        """
        Envia comando para dispositivo Bluetooth com proteção opcional.
        
        Args:
            mac_address (str): Endereço MAC do dispositivo
            command (str): Comando a ser enviado
            encrypted_data (Optional[Dict]): Dados criptografados se proteção ativa
            
        Returns:
            str: Status do envio ("success", "error", "not_connected")
        """
        try:
            if mac_address not in self.connected_devices:
                logger.error(f"Dispositivo {mac_address} não está conectado")
                return "not_connected"
            
            client = self.connected_devices[mac_address]
            
            if not client.is_connected:
                logger.error(f"Conexão com {mac_address} foi perdida")
                del self.connected_devices[mac_address]
                return "not_connected"
            
            # Preparar mensagem
            if encrypted_data:
                message = json.dumps(encrypted_data)
                logger.info(f"Enviando comando criptografado para {mac_address}")
            else:
                message = command
                logger.info(f"Enviando comando não criptografado para {mac_address}: {command}")
            
            # Encontrar característica para envio de comandos
            command_char_uuid = self._get_command_characteristic(mac_address)
            if not command_char_uuid:
                logger.error(f"Característica de comando não encontrada para {mac_address}")
                return "error"
            
            # Enviar comando
            await client.write_gatt_char(command_char_uuid, message.encode())
            
            logger.info(f"Comando enviado com sucesso para {mac_address}")
            return "success"
            
        except Exception as e:
            logger.error(f"Erro ao enviar comando para {mac_address}: {e}")
            return "error"
    
    async def _discover_characteristics(self, mac_address: str, client: BleakClient) -> None:
        """
        Descobre características GATT disponíveis no dispositivo.
        
        Args:
            mac_address (str): Endereço MAC do dispositivo
            client (BleakClient): Cliente Bluetooth conectado
        """
        try:
            services = await client.get_services()
            characteristics = {}
            
            for service in services:
                logger.debug(f"Serviço encontrado: {service.uuid}")
                
                for char in service.characteristics:
                    logger.debug(f"Característica encontrada: {char.uuid} - {char.properties}")
                    
                    # Mapear características conhecidas
                    if "write" in char.properties:
                        characteristics["command"] = char.uuid
                    if "read" in char.properties or "notify" in char.properties:
                        characteristics["response"] = char.uuid
            
            self.device_characteristics[mac_address] = characteristics
            logger.info(f"Características descobertas para {mac_address}: {characteristics}")
            
        except Exception as e:
            logger.error(f"Erro ao descobrir características para {mac_address}: {e}")
    
    def _get_command_characteristic(self, mac_address: str) -> Optional[str]:
        """
        Obtém UUID da característica de comando para um dispositivo.
        
        Args:
            mac_address (str): Endereço MAC do dispositivo
            
        Returns:
            Optional[str]: UUID da característica ou None
        """
        if mac_address not in self.device_characteristics:
            return None
        
        characteristics = self.device_characteristics[mac_address]
        return characteristics.get("command", IOTRAC_COMMAND_CHAR_UUID)
    
    def get_connected_devices(self) -> List[str]:
        """
        Retorna lista de dispositivos atualmente conectados.
        
        Returns:
            List[str]: Lista de endereços MAC conectados
        """
        return list(self.connected_devices.keys())
    
    def is_device_connected(self, mac_address: str) -> bool:
        """
        Verifica se um dispositivo está conectado.
        
        Args:
            mac_address (str): Endereço MAC do dispositivo
            
        Returns:
            bool: True se conectado, False caso contrário
        """
        if mac_address not in self.connected_devices:
            return False
        
        client = self.connected_devices[mac_address]
        return client.is_connected
    
    async def cleanup(self) -> None:
        """
        Limpa recursos e desconecta todos os dispositivos.
        """
        logger.info("Limpando recursos Bluetooth...")
        
        for mac_address in list(self.connected_devices.keys()):
            await self.disconnect_device(mac_address)
        
        logger.info("Limpeza concluída")

# Instância global do interceptor
bluetooth_interceptor = BluetoothInterceptor() if BLUETOOTH_AVAILABLE else None

# Funções de conveniência para compatibilidade com device_interceptor.py
async def scan_bluetooth_devices(timeout: float = DEFAULT_SCAN_TIMEOUT) -> List[Dict[str, Any]]:
    """
    Função de conveniência para escaneamento de dispositivos Bluetooth.
    
    Args:
        timeout (float): Tempo limite para escaneamento
        
    Returns:
        List[Dict[str, Any]]: Lista de dispositivos encontrados
    """
    if not bluetooth_interceptor:
        raise RuntimeError("Bluetooth não disponível")
    
    return await bluetooth_interceptor.scan_devices(timeout)

async def send_bluetooth_command(mac_address: str, command: str, encrypted_data: Optional[Dict] = None) -> str:
    """
    Função de conveniência para envio de comandos Bluetooth.
    
    Args:
        mac_address (str): Endereço MAC do dispositivo
        command (str): Comando a ser enviado
        encrypted_data (Optional[Dict]): Dados criptografados se proteção ativa
        
    Returns:
        str: Status do envio
    """
    if not bluetooth_interceptor:
        raise RuntimeError("Bluetooth não disponível")
    
    return await bluetooth_interceptor.send_command(mac_address, command, encrypted_data)

async def connect_bluetooth_device(mac_address: str) -> bool:
    """
    Função de conveniência para conexão Bluetooth.
    
    Args:
        mac_address (str): Endereço MAC do dispositivo
        
    Returns:
        bool: True se conexão bem-sucedida
    """
    if not bluetooth_interceptor:
        raise RuntimeError("Bluetooth não disponível")
    
    return await bluetooth_interceptor.connect_device(mac_address)

async def disconnect_bluetooth_device(mac_address: str) -> bool:
    """
    Função de conveniência para desconexão Bluetooth.
    
    Args:
        mac_address (str): Endereço MAC do dispositivo
        
    Returns:
        bool: True se desconexão bem-sucedida
    """
    if not bluetooth_interceptor:
        raise RuntimeError("Bluetooth não disponível")
    
    return await bluetooth_interceptor.disconnect_device(mac_address) 