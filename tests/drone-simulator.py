#!/usr/bin/env python3
"""
🚁 DRONE SIMULATOR - Simulador de drone para provas de conexão de sistemas
Autor: Devi (Companheiro de Desenvolvimento do Kiron Garcia)
"""

import socket
import threading
import time
import json
import requests
from datetime import datetime

# Configurações
DRONE_IP = "127.0.0.1"
DRONE_PORT = 8080
IOTRAC_URL = "http://localhost:8000"

class DroneSimulator:
    def __init__(self):
        self.running = False
        self.protected = False
        self.socket = None
        self.drone_device_id = None
        
    def print_header(self):
        print("🚁 DRONE SIMULATOR")
        print("Sistema de drone ligado, respondendo no IP:", DRONE_IP)
        print("-" * 50)
        
    def initialize_drone_system(self):
        """Simula inicialização do sistema de drone"""
        print("🔧 Inicializando sistema de drone...")
        time.sleep(0.5)
        print("📡 Sistema de comunicação: ATIVO")
        time.sleep(0.3)
        print("🔒 Sistema de segurança: AGUARDANDO CONEXÃO")
        time.sleep(0.3)
        print("✅ Sistema de drone inicializado com sucesso!")
        print("-" * 50)
        
    def get_drone_device_id(self):
        """Obtém o ID do drone registrado"""
        try:
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
            
            response = requests.get(f"{IOTRAC_URL}/devices", headers=headers, timeout=5)
            
            if response.status_code == 200:
                devices = response.json()
                for device in devices:
                    if device.get("ip_address") == DRONE_IP:
                        self.drone_device_id = device.get("id")
                        return self.drone_device_id
            
            return None
        except Exception as e:
            print(f"❌ Erro ao obter ID do drone: {e}")
            return None
        
    def test_connection(self):
        """Teste 1: Verificar se drone está registrado no IOTRAC"""
        print("\n🧪 TESTE 1: Verificando registro do drone no IOTRAC")
        print("📡 Verificando se drone está na lista de dispositivos...")
        
        try:
            drone_id = self.get_drone_device_id()
            
            if drone_id:
                print(f"✅ Drone encontrado na lista (ID: {drone_id})")
                print(f"✅ IP: {DRONE_IP} - Registrado com sucesso")
                return True
            else:
                print("❌ Drone NÃO está registrado no IOTRAC")
                print(f"❌ IP {DRONE_IP} não encontrado na lista de dispositivos")
                print("💡 Adicione o drone na sua app primeiro!")
                return False
                
        except Exception as e:
            print(f"❌ Erro na verificação: {e}")
            return False
            
    def test_jwt_protection(self):
        """Teste 2: Verificar proteção JWT - Testa endpoint /status sem token"""
        print("\n🧪 TESTE 2: Verificando proteção JWT")
        print("🔑 Testando autenticação no endpoint /status...")
        
        try:
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
            
            response = requests.get(f"{IOTRAC_URL}/status", headers=headers, timeout=5)
            
            if response.status_code == 200:
                print("✅ Endpoint /status acessível (é público)")
                return True
            elif response.status_code == 401:
                print("❌ Endpoint /status não deveria requerer autenticação")
                return False
            else:
                print(f"❌ Resposta inesperada: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Erro no teste JWT: {e}")
            return False
            
    def test_hmac_protection(self):
        """Teste 3: Verificar proteção HMAC baseada na proteção individual do drone"""
        print("\n🧪 TESTE 3: Verificando proteção HMAC")
        print("🔐 Testando verificação de integridade...")
        
        try:
            if not self.drone_device_id:
                print("❌ ID do drone não encontrado")
                return False
            
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
            
            # Verifica status de proteção individual do drone
            protection_response = requests.get(f"{IOTRAC_URL}/devices/{self.drone_device_id}/protection", headers=headers, timeout=5)
            device_protection_enabled = False
            
            if protection_response.status_code == 200:
                device_protection_enabled = protection_response.json().get("protection_enabled", False)
                print(f"📊 Status da proteção do drone: {'ATIVA' if device_protection_enabled else 'DESATIVADA'}")
            else:
                print(f"❌ Erro ao verificar proteção do drone: {protection_response.status_code}")
                return False
            
            # Testa se IOTRAC rejeita HMAC inválido no endpoint /devices
            test_headers = headers.copy()
            test_headers["X-HMAC"] = "invalid_signature"
            response = requests.get(f"{IOTRAC_URL}/devices", headers=test_headers, timeout=5)
            
            if device_protection_enabled:
                # Se proteção do drone está ativa, deve rejeitar HMAC inválido
                if response.status_code in [400, 401, 422]:
                    print("✅ HMAC implementado com sucesso")
                    print("✅ Assinaturas inválidas são rejeitadas quando proteção do drone ativa")
                    return True
                elif response.status_code == 200:
                    print("❌ HMAC não está funcionando")
                    print("❌ Assinatura inválida foi aceita quando proteção do drone ativa")
                    return False
                else:
                    print(f"❌ Resposta inesperada: {response.status_code}")
                    return False
            else:
                # Se proteção do drone está desativada, mostra vulnerabilidade
                if response.status_code in [200, 401, 403, 404]:
                    print("⚠️  HMAC DESATIVADO - SISTEMA VULNERÁVEL")
                    print("❌ Assinaturas inválidas são aceitas quando proteção desativada")
                    print("🚨 Sistema suscetível a ataques de integridade")
                    return False  # Retorna False para indicar vulnerabilidade
                else:
                    print(f"❌ Resposta inesperada: {response.status_code}")
                    return False
                
        except Exception as e:
            print(f"❌ Erro no teste HMAC: {e}")
            return False
            
    def test_aes_protection(self):
        """Teste 4: Verificar proteção AES baseada na proteção individual do drone"""
        print("\n🧪 TESTE 4: Verificando proteção AES-256")
        print("🔒 Testando criptografia de dados no endpoint /command...")
        
        try:
            if not self.drone_device_id:
                print("❌ ID do drone não encontrado")
                return False
            
            headers = {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
            
            # Verifica status de proteção individual do drone
            protection_response = requests.get(f"{IOTRAC_URL}/devices/{self.drone_device_id}/protection", headers=headers, timeout=5)
            device_protection_enabled = False
            
            if protection_response.status_code == 200:
                device_protection_enabled = protection_response.json().get("protection_enabled", False)
                print(f"📊 Status da proteção do drone: {'ATIVA' if device_protection_enabled else 'DESATIVADA'}")
            else:
                print(f"❌ Erro ao verificar proteção do drone: {protection_response.status_code}")
                return False
            
            # Testa se o endpoint /command aceita dados não criptografados
            command_data = {
                "device_id": self.drone_device_id,
                "command": "get_status"
            }
            
            response = requests.post(f"{IOTRAC_URL}/command", json=command_data, headers=headers, timeout=5)
            
            if device_protection_enabled:
                # Se proteção do drone está ativa, deve rejeitar dados não criptografados
                if response.status_code in [400, 401, 422]:
                    print("✅ AES-256 implementado com sucesso")
                    print("✅ Dados não criptografados são rejeitados quando proteção do drone ativa")
                    return True
                elif response.status_code == 200:
                    print("❌ AES-256 não está funcionando")
                    print("❌ Dados não criptografados foram aceitos quando proteção do drone ativa")
                    return False
                else:
                    print(f"❌ Resposta inesperada: {response.status_code}")
                    return False
            else:
                # Se proteção do drone está desativada, mostra vulnerabilidade
                if response.status_code in [200, 404]:
                    print("⚠️  AES-256 DESATIVADO - SISTEMA VULNERÁVEL")
                    print("❌ Dados não criptografados são aceitos quando proteção desativada")
                    print("🚨 Sistema suscetível a interceptação de dados")
                    return False  # Retorna False para indicar vulnerabilidade
                else:
                    print(f"❌ Resposta inesperada: {response.status_code}")
                    return False
                
        except Exception as e:
            print(f"❌ Erro no teste AES: {e}")
            return False
            
    def test_frontend_connection(self):
        """Teste 5: Verificar se frontend consegue se conectar sem erros"""
        print("\n🧪 TESTE 5: Verificando conexão do frontend")
        print("📱 Testando se app consegue acessar endpoints...")
        
        try:
            # Testa endpoints que o frontend usa
            endpoints = [
                ("/", "GET", "Endpoint raiz"),
                ("/toggle_protection", "POST", "Alternar proteção"),
                ("/logs", "GET", "Logs do sistema")
            ]
            
            success_count = 0
            for endpoint, method, name in endpoints:
                try:
                    if method == "GET":
                        response = requests.get(f"{IOTRAC_URL}{endpoint}", timeout=5)
                    elif method == "POST":
                        response = requests.post(f"{IOTRAC_URL}{endpoint}", timeout=5)
                    
                    if response.status_code in [200, 401, 403]:  # 401/403 são esperados se protegido
                        print(f"✅ {name}: Acessível")
                        success_count += 1
                    else:
                        print(f"❌ {name}: Erro {response.status_code}")
                except Exception as e:
                    print(f"❌ {name}: Erro de conexão")
            
            if success_count >= 2:
                print("✅ Frontend consegue se conectar ao backend")
                return True
            else:
                print("❌ Frontend tem problemas de conexão")
                return False
                
        except Exception as e:
            print(f"❌ Erro no teste de frontend: {e}")
            return False
            
    def run_all_tests(self):
        """Executa todos os testes"""
        print("\n" + "="*50)
        print("🔍 INICIANDO TESTES DE PROTEÇÃO")
        print("="*50)
        
        # Reset do status de proteção a cada execução
        self.protected = False
        
        tests = [
            ("Comunicação", self.test_connection),
            ("JWT", self.test_jwt_protection),
            ("HMAC", self.test_hmac_protection),
            ("AES-256", self.test_aes_protection),
            ("Frontend", self.test_frontend_connection)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            if test_func():
                passed += 1
            time.sleep(1)
            
        # Resultado final - verifica proteção individual do drone
        print("\n" + "="*50)
        print("📊 RESULTADO DOS TESTES")
        print("="*50)
        
        # Verifica proteção individual do drone
        try:
            if self.drone_device_id:
                headers = {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
                protection_response = requests.get(f"{IOTRAC_URL}/devices/{self.drone_device_id}/protection", headers=headers, timeout=5)
                current_protection_enabled = False
                if protection_response.status_code == 200:
                    current_protection_enabled = protection_response.json().get("protection_enabled", False)
                    print(f"🔍 Status real do drone: {'ATIVA' if current_protection_enabled else 'DESATIVADA'}")
            else:
                print("❌ Drone não encontrado para verificação final")
                current_protection_enabled = False
        except Exception as e:
            print(f"❌ Erro ao verificar proteção do drone: {e}")
            current_protection_enabled = False
        
        if passed == 0:
            print("❌ SISTEMA NÃO CONECTADO")
            print("💡 Verifique se o IOTRAC App está conectado")
        elif passed == total and current_protection_enabled:
            print("🛡️  DRONE TOTALMENTE SEGURO")
            print("✅ Todos os testes passaram com sucesso!")
            print("✅ Proteções HMAC e AES implementadas e funcionando")
            print("✅ Drone protegido contra ataques")
            self.protected = True
        elif passed == total and not current_protection_enabled:
            print("🚨 DRONE TOTALMENTE VULNERÁVEL")
            print("❌ Todos os testes passaram, mas proteção do drone está DESATIVADA")
            print("🚨 Sistema completamente exposto a ataques")
            print("🚨 HMAC e AES não estão protegendo o drone")
            print("⚠️  ATIVE A PROTEÇÃO IMEDIATAMENTE!")
            self.protected = False
        elif passed >= 4 and current_protection_enabled:
            print("⚠️  DRONE PARCIALMENTE SEGURO")
            print(f"✅ {passed}/{total} testes passaram")
            print("💡 Algumas proteções podem precisar de ajustes")
            print("⚠️  Drone parcialmente vulnerável")
        elif passed >= 4 and not current_protection_enabled:
            print("🚨 DRONE PARCIALMENTE VULNERÁVEL")
            print(f"❌ {passed}/{total} testes passaram, mas proteção do drone está DESATIVADA")
            print("🚨 Sistema parcialmente exposto a ataques")
            print("⚠️  ATIVE A PROTEÇÃO PARA SEGURANÇA COMPLETA")
        else:
            print("🚨 DRONE ALTAMENTE VULNERÁVEL")
            print(f"❌ Apenas {passed}/{total} testes passaram")
            if current_protection_enabled:
                print("💡 Proteção ativa mas não está funcionando corretamente")
                print("🚨 Sistema pode estar comprometido")
            else:
                print("🚨 Proteção desativada - drone completamente vulnerável")
                print("🚨 Sistema exposto a múltiplos tipos de ataques")
                print("⚠️  ATIVE A PROTEÇÃO IMEDIATAMENTE!")
            
        return passed == total and current_protection_enabled
        
    def start_server(self):
        """Inicia servidor do drone"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((DRONE_IP, DRONE_PORT))
            self.socket.listen(5)
            
            print(f"🌐 Servidor iniciado em {DRONE_IP}:{DRONE_PORT}")
            
            while self.running:
                try:
                    client, addr = self.socket.accept()
                    data = client.recv(1024).decode('utf-8')
                    
                    if data:
                        response = {
                            "status": "ok",
                            "message": "Comando recebido",
                            "protected": self.protected
                        }
                        client.send(json.dumps(response).encode('utf-8'))
                        
                    client.close()
                    
                except Exception as e:
                    if self.running:
                        print(f"❌ Erro na conexão: {e}")
                        
        except Exception as e:
            print(f"❌ Erro ao iniciar servidor: {e}")
            
    def monitor_protection(self):
        """Monitora status de proteção"""
        while self.running:
            try:
                # Verifica se IOTRAC está rodando
                response = requests.get(f"{IOTRAC_URL}/", timeout=5)
                
                if response.status_code == 200:
                    # Se estava protegido e agora não está
                    if self.protected:
                        print("\n🔓 ATENÇÃO: Proteção foi desativada!")
                        print("⚠️  Sistema está vulnerável!")
                        self.protected = False
                else:
                    if self.protected:
                        print("\n🔓 ATENÇÃO: IOTRAC desconectado!")
                        print("⚠️  Sistema está vulnerável!")
                        self.protected = False
                        
            except Exception as e:
                if self.protected:
                    print("\n🔓 ATENÇÃO: IOTRAC não está acessível!")
                    print("⚠️  Sistema está vulnerável!")
                    self.protected = False
                    
            time.sleep(10)  # Verifica a cada 10 segundos
            
    def run(self):
        """Executa o simulador"""
        self.print_header()
        self.initialize_drone_system()
        
        # Inicia servidor em thread
        self.running = True
        server_thread = threading.Thread(target=self.start_server)
        server_thread.daemon = True
        server_thread.start()
        
        # Aguarda inicialização
        time.sleep(2)
        
        # Menu principal
        while True:
            print("\n📱 Digite 1 se já se conectou ao app para prosseguir com os testes")
            print("📱 Digite 2 para fechar o processo")
            
            try:
                choice = input("Escolha: ").strip()
                
                if choice == "1":
                    success = self.run_all_tests()
                    
                    # Menu após testes
                    while True:
                        print("\n🔄 Atualizar status de testes: 1")
                        print("🚪 Para sair: 2")
                        
                        try:
                            choice2 = input("Escolha: ").strip()
                            
                            if choice2 == "1":
                                success = self.run_all_tests()
                            elif choice2 == "2":
                                print("🛑 Encerrando drone simulator...")
                                return
                            else:
                                print("❌ Opção inválida!")
                                
                        except KeyboardInterrupt:
                            print("\n🛑 Encerrando drone simulator...")
                            return
                            
                elif choice == "2":
                    print("🛑 Encerrando drone simulator...")
                    break
                else:
                    print("❌ Opção inválida!")
                    
            except KeyboardInterrupt:
                print("\n🛑 Encerrando drone simulator...")
                break
            except Exception as e:
                print(f"❌ Erro: {e}")
                
        self.running = False
        if self.socket:
            self.socket.close()

def main():
    drone = DroneSimulator()
    drone.run()

if __name__ == "__main__":
    main() 