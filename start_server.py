#!/usr/bin/env python3
"""
Script robusto para iniciar o servidor IOTRAC Backend
Com tratamento de erros, reinicialização automática e logs detalhados
"""

import os
import sys
import time
import signal
import subprocess
import logging
from pathlib import Path

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ServerManager:
    def __init__(self):
        self.process = None
        self.restart_count = 0
        self.max_restarts = 5
        self.restart_delay = 3
        
    def start_server(self):
        """Inicia o servidor uvicorn"""
        try:
            logger.info("🚀 Iniciando servidor IOTRAC Backend...")
            
            # Verificar se estamos no diretório correto
            if not Path("src/main.py").exists():
                logger.error("❌ Arquivo src/main.py não encontrado!")
                logger.error("   Certifique-se de estar no diretório iotrac-backend")
                return False
            
            # Verificar se o ambiente virtual existe
            if not Path("venv/bin/activate").exists():
                logger.error("❌ Ambiente virtual não encontrado!")
                logger.error("   Execute: python -m venv venv")
                return False
            
            # Comando para iniciar o servidor
            cmd = [
                "venv/bin/python", "-m", "uvicorn",
                "src.main:app",
                "--host", "0.0.0.0",
                "--port", "8000",
                "--log-level", "info",
                "--reload"
            ]
            
            logger.info(f"📡 Comando: {' '.join(cmd)}")
            
            # Iniciar processo
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            logger.info(f"✅ Servidor iniciado com PID: {self.process.pid}")
            
            # Monitorar saída
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    print(line.strip())
                    if "Uvicorn running on" in line:
                        logger.info("🎉 Servidor pronto e acessível!")
                        break
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao iniciar servidor: {e}")
            return False
    
    def stop_server(self):
        """Para o servidor"""
        if self.process:
            logger.info(f"🛑 Parando servidor (PID: {self.process.pid})...")
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
                logger.info("✅ Servidor parado com sucesso")
            except subprocess.TimeoutExpired:
                logger.warning("⚠️ Forçando parada do servidor...")
                self.process.kill()
            self.process = None
    
    def restart_server(self):
        """Reinicia o servidor"""
        self.restart_count += 1
        if self.restart_count > self.max_restarts:
            logger.error(f"❌ Máximo de reinicializações ({self.max_restarts}) atingido!")
            return False
        
        logger.info(f"🔄 Reiniciando servidor (tentativa {self.restart_count}/{self.max_restarts})...")
        self.stop_server()
        time.sleep(self.restart_delay)
        return self.start_server()
    
    def monitor_server(self):
        """Monitora o servidor e reinicia se necessário"""
        logger.info("👀 Iniciando monitoramento do servidor...")
        
        while True:
            try:
                # Verificar se o processo ainda está rodando
                if self.process and self.process.poll() is not None:
                    logger.warning("⚠️ Servidor parou inesperadamente!")
                    if not self.restart_server():
                        break
                
                # Verificar conectividade
                if self.process:
                    try:
                        import requests
                        response = requests.get("http://localhost:8000/", timeout=5)
                        if response.status_code == 200:
                            logger.debug("✅ Servidor respondendo normalmente")
                        else:
                            logger.warning(f"⚠️ Servidor retornou status {response.status_code}")
                    except Exception as e:
                        logger.warning(f"⚠️ Erro ao verificar servidor: {e}")
                        if not self.restart_server():
                            break
                
                time.sleep(30)  # Verificar a cada 30 segundos
                
            except KeyboardInterrupt:
                logger.info("🛑 Interrupção do usuário detectada")
                break
            except Exception as e:
                logger.error(f"❌ Erro no monitoramento: {e}")
                break
        
        self.stop_server()

def signal_handler(signum, frame):
    """Handler para sinais do sistema"""
    logger.info(f"📡 Sinal {signum} recebido, parando servidor...")
    if server_manager:
        server_manager.stop_server()
    sys.exit(0)

if __name__ == "__main__":
    # Registrar handlers de sinal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    server_manager = ServerManager()
    
    # Verificar se já há um servidor rodando
    try:
        import requests
        response = requests.get("http://localhost:8000/", timeout=2)
        if response.status_code == 200:
            logger.info("✅ Servidor já está rodando!")
            logger.info("   Para parar: pkill -f uvicorn")
            sys.exit(0)
    except:
        pass
    
    # Iniciar servidor
    if server_manager.start_server():
        logger.info("🎯 Servidor iniciado com sucesso!")
        logger.info("   URL: http://192.168.112.180:8000")
        logger.info("   Para parar: Ctrl+C")
        
        # Iniciar monitoramento
        server_manager.monitor_server()
    else:
        logger.error("❌ Falha ao iniciar servidor!")
        sys.exit(1) 