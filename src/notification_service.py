# notification_service.py
# Serviço de notificações para envio de códigos 2FA via email
# Dependências: smtplib, email

import smtplib
import ssl
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any
from datetime import datetime
from src.config import setup_logging
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Configuração de logging
setup_logging()
logger = logging.getLogger(__name__)

class NotificationService:
    """
    Serviço para envio de notificações via email.
    Usado para códigos 2FA, notificações de segurança e alertas de anomalias.
    """
    
    def __init__(self):
        # Configurações de email
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.email_user = os.getenv("EMAIL_USER")
        self.email_password = os.getenv("EMAIL_PASSWORD")
        self.email_from = os.getenv("EMAIL_FROM", self.email_user)
        
        self.email_enabled = bool(self.email_user and self.email_password)
        
        logger.info(f"NotificationService inicializado - Email: {'✓' if self.email_enabled else '✗'}")
    
    def send_2fa_email(self, email: str, code: str, user_name: str = "Usuário") -> bool:
        """
        Envia código 2FA por email.
        
        Args:
            email (str): Email do destinatário
            code (str): Código 2FA de 6 dígitos
            user_name (str): Nome do usuário
            
        Returns:
            bool: True se enviado com sucesso
        """
        if not self.email_enabled:
            logger.error("Serviço de email não configurado")
            return False
        
        try:
            # Criar mensagem
            message = MIMEMultipart("alternative")
            message["Subject"] = "Código de Verificação IOTRAC"
            message["From"] = self.email_from
            message["To"] = email
            
            # Conteúdo do email
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Código de Verificação IOTRAC</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                    .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #2563eb; }}
                    .code {{ font-size: 36px; font-weight: bold; color: #1f2937; text-align: center; background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; letter-spacing: 8px; }}
                    .warning {{ background-color: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">🔒 IOTRAC</div>
                        <h1>Código de Verificação</h1>
                    </div>
                    
                    <p>Olá, {user_name}!</p>
                    
                    <p>Você solicitou acesso ao sistema IOTRAC. Use o código abaixo para completar sua autenticação:</p>
                    
                    <div class="code">{code}</div>
                    
                    <div class="warning">
                        <strong>⚠️ Importante:</strong>
                        <ul>
                            <li>Este código expira em <strong>10 minutos</strong></li>
                            <li>Não compartilhe este código com ninguém</li>
                            <li>Se você não solicitou este código, ignore este email</li>
                        </ul>
                    </div>
                    
                    <p>Se você não solicitou este código, pode ignorar este email com segurança.</p>
                    
                    <div class="footer">
                        <p>Este é um email automático do sistema IOTRAC</p>
                        <p>Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            IOTRAC - Código de Verificação
            
            Olá, {user_name}!
            
            Você solicitou acesso ao sistema IOTRAC.
            Use o código abaixo para completar sua autenticação:
            
            CÓDIGO: {code}
            
            IMPORTANTE:
            - Este código expira em 10 minutos
            - Não compartilhe este código com ninguém
            - Se você não solicitou este código, ignore este email
            
            Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
            
            Este é um email automático do sistema IOTRAC.
            """
            
            # Adicionar conteúdo
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            
            message.attach(part1)
            message.attach(part2)
            
            # Enviar email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.email_user, self.email_password)
                server.sendmail(self.email_from, email, message.as_string())
            
            logger.info(f"Código 2FA enviado por email para {email}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar email para {email}: {e}")
            return False
    
    def send_anomaly_alert(self, email: str, anomaly_type: str, description: str, 
                          device_id: int, device_type: str, severity: str,
                          user_name: str = "Usuário") -> bool:
        """
        Envia alerta de anomalia por email.
        
        Args:
            email (str): Email do usuário
            anomaly_type (str): Tipo da anomalia
            description (str): Descrição da anomalia
            device_id (int): ID do dispositivo
            device_type (str): Tipo do dispositivo
            severity (str): Severidade (low, medium, high, critical)
            user_name (str): Nome do usuário
            
        Returns:
            bool: True se enviado com sucesso
        """
        if not self.email_enabled:
            logger.error("Serviço de email não configurado")
            return False
        
        # Mapear severidade para cores e ícones
        severity_config = {
            "low": {"color": "#10b981", "bg": "#d1fae5", "icon": "ℹ️", "text": "Baixa"},
            "medium": {"color": "#f59e0b", "bg": "#fef3c7", "icon": "⚠️", "text": "Média"},
            "high": {"color": "#ef4444", "bg": "#fef2f2", "icon": "🚨", "text": "Alta"},
            "critical": {"color": "#dc2626", "bg": "#fef2f2", "icon": "🔴", "text": "Crítica"}
        }
        
        config = severity_config.get(severity, severity_config["medium"])
        
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = f"🚨 Anomalia Detectada - IOTRAC"
            message["From"] = self.email_from
            message["To"] = email
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Anomalia Detectada - IOTRAC</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                    .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #2563eb; }}
                    .alert {{ background-color: {config['bg']}; border: 2px solid {config['color']}; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                    .severity {{ font-size: 18px; font-weight: bold; color: {config['color']}; }}
                    .device-info {{ background-color: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                    .actions {{ background-color: #e0f2fe; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">🔒 IOTRAC</div>
                        <h1>Anomalia Detectada</h1>
                    </div>
                    
                    <p>Olá, {user_name}!</p>
                    
                    <div class="alert">
                        <div class="severity">{config['icon']} Severidade: {config['text']}</div>
                        <h3>Tipo: {anomaly_type.replace('_', ' ').title()}</h3>
                        <p><strong>Descrição:</strong> {description}</p>
                    </div>
                    
                    <div class="device-info">
                        <h3>Dispositivo Afetado:</h3>
                        <p><strong>ID:</strong> #{device_id}</p>
                        <p><strong>Tipo:</strong> {device_type}</p>
                        <p><strong>Data:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                    </div>
                    
                    <div class="actions">
                        <h3>💡 Ações Recomendadas:</h3>
                        <ul>
                            <li>Verifique a atividade recente do dispositivo</li>
                            <li>Confirme se os comandos foram autorizados</li>
                            <li>Considere alterar credenciais se necessário</li>
                            <li>Entre no sistema para mais detalhes</li>
                        </ul>
                    </div>
                    
                    <p>Este alerta foi gerado automaticamente pelo sistema de detecção de anomalias do IOTRAC.</p>
                    
                    <div class="footer">
                        <p>Este é um email automático do sistema IOTRAC</p>
                        <p>Para mais informações, acesse o painel de controle</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            IOTRAC - Anomalia Detectada
            
            Olá, {user_name}!
            
            {config['icon']} ANOMALIA DETECTADA - Severidade: {config['text']}
            
            Tipo: {anomaly_type.replace('_', ' ').title()}
            Descrição: {description}
            
            Dispositivo Afetado:
            - ID: #{device_id}
            - Tipo: {device_type}
            - Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
            
            AÇÕES RECOMENDADAS:
            - Verifique a atividade recente do dispositivo
            - Confirme se os comandos foram autorizados
            - Considere alterar credenciais se necessário
            - Entre no sistema para mais detalhes
            
            Este alerta foi gerado automaticamente pelo sistema de detecção de anomalias do IOTRAC.
            """
            
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            
            message.attach(part1)
            message.attach(part2)
            
            # Enviar email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.email_user, self.email_password)
                server.sendmail(self.email_from, email, message.as_string())
            
            logger.info(f"Alerta de anomalia enviado para {email} - Severidade: {severity}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar alerta de anomalia para {email}: {e}")
            return False
    
    def send_device_registration_notification(self, email: str, device_type: str, 
                                            device_id: int, user_name: str = "Usuário") -> bool:
        """
        Envia notificação de registro de dispositivo.
        
        Args:
            email (str): Email do usuário
            device_type (str): Tipo do dispositivo
            device_id (int): ID do dispositivo
            user_name (str): Nome do usuário
            
        Returns:
            bool: True se enviado com sucesso
        """
        if not self.email_enabled:
            logger.error("Serviço de email não configurado")
            return False
        
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = "Novo Dispositivo Registrado - IOTRAC"
            message["From"] = self.email_from
            message["To"] = email
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Dispositivo Registrado - IOTRAC</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                    .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #2563eb; }}
                    .success {{ background-color: #d1fae5; border: 1px solid #10b981; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                    .device-info {{ background-color: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">🔒 IOTRAC</div>
                        <h1>Dispositivo Registrado</h1>
                    </div>
                    
                    <p>Olá, {user_name}!</p>
                    
                    <div class="success">
                        <strong>✅ Sucesso!</strong> Um novo dispositivo foi registrado em sua conta.
                    </div>
                    
                    <div class="device-info">
                        <h3>Informações do Dispositivo:</h3>
                        <p><strong>Tipo:</strong> {device_type}</p>
                        <p><strong>ID:</strong> #{device_id}</p>
                        <p><strong>Data:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                    </div>
                    
                    <p>Se você não registrou este dispositivo, entre em contato conosco imediatamente.</p>
                    
                    <div class="footer">
                        <p>Este é um email automático do sistema IOTRAC</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            IOTRAC - Dispositivo Registrado
            
            Olá, {user_name}!
            
            Um novo dispositivo foi registrado em sua conta:
            
            Tipo: {device_type}
            ID: #{device_id}
            Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
            
            Se você não registrou este dispositivo, entre em contato conosco imediatamente.
            
            Este é um email automático do sistema IOTRAC.
            """
            
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            
            message.attach(part1)
            message.attach(part2)
            
            # Enviar email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.email_user, self.email_password)
                server.sendmail(self.email_from, email, message.as_string())
            
            logger.info(f"Notificação de dispositivo enviada para {email}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar notificação de dispositivo para {email}: {e}")
            return False
    
    def send_security_alert(self, email: str, alert_type: str, details: str, 
                          user_name: str = "Usuário") -> bool:
        """
        Envia alerta de segurança.
        
        Args:
            email (str): Email do usuário
            alert_type (str): Tipo do alerta
            details (str): Detalhes do alerta
            user_name (str): Nome do usuário
            
        Returns:
            bool: True se enviado com sucesso
        """
        if not self.email_enabled:
            logger.error("Serviço de email não configurado")
            return False
        
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = f"Alerta de Segurança - IOTRAC"
            message["From"] = self.email_from
            message["To"] = email
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Alerta de Segurança - IOTRAC</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                    .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .logo {{ font-size: 24px; font-weight: bold; color: #2563eb; }}
                    .alert {{ background-color: #fef2f2; border: 1px solid #ef4444; padding: 15px; border-radius: 8px; margin: 20px 0; }}
                    .details {{ background-color: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                    .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <div class="logo">🔒 IOTRAC</div>
                        <h1>Alerta de Segurança</h1>
                    </div>
                    
                    <p>Olá, {user_name}!</p>
                    
                    <div class="alert">
                        <strong>⚠️ {alert_type}</strong>
                    </div>
                    
                    <div class="details">
                        <h3>Detalhes:</h3>
                        <p>{details}</p>
                        <p><strong>Data:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                    </div>
                    
                    <p>Se esta atividade não foi autorizada por você, recomendamos que altere sua senha imediatamente.</p>
                    
                    <div class="footer">
                        <p>Este é um email automático do sistema IOTRAC</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            IOTRAC - Alerta de Segurança
            
            Olá, {user_name}!
            
            ALERTA: {alert_type}
            
            Detalhes: {details}
            Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
            
            Se esta atividade não foi autorizada por você, recomendamos que altere sua senha imediatamente.
            
            Este é um email automático do sistema IOTRAC.
            """
            
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            
            message.attach(part1)
            message.attach(part2)
            
            # Enviar email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.email_user, self.email_password)
                server.sendmail(self.email_from, email, message.as_string())
            
            logger.info(f"Alerta de segurança enviado para {email}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar alerta de segurança para {email}: {e}")
            return False

    def send_test_email(self, email: str) -> Dict[str, Any]:
        """
        Envia um email de teste para validar configuração.
        Usado pelo start-iotrac.sh para validação real de credenciais.
        
        Args:
            email (str): Email do destinatário
            
        Returns:
            Dict[str, Any]: Resultado do teste (success, message, error)
        """
        if not self.email_enabled:
            return {
                "success": False,
                "error": "Serviço de email não configurado (EMAIL_USER ou EMAIL_PASSWORD ausente)"
            }
        
        try:
            # Criar mensagem de teste
            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = email
            msg['Subject'] = "🔒 IOTRAC - Teste de Configuração de Email"
            
            # Corpo do email de teste
            body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IOTRAC Email Test</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center;">
        <h1>🔒 IOTRAC</h1>
        <h2>Teste de Configuração de Email</h2>
    </div>
    
    <div style="padding: 20px; background: #f9f9f9; border-radius: 10px; margin: 20px 0;">
        <h3>✅ Configuração Validada com Sucesso!</h3>
        <p>Este é um email de teste enviado automaticamente pelo sistema IOTRAC durante a inicialização.</p>
        
        <div style="background: white; padding: 15px; border-left: 4px solid #4CAF50; margin: 15px 0;">
            <strong>Status:</strong> Credenciais de email válidas<br>
            <strong>Timestamp:</strong> {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}<br>
            <strong>Destinatário:</strong> {email}
        </div>
        
        <p style="color: #666; font-size: 12px;">
            Este email confirma que as credenciais de email estão corretas e o sistema pode enviar notificações de segurança.
        </p>
    </div>
    
    <div style="text-align: center; color: #666; font-size: 12px; margin-top: 20px;">
        <p>IOTRAC Security System - Teste Automático de Email</p>
        <p>Se você não solicitou este teste, ignore este email.</p>
    </div>
</body>
</html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Conectar e enviar
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.email_user, self.email_password)
                server.send_message(msg)
            
            logger.info(f"Email de teste enviado com sucesso para {email}")
            
            return {
                "success": True,
                "message": "Email de teste enviado com sucesso",
                "timestamp": datetime.now().isoformat(),
                "recipient": email
            }
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Erro de autenticação SMTP para {email}: {e}")
            return {
                "success": False,
                "error": "Credenciais de email inválidas (usuário ou senha incorretos)"
            }
            
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"Destinatário recusado para {email}: {e}")
            return {
                "success": False,
                "error": f"Email destinatário inválido: {email}"
            }
            
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"Servidor SMTP desconectado para {email}: {e}")
            return {
                "success": False,
                "error": "Falha na conexão com servidor SMTP"
            }
            
        except Exception as e:
            logger.error(f"Erro geral ao enviar email de teste para {email}: {e}")
            return {
                "success": False,
                "error": f"Erro interno: {str(e)}"
            }

# Instância global do serviço de notificações
notification_service = NotificationService() 