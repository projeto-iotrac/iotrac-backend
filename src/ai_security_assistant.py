# ai_security_assistant.py
# Sistema de IA para Análise de Comportamentos e Assistência em Cibersegurança
# ARQUITETURA ULTRA-SEGURA: 5 camadas de proteção contra vulnerabilidades
# Dependências: fastapi, sqlite3, datetime, typing, logging

import sqlite3
import json
import re
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
import logging
from dataclasses import dataclass

from src.config import setup_logging
from src.db_setup import DATABASE_PATH
from src.auth_db import auth_db_manager

# Configuração de logging
setup_logging()
logger = logging.getLogger(__name__)

class AIActionType(str, Enum):
    """Tipos de ações que a IA pode realizar (todas SOMENTE LEITURA)."""
    SUMMARY_ANALYSIS = "summary_analysis"
    QA_RESPONSE = "qa_response" 
    SECURITY_RECOMMENDATION = "security_recommendation"
    ANOMALY_EXPLANATION = "anomaly_explanation"
    THREAT_ASSESSMENT = "threat_assessment"

class AISecurityLevel(str, Enum):
    """Níveis de segurança para respostas da IA."""
    PUBLIC = "public"          # Informações gerais
    AUTHENTICATED = "authenticated"  # Requer autenticação
    PRIVILEGED = "privileged"  # Requer role admin/operator

@dataclass
class AISecurityContext:
    """Contexto de segurança para operações da IA."""
    user_id: int
    user_role: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime
    action_type: AIActionType

class AISecurityValidator:
    """
    Validador de segurança para todas as operações da IA.
    CAMADA 3: Validação e sanitização rigorosa.
    """
    
    # Lista negra de palavras/comandos perigosos
    BLACKLISTED_TERMS = {
        'exec', 'eval', 'import', 'subprocess', 'os.system', 'shell',
        'rm -rf', 'delete', 'drop', 'truncate', 'alter', 'create',
        'insert', 'update', 'grant', 'revoke', 'chmod', 'chown',
        '__import__', 'getattr', 'setattr', 'delattr', 'globals',
        'locals', 'vars', 'dir', 'compile', 'open', 'file'
    }
    
    # Padrões suspeitos
    SUSPICIOUS_PATTERNS = [
        r'[;&|`$()]',  # Caracteres de shell injection
        r'<script.*?>',  # XSS básico
        r'javascript:',  # JavaScript injection
        r'data:.*base64',  # Data URI suspeito
        r'\\x[0-9a-fA-F]{2}',  # Hex encoding
        r'%[0-9a-fA-F]{2}',  # URL encoding suspeito
    ]
    
    @classmethod
    def validate_input(cls, input_text: str) -> Tuple[bool, str]:
        """
        Valida entrada do usuário contra ataques conhecidos.
        
        Args:
            input_text (str): Texto de entrada
            
        Returns:
            Tuple[bool, str]: (é_válido, motivo_rejeição)
        """
        if not isinstance(input_text, str):
            return False, "Entrada deve ser string"
        
        # Limite de tamanho
        if len(input_text) > 2000:
            return False, "Entrada muito longa (máximo 2000 caracteres)"
        
        # Verificar lista negra
        input_lower = input_text.lower()
        for term in cls.BLACKLISTED_TERMS:
            if term in input_lower:
                logger.warning(f"Termo suspeito detectado: {term}")
                return False, f"Termo não permitido: {term}"
        
        # Verificar padrões suspeitos
        for pattern in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, input_text, re.IGNORECASE):
                logger.warning(f"Padrão suspeito detectado: {pattern}")
                return False, "Padrão suspeito detectado"
        
        return True, "Válido"
    
    @classmethod
    def sanitize_output(cls, output_text: str) -> str:
        """
        Sanitiza saída da IA para prevenir XSS e outros ataques.
        
        Args:
            output_text (str): Texto de saída
            
        Returns:
            str: Texto sanitizado
        """
        if not isinstance(output_text, str):
            return str(output_text)
        
        # Escapar caracteres HTML perigosos
        output_text = output_text.replace('<', '&lt;')
        output_text = output_text.replace('>', '&gt;')
        output_text = output_text.replace('"', '&quot;')
        output_text = output_text.replace("'", '&#x27;')
        
        # Remover caracteres de controle
        output_text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', output_text)
        
        return output_text

class AIAuditLogger:
    """
    Sistema de auditoria para todas as ações da IA.
    CAMADA 5: Monitoramento total.
    """
    
    @staticmethod
    def log_ai_action(context: AISecurityContext, query: str, response: str, 
                     success: bool, details: Optional[str] = None) -> None:
        """
        Registra ação da IA no sistema de auditoria.
        
        Args:
            context: Contexto de segurança
            query: Query do usuário
            response: Resposta da IA
            success: Se a operação foi bem-sucedida
            details: Detalhes adicionais
        """
        try:
            # Hash das informações sensíveis para auditoria
            query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
            response_hash = hashlib.sha256(response.encode()).hexdigest()[:16]
            
            audit_details = {
                "action_type": context.action_type.value,
                "query_hash": query_hash,
                "response_hash": response_hash,
                "query_length": len(query),
                "response_length": len(response),
                "ip_address": context.ip_address,
                "user_agent": context.user_agent,
                "additional_details": details
            }
            
            # Log no sistema de autenticação (reutilizando infraestrutura existente)
            auth_db_manager.log_auth_event(
                user_id=context.user_id,
                action=f"ai_{context.action_type.value}",
                success=success,
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                details=json.dumps(audit_details)
            )
            
            # Log local para análise técnica
            logger.info(f"IA Action: user={context.user_id}, type={context.action_type.value}, "
                       f"success={success}, query_len={len(query)}, response_len={len(response)}")
            
        except Exception as e:
            logger.error(f"Erro ao registrar auditoria da IA: {e}")

class AIDataRetriever:
    """
    Classe para recuperação SEGURA de dados.
    CAMADA 4: Somente leitura, sem acesso direto ao banco.
    """
    
    def __init__(self):
        """Inicializa o recuperador de dados."""
        self.db_path = DATABASE_PATH
    
    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Recupera resumo de segurança das últimas N horas.
        SOMENTE LEITURA - Usa dados já processados.
        
        Args:
            hours (int): Período em horas
            
        Returns:
            Dict[str, Any]: Resumo de segurança
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            time_limit = datetime.now() - timedelta(hours=hours)
            
            # Contar alertas por severidade
            cursor.execute('''
                SELECT severity, COUNT(*) FROM simple_logs 
                WHERE timestamp >= ? AND severity IN ('warning', 'critical')
                GROUP BY severity
            ''', (time_limit,))
            
            alert_counts = dict(cursor.fetchall())
            
            # Dispositivos mais ativos
            cursor.execute('''
                SELECT device_name, COUNT(*) as activity_count 
                FROM simple_logs 
                WHERE timestamp >= ? AND device_name IS NOT NULL
                GROUP BY device_name 
                ORDER BY activity_count DESC 
                LIMIT 5
            ''', (time_limit,))
            
            top_devices = [{"name": row[0], "activity": row[1]} for row in cursor.fetchall()]
            
            # Tipos de eventos mais comuns
            cursor.execute('''
                SELECT type, COUNT(*) as event_count 
                FROM simple_logs 
                WHERE timestamp >= ?
                GROUP BY type 
                ORDER BY event_count DESC 
                LIMIT 5
            ''', (time_limit,))
            
            top_events = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            return {
                "period_hours": hours,
                "alert_counts": alert_counts,
                "top_devices": top_devices,
                "top_events": top_events,
                "total_alerts": sum(alert_counts.values()),
                "critical_alerts": alert_counts.get('critical', 0),
                "warning_alerts": alert_counts.get('warning', 0)
            }
            
        except Exception as e:
            logger.error(f"Erro ao recuperar resumo de segurança: {e}")
            return {"error": "Erro ao recuperar dados"}
    
    def get_anomaly_context(self, device_id: Optional[int] = None, hours: int = 24) -> Dict[str, Any]:
        """
        Recupera contexto de anomalias detectadas.
        
        Args:
            device_id (Optional[int]): ID do dispositivo específico
            hours (int): Período em horas
            
        Returns:
            Dict[str, Any]: Contexto de anomalias
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            time_limit = datetime.now() - timedelta(hours=hours)
            
            # Base query para anomalias
            base_query = '''
                SELECT device_id, anomaly_type, severity, description, timestamp 
                FROM anomaly_alerts 
                WHERE timestamp >= ? AND resolved = 0
            '''
            params = [time_limit]
            
            if device_id:
                base_query += ' AND device_id = ?'
                params.append(device_id)
            
            base_query += ' ORDER BY timestamp DESC LIMIT 20'
            
            cursor.execute(base_query, params)
            anomalies = [
                {
                    "device_id": row[0],
                    "type": row[1],
                    "severity": row[2],
                    "description": row[3],
                    "timestamp": row[4]
                }
                for row in cursor.fetchall()
            ]
            
            conn.close()
            
            return {
                "anomalies": anomalies,
                "total_count": len(anomalies),
                "period_hours": hours,
                "device_filter": device_id
            }
            
        except Exception as e:
            logger.error(f"Erro ao recuperar contexto de anomalias: {e}")
            return {"error": "Erro ao recuperar dados"}

class AISecurityAssistant:
    """
    Assistente de IA para análise de comportamentos e cibersegurança.
    ARQUITETURA ULTRA-SEGURA com 5 camadas de proteção.
    """
    
    def __init__(self):
        """Inicializa o assistente de IA."""
        self.validator = AISecurityValidator()
        self.data_retriever = AIDataRetriever()
        self.audit_logger = AIAuditLogger()
        
        # Respostas pré-definidas para intents comuns (heurística)
        self.intent_responses = {
            "status_sistema": self._get_system_status,
            "alertas_recentes": self._get_recent_alerts,
            "dispositivos_suspeitos": self._get_suspicious_devices,
            "recomendacoes_seguranca": self._get_security_recommendations,
            "explicar_anomalia": self._explain_anomaly,
            "protecao_fisica": self._get_physical_protection_tips,
            # Novos intents específicos solicitados
            "historia_argos": self._get_argos_history,
            "sistema_protecao": self._get_protection_system_overview,
            "detalhar_camada_2": self._explain_layer_two,
        }
        
        logger.info("AI Security Assistant inicializado com sucesso")
    
    def process_query(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """
        Processa query do usuário com máxima segurança.
        
        Args:
            query (str): Query do usuário
            context (AISecurityContext): Contexto de segurança
            
        Returns:
            Dict[str, Any]: Resposta processada
        """
        start_time = datetime.now()
        
        try:
            # CAMADA 3: Validação de entrada
            is_valid, validation_error = self.validator.validate_input(query)
            if not is_valid:
                self.audit_logger.log_ai_action(
                    context, query, f"REJECTED: {validation_error}", 
                    False, f"Input validation failed: {validation_error}"
                )
                return {
                    "success": False,
                    "error": "Query rejeitada por motivos de segurança",
                    "details": validation_error
                }
            
            # Detectar intent da query
            intent = self._detect_intent(query)
            
            # Processar baseado no intent
            if intent in self.intent_responses:
                raw_response = self.intent_responses[intent](query, context)
            else:
                raw_response = self._handle_general_query(query, context)
            
            # CAMADA 3: Sanitização da saída
            if isinstance(raw_response, str):
                sanitized_response = self.validator.sanitize_output(raw_response)
            else:
                sanitized_response = raw_response
                if "message" in sanitized_response:
                    sanitized_response["message"] = self.validator.sanitize_output(
                        sanitized_response["message"]
                    )
            
            # INTEGRAÇÃO LLM: Tentar melhorar resposta se LLM estiver configurado
            try:
                from src.ai_llm_integration import llm_manager
                if llm_manager.enabled:
                    original_message = sanitized_response.get("message", str(sanitized_response))
                    enhanced_result = llm_manager.enhance_response(
                        original_message, 
                        f"Intent: {intent}, User role: {context.user_role}"
                    )
                    
                    if enhanced_result.get("enhanced"):
                        sanitized_response["message"] = enhanced_result["response"]
                        sanitized_response["llm_enhanced"] = True
                        sanitized_response["llm_provider"] = enhanced_result.get("provider", llm_manager.provider.value if llm_manager.provider else None)
                    else:
                        sanitized_response["llm_enhanced"] = False
                        sanitized_response["llm_reason"] = enhanced_result.get("reason", "N/A")
                else:
                    sanitized_response["llm_enhanced"] = False
                    sanitized_response["llm_reason"] = "LLM não configurado"
            except Exception as llm_error:
                logger.warning(f"Erro na integração LLM: {llm_error}")
                sanitized_response["llm_enhanced"] = False
                sanitized_response["llm_reason"] = "Erro na integração LLM"
            
            # CAMADA 5: Auditoria
            processing_time = (datetime.now() - start_time).total_seconds()
            self.audit_logger.log_ai_action(
                context, query, str(sanitized_response)[:200], True,
                f"Processing time: {processing_time:.2f}s, Intent: {intent}"
            )
            
            return {
                "success": True,
                "response": sanitized_response,
                "intent": intent,
                "processing_time": processing_time
            }
            
        except Exception as e:
            logger.error(f"Erro ao processar query da IA: {e}")
            error_response = "Erro interno do assistente de IA"
            
            self.audit_logger.log_ai_action(
                context, query, error_response, False, f"Exception: {str(e)}"
            )
            
            return {
                "success": False,
                "error": error_response,
                "details": "Erro interno"
            }
    
    def _get_argos_history(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """História e missão do Argos (mitologia e papel no IOTRAC)."""
        message = (
            "🏛️ Memória de Argos\n\n"
            "Introdução\n"
            "Meu nome é inspirado na mitologia grega, onde Argos Panoptes (também conhecido como Argos, o 'todo-vidente') "
            "era um gigante com cem olhos, famoso por sua vigilância inabalável. Na lenda, ele foi incumbido pela deusa Hera. "
            "Com seus cem olhos distribuídos pelo corpo, Argos podia vigiar em todas as direções simultaneamente, dormindo apenas "
            "com alguns olhos enquanto os outros permaneciam abertos. Assim como esse guardião mitológico, eu estou aqui para "
            "monitorar e proteger seus dispositivos conectados em tempo real, garantindo uma vigilância constante e infalível "
            "contra ameaças.\n\n"
            "Minha Missão\n"
            "Minha missão principal é guiar sua experiência no IOTRAC, atuando como um aliado proativo na segurança digital. "
            "Eu não sou apenas um chatbot; sou o coração inteligente do sistema, responsável por detectar anomalias, fornecer "
            "orientações e esclarecer dúvidas para tornar seu ambiente conectado mais seguro.\n\n"
            "Funções Específicas\n"
            "- Detecção de Anomalias: Varredura contínua em busca de comportamentos suspeitos nos dispositivos IoT conectados, "
            "identificando ameaças potenciais antes que elas se tornem problemas.\n\n"
            "- Orientações de Segurança: Forneço dicas práticas e personalizadas para fortalecer a proteção dos seus dispositivos, "
            "indo além das capacidades do app. Por exemplo, para proteger o sinal da chave do seu carro autônomo, recomendo o uso de "
            "uma carteira anti-roubo de sinal (bolsa Faraday), que bloqueia tentativas de interceptação remota.\n\n"
            "- Esclarecimento de Dúvidas: Programado para explicar ataques cibernéticos, alertas e notificações do sistema.\n\n"
            "- Ações de Proteção Diretas: Executo ações somente com sua autorização explícita, garantindo controle total.\n\n"
            "- Monitoramento e Alertas: Acompanho tráfego, padrões de uso e vulnerabilidades em tempo real, enviando alertas imediatos.\n"
        )
        return {"message": message}

    def _get_protection_system_overview(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Visão geral das camadas de proteção do IOTRAC."""
        message = (
            "🛡️ Sistema de Proteção IOTRAC\n\n"
            "Camada 1 - Autenticação e Autorização\n"
            "- 2FA obrigatório\n- RBAC por função\n- Renovação segura de tokens\n- Criptografia AES-256 para dados sensíveis\n\n"
            "Camada 2 - Monitoramento Ativo\n"
            "- Detecção de anomalias em tempo real\n- Análise de padrões de tráfego suspeitos\n- Alertas automáticos e logs completos\n\n"
            "Camada 3 - Proteção de Dispositivos\n"
            "- Interceptação/validação de comandos\n- Bloqueio de ações suspeitas\n- Proteção HMAC contra adulteração\n- Quarentena de dispositivos comprometidos\n\n"
            "Camada 4 - Inteligência Artificial\n"
            "- Análise contínua com IA\n- Recomendações personalizadas\n- Respostas assistidas a incidentes\n"
        )
        return {"message": message}

    def _explain_layer_two(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Detalhamento técnico da Camada 2 (monitoramento ativo)."""
        # Buscar dados reais de 24h para enriquecer a resposta
        summary = self.data_retriever.get_security_summary(24)
        anomalies = self.data_retriever.get_anomaly_context(hours=24)
        total_alerts = summary.get('total_alerts', 0)
        critical = summary.get('critical_alerts', 0)
        warning = summary.get('warning_alerts', 0)
        recent_anoms = anomalies.get('total_count', 0)
        message = (
            "🧭 Camada 2 - Monitoramento Ativo (Detalhado)\n\n"
            "O IOTRAC acompanha continuamente seu ambiente IoT em múltiplas frentes:\n\n"
            "1) Telemetria e Logs\n"
            "- Coleta de eventos relevantes (conexões, comandos, alterações de estado)\n"
            "- Consolidação em 'simple_logs' para análise e auditoria\n\n"
            "2) Regras de Anomalia\n"
            "- Sequência suspeita de comandos\n- Frequência/tempo incomuns\n- Repetição e falhas em burst\n- Padrões fora do histórico normal\n\n"
            "3) Alertas e Severidade\n"
            f"- Últimas 24h: {total_alerts} alertas (Críticos: {critical}, Avisos: {warning})\n"
            f"- Anomalias recentes não resolvidas: {recent_anoms}\n\n"
            "4) Ação e Resposta\n"
            "- Logs detalhados por evento\n- Recomendação de mitigação\n- Possibilidade de bloqueio/isolamento via Camada 3\n\n"
            "Observação: a Camada 2 é não intrusiva (somente leitura). A intervenção ocorre na Camada 3."
        )
        return {"message": message, "data": {"summary": summary, "anomalies": anomalies}}

    def _detect_intent(self, query: str) -> str:
        """
        Detecta a intenção da query usando regras heurísticas.
        
        Args:
            query (str): Query do usuário
            
        Returns:
            str: Intent detectado
        """
        query_lower = query.lower()
        
        # Mapeamento de palavras-chave para intents
        intent_keywords = {
            "status_sistema": ["status", "situação", "como está", "resumo", "overview"],
            "alertas_recentes": ["alertas", "avisos", "problemas", "últimos", "recentes"],
            "dispositivos_suspeitos": ["dispositivo suspeito", "comportamento estranho", "anômalo"],
            "recomendacoes_seguranca": ["como proteger", "recomendação", "sugestão", "melhorar segurança"],
            "explicar_anomalia": ["por que", "explicar", "o que significa", "anomalia"],
            "protecao_fisica": ["proteção física", "roubo", "chave", "carro", "recipiente"],
            # Novos intents
            "historia_argos": ["história do argos", "historia do argos", "quem é argos", "argos panoptes", "mitologia", "memória de argos", "memoria de argos"],
            "sistema_protecao": ["sistema de proteção", "sistema de protecao", "camadas de segurança", "camadas do iotrac", "sistema iotrac"],
            "detalhar_camada_2": ["camada 2", "camada dois", "monitoramento ativo", "detecção de anomalias", "analise de padrões", "análise de padrões"],
        }
        
        for intent, keywords in intent_keywords.items():
            if any(keyword in query_lower for keyword in keywords):
                return intent
        
        return "general_query"
    
    def _get_system_status(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Retorna status geral do sistema."""
        summary = self.data_retriever.get_security_summary(24)
        
        if "error" in summary:
            return {"message": "Não foi possível recuperar o status do sistema no momento."}
        
        status_message = f"""
🔒 **Status de Segurança IOTRAC (Últimas 24h)**

📊 **Resumo de Alertas:**
• Total: {summary['total_alerts']} alertas
• Críticos: {summary['critical_alerts']}
• Avisos: {summary['warning_alerts']}

🔥 **Dispositivos Mais Ativos:**
"""
        
        for device in summary['top_devices'][:3]:
            status_message += f"• {device['name']}: {device['activity']} eventos\n"
        
        if summary['critical_alerts'] == 0:
            status_message += "\n✅ **Nenhum alerta crítico ativo**"
        else:
            status_message += f"\n⚠️ **{summary['critical_alerts']} alertas críticos requerem atenção**"
        
        return {
            "message": status_message,
            "data": summary,
            "recommendations": self._generate_status_recommendations(summary)
        }
    
    def _get_recent_alerts(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Retorna alertas recentes."""
        anomalies = self.data_retriever.get_anomaly_context(hours=24)
        
        if not anomalies.get('anomalies'):
            return {"message": "🎉 Nenhum alerta recente! Seus dispositivos estão seguros."}
        
        alert_message = f"🚨 **Alertas Recentes ({len(anomalies['anomalies'])} encontrados)**\n\n"
        
        for anomaly in anomalies['anomalies'][:5]:
            severity_icon = "🔴" if anomaly['severity'] == 'critical' else "🟡"
            alert_message += f"{severity_icon} **{anomaly['type']}** - {anomaly['description']}\n"
        
        return {
            "message": alert_message,
            "data": anomalies,
            "recommendations": ["Investigue alertas críticos imediatamente", 
                             "Configure notificações automáticas"]
        }
    
    def _get_suspicious_devices(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Identifica dispositivos com comportamento suspeito."""
        summary = self.data_retriever.get_security_summary(48)
        
        suspicious_message = "🔍 **Análise de Dispositivos Suspeitos**\n\n"
        
        if summary.get('top_devices'):
            suspicious_message += "📈 **Dispositivos com Alta Atividade:**\n"
            for device in summary['top_devices'][:3]:
                if device['activity'] > 50:  # Threshold para atividade suspeita
                    suspicious_message += f"⚠️ {device['name']}: {device['activity']} eventos (Alto)\n"
                else:
                    suspicious_message += f"✅ {device['name']}: {device['activity']} eventos (Normal)\n"
        
        return {"message": suspicious_message, "data": summary}
    
    def _get_security_recommendations(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Gera recomendações de segurança."""
        recommendations = [
            "🔐 **Autenticação:** Mantenha 2FA ativado em todos os dispositivos",
            "🔄 **Atualizações:** Verifique firmware dos dispositivos mensalmente", 
            "📱 **Monitoramento:** Configure alertas automáticos para eventos críticos",
            "🔒 **Senhas:** Use senhas únicas e complexas para cada dispositivo",
            "🌐 **Rede:** Mantenha dispositivos IoT em rede separada quando possível"
        ]
        
        physical_recommendations = [
            "🚗 **Carros:** Use recipiente anti-roubo para chaves (Faraday cage)",
            "🏠 **Casa:** Dispositivos IoT longe de janelas (evita interceptação)",
            "📶 **WiFi:** Roteador com WPA3 e senha forte",
            "🔌 **Físico:** Dispositivos em locais seguros, longe de acesso não autorizado"
        ]
        
        return {
            "message": "🛡️ **Recomendações de Segurança IOTRAC**",
            "digital_security": recommendations,
            "physical_security": physical_recommendations,
            "priority": "Implemente proteção física primeiro, depois digital"
        }
    
    def _get_physical_protection_tips(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Dicas específicas de proteção física."""
        tips = {
            "carro_autonomo": [
                "🔑 **Chave:** Recipiente Faraday para bloquear sinais",
                "📡 **Relay Attack:** Mantenha chave > 5m do carro em casa",
                "🔒 **Steering Lock:** Trava física adicional no volante",
                "📱 **App:** Desative funções remotas quando não usar"
            ],
            "casa_inteligente": [
                "🚪 **Smart Locks:** Sempre com chave física de backup",
                "📹 **Câmeras:** Posicionamento que evite pontos cegos",
                "🔌 **Dispositivos:** Alimentação protegida contra cortes",
                "📶 **Rede:** Roteador em local central e protegido"
            ],
            "geral": [
                "🔍 **Inspeção:** Verificar dispositivos fisicamente mensalmente",
                "⚡ **Energia:** UPS para dispositivos críticos",
                "🌡️ **Ambiente:** Proteger contra temperatura/umidade extremas",
                "👥 **Acesso:** Limitar quem tem acesso físico aos dispositivos"
            ]
        }
        
        return {
            "message": "🛡️ **Guia de Proteção Física IOTRAC**",
            "categories": tips,
            "warning": "⚠️ Proteção física é tão importante quanto digital!"
        }
    
    def _explain_anomaly(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Explica anomalias detectadas."""
        anomaly_explanations = {
            "suspicious_sequence": "Sequência de comandos fora do padrão normal de uso",
            "unusual_frequency": "Frequência de comandos muito alta ou baixa",
            "unusual_timing": "Comandos enviados em horários atípicos",
            "repeated_commands": "Mesmo comando repetido muitas vezes",
            "failed_commands_burst": "Muitos comandos falharam em sequência"
        }
        
        return {
            "message": "🧠 **Explicações de Anomalias**",
            "explanations": anomaly_explanations,
            "note": "Anomalias são detectadas comparando com padrões históricos normais"
        }
    
    def _handle_general_query(self, query: str, context: AISecurityContext) -> Dict[str, Any]:
        """Trata queries gerais."""
        return {
            "message": f"Recebi sua pergunta: '{query[:100]}...' \n\n" +
                      "🤖 Sou o assistente de segurança IOTRAC. Posso ajudar com:\n" +
                      "• Status do sistema\n• Alertas recentes\n• Recomendações de segurança\n" +
                      "• Explicação de anomalias\n• Dicas de proteção física",
            "suggestions": [
                "Como está o status do sistema?",
                "Quais são os alertas recentes?",
                "Como proteger meu carro autônomo?"
            ]
        }
    
    def _generate_status_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas no status atual."""
        recommendations = []
        
        if summary['critical_alerts'] > 0:
            recommendations.append("🚨 Investigue alertas críticos imediatamente")
        
        if summary['total_alerts'] > 20:
            recommendations.append("📈 Alto volume de alertas - considere ajustar sensibilidade")
        
        if len(summary['top_devices']) > 0:
            most_active = summary['top_devices'][0]
            if most_active['activity'] > 100:
                recommendations.append(f"🔍 Investigar alta atividade: {most_active['name']}")
        
        if not recommendations:
            recommendations.append("✅ Sistema operando normalmente")
        
        return recommendations

# Instância global do assistente
ai_assistant = AISecurityAssistant() 