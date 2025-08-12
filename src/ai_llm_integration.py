# ai_llm_integration.py
# Integração Segura com LLMs Externos para IOTRAC
# ARQUITETURA ULTRA-SEGURA: Sem exposição de dados sensíveis
# Dependências: requests, json, logging

import os
import json
import requests
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import logging

from src.config import setup_logging

# Configuração de logging
setup_logging()
logger = logging.getLogger(__name__)

class LLMProvider(str, Enum):
    """Provedores de LLM suportados."""
    HUGGINGFACE = "huggingface"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    TOGETHER = "together"
    CUSTOM = "custom"

class LLMSecurityFilter:
    """
    Filtro de segurança para integração com LLMs.
    Remove dados sensíveis antes de enviar para APIs externas.
    """
    
    # Dados sensíveis que NUNCA devem ser enviados
    SENSITIVE_PATTERNS = [
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IPs
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Emails
        r'\b(?:password|senha|token|key|secret)\s*[:=]\s*\S+',  # Credenciais
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Cartões
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b[A-F0-9]{32,}\b',  # Hashes/tokens
    ]
    
    @classmethod
    def sanitize_for_llm(cls, text: str) -> str:
        """
        Remove dados sensíveis do texto antes de enviar para LLM.
        
        Args:
            text (str): Texto original
            
        Returns:
            str: Texto sanitizado
        """
        import re
        
        sanitized = text
        
        # Substituir padrões sensíveis
        for pattern in cls.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, '[DADOS_REMOVIDOS]', sanitized, flags=re.IGNORECASE)
        
        # Limitar tamanho do texto
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000] + "... [TEXTO_TRUNCADO]"
        
        return sanitized
    
    @classmethod
    def validate_response(cls, response: str) -> bool:
        """
        Valida resposta do LLM para evitar conteúdo malicioso.
        
        Args:
            response (str): Resposta do LLM
            
        Returns:
            bool: True se a resposta é segura
        """
        if not isinstance(response, str):
            return False
        
        # Verificar tamanho
        if len(response) > 5000:
            return False
        
        # Verificar conteúdo suspeito
        suspicious_terms = [
            '<script', 'javascript:', 'eval(', 'exec(',
            'rm -rf', 'sudo ', 'chmod ', 'wget ', 'curl '
        ]
        
        response_lower = response.lower()
        for term in suspicious_terms:
            if term in response_lower:
                return False
        
        return True

class LLMIntegrationManager:
    """
    Gerenciador de integração com LLMs externos.
    MÁXIMA SEGURANÇA: Sem dados sensíveis, validação rigorosa.
    """
    
    def __init__(self):
        """Inicializa o gerenciador de LLM."""
        self.security_filter = LLMSecurityFilter()
        self.api_token = None
        self.provider = None
        self.enabled = False
        
        logger.info("LLM Integration Manager inicializado (desabilitado por padrão)")
    
    def configure_llm(self, provider: LLMProvider, api_token: str, 
                     custom_endpoint: Optional[str] = None) -> Dict[str, Any]:
        """
        Configura integração com LLM externo.
        
        Args:
            provider (LLMProvider): Provedor do LLM
            api_token (str): Token da API
            custom_endpoint (Optional[str]): Endpoint customizado
            
        Returns:
            Dict[str, Any]: Status da configuração
        """
        try:
            # Validar token
            if not api_token or len(api_token) < 10:
                return {
                    "success": False,
                    "error": "Token da API inválido ou muito curto"
                }
            
            # Testar conectividade
            test_result = self._test_llm_connection(provider, api_token, custom_endpoint)
            
            if test_result["success"]:
                self.provider = provider
                self.api_token = api_token
                self.custom_endpoint = custom_endpoint
                self.enabled = True
                
                logger.info(f"LLM integração configurada: {provider.value}")
                
                return {
                    "success": True,
                    "message": f"LLM {provider.value} configurado com sucesso",
                    "provider": provider.value
                }
            else:
                return {
                    "success": False,
                    "error": f"Falha ao conectar com {provider.value}: {test_result['error']}"
                }
                
        except Exception as e:
            logger.error(f"Erro ao configurar LLM: {e}")
            return {
                "success": False,
                "error": "Erro interno ao configurar LLM"
            }
    
    def _test_llm_connection(self, provider: LLMProvider, api_token: str, 
                           custom_endpoint: Optional[str] = None) -> Dict[str, Any]:
        """
        Testa conexão com o LLM.
        
        Args:
            provider (LLMProvider): Provedor
            api_token (str): Token
            custom_endpoint (Optional[str]): Endpoint customizado
            
        Returns:
            Dict[str, Any]: Resultado do teste
        """
        try:
            # Configurar endpoint baseado no provedor
            if provider == LLMProvider.HUGGINGFACE:
                url = "https://api-inference.huggingface.co/models/microsoft/DialoGPT-small"
                headers = {"Authorization": f"Bearer {api_token}"}
                payload = {"inputs": "Hello"}
                
            elif provider == LLMProvider.TOGETHER:
                url = "https://api.together.xyz/inference"
                headers = {"Authorization": f"Bearer {api_token}"}
                payload = {
                    "model": "togethercomputer/RedPajama-INCITE-Chat-3B-v1",
                    "prompt": "Hello",
                    "max_tokens": 10
                }
                
            elif provider == LLMProvider.CUSTOM:
                if not custom_endpoint:
                    return {"success": False, "error": "Endpoint customizado necessário"}
                url = custom_endpoint
                headers = {"Authorization": f"Bearer {api_token}"}
                payload = {"prompt": "test"}
                
            else:
                return {"success": False, "error": f"Provedor {provider.value} não suportado ainda"}
            
            # Fazer requisição de teste
            response = requests.post(
                url, 
                headers=headers, 
                json=payload, 
                timeout=10
            )
            
            if response.status_code == 200:
                return {"success": True, "message": "Conexão estabelecida"}
            else:
                return {
                    "success": False, 
                    "error": f"HTTP {response.status_code}: {response.text[:100]}"
                }
                
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Erro de conexão: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Erro interno: {str(e)}"}
    
    def enhance_response(self, original_response: str, context: str = "") -> Dict[str, Any]:
        """
        Melhora resposta usando LLM externo (se configurado).
        
        Args:
            original_response (str): Resposta original da IA heurística
            context (str): Contexto adicional
            
        Returns:
            Dict[str, Any]: Resposta melhorada ou original
        """
        if not self.enabled:
            return {
                "enhanced": False,
                "response": original_response,
                "reason": "LLM não configurado"
            }
        
        try:
            # Sanitizar dados antes de enviar
            safe_response = self.security_filter.sanitize_for_llm(original_response)
            safe_context = self.security_filter.sanitize_for_llm(context) if context else ""
            
            # Criar prompt seguro
            prompt = self._create_safe_prompt(safe_response, safe_context)
            
            # Chamar LLM
            llm_result = self._call_llm(prompt)
            
            if llm_result["success"]:
                enhanced_text = llm_result["response"]
                
                # Validar resposta do LLM
                if self.security_filter.validate_response(enhanced_text):
                    logger.info("Resposta melhorada com LLM externo")
                    return {
                        "enhanced": True,
                        "response": enhanced_text,
                        "original": original_response,
                        "provider": self.provider.value
                    }
                else:
                    logger.warning("Resposta do LLM rejeitada por segurança")
                    return {
                        "enhanced": False,
                        "response": original_response,
                        "reason": "Resposta do LLM rejeitada por segurança"
                    }
            else:
                logger.error(f"Erro do LLM: {llm_result['error']}")
                return {
                    "enhanced": False,
                    "response": original_response,
                    "reason": f"Erro do LLM: {llm_result['error']}"
                }
                
        except Exception as e:
            logger.error(f"Erro ao melhorar resposta com LLM: {e}")
            return {
                "enhanced": False,
                "response": original_response,
                "reason": "Erro interno"
            }
    
    def _create_safe_prompt(self, response: str, context: str) -> str:
        """
        Cria prompt seguro para o LLM.
        
        Args:
            response (str): Resposta original
            context (str): Contexto
            
        Returns:
            str: Prompt seguro
        """
        prompt = f"""
Você é um assistente de cibersegurança. Melhore a resposta abaixo para ser mais clara e útil, 
mantendo foco em segurança de dispositivos IoT. Não inclua informações pessoais ou comandos.

Resposta original: {response}

Contexto adicional: {context}

Resposta melhorada (máximo 300 palavras):
"""
        return prompt.strip()
    
    def _call_llm(self, prompt: str) -> Dict[str, Any]:
        """
        Faz chamada para o LLM.
        
        Args:
            prompt (str): Prompt para o LLM
            
        Returns:
            Dict[str, Any]: Resposta do LLM
        """
        try:
            if self.provider == LLMProvider.HUGGINGFACE:
                return self._call_huggingface(prompt)
            elif self.provider == LLMProvider.TOGETHER:
                return self._call_together(prompt)
            elif self.provider == LLMProvider.CUSTOM:
                return self._call_custom(prompt)
            else:
                return {"success": False, "error": "Provedor não implementado"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _call_huggingface(self, prompt: str) -> Dict[str, Any]:
        """Chama API do Hugging Face."""
        url = "https://api-inference.huggingface.co/models/microsoft/DialoGPT-medium"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        payload = {"inputs": prompt, "parameters": {"max_length": 300}}
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list) and len(result) > 0:
                return {"success": True, "response": result[0].get("generated_text", "")}
            else:
                return {"success": False, "error": "Resposta inválida do HuggingFace"}
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    
    def _call_together(self, prompt: str) -> Dict[str, Any]:
        """Chama API do Together AI."""
        url = "https://api.together.xyz/inference"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        payload = {
            "model": "togethercomputer/RedPajama-INCITE-Chat-3B-v1",
            "prompt": prompt,
            "max_tokens": 300,
            "temperature": 0.7
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            return {"success": True, "response": result.get("output", {}).get("choices", [{}])[0].get("text", "")}
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    
    def _call_custom(self, prompt: str) -> Dict[str, Any]:
        """Chama endpoint customizado."""
        headers = {"Authorization": f"Bearer {self.api_token}"}
        payload = {"prompt": prompt, "max_tokens": 300}
        
        response = requests.post(self.custom_endpoint, headers=headers, json=payload, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            return {"success": True, "response": result.get("response", "")}
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    
    def disable_llm(self) -> Dict[str, Any]:
        """
        Desabilita integração com LLM.
        
        Returns:
            Dict[str, Any]: Status da operação
        """
        self.enabled = False
        self.api_token = None
        self.provider = None
        self.custom_endpoint = None
        
        logger.info("LLM integração desabilitada")
        
        return {
            "success": True,
            "message": "LLM desabilitado com sucesso"
        }
    
    def get_status(self) -> Dict[str, Any]:
        """
        Retorna status da integração LLM.
        
        Returns:
            Dict[str, Any]: Status atual
        """
        return {
            "enabled": self.enabled,
            "provider": self.provider.value if self.provider else None,
            "has_token": bool(self.api_token),
            "security_filters": "active",
            "supported_providers": [provider.value for provider in LLMProvider]
        }

# Instância global do gerenciador LLM
llm_manager = LLMIntegrationManager() 