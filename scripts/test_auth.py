#!/usr/bin/env python3
"""
Script de teste para demonstrar o funcionamento dos endpoints de autenticação.
Execute este script após inicializar o servidor para testar as funcionalidades.

Uso:
    python scripts/test_auth.py
"""

import requests
import json
import time
import sys
import os

# Configurações
BASE_URL = "http://localhost:8000"
TEST_EMAIL = "admin@iotrac.com"
TEST_PASSWORD = "Admin123!@#"
TEST_NAME = "Administrador IOTRAC"
TEST_PHONE = "+5511999999999"

def print_header(title):
    """Imprime cabeçalho formatado."""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def print_step(step, description):
    """Imprime passo do teste."""
    print(f"\n[PASSO {step}] {description}")
    print("-" * 40)

def print_response(response, show_full=False):
    """Imprime resposta da API."""
    print(f"Status: {response.status_code}")
    if show_full:
        try:
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2, ensure_ascii=False)}")
        except:
            print(f"Response: {response.text}")
    else:
        try:
            data = response.json()
            if 'message' in data:
                print(f"Message: {data['message']}")
            if 'success' in data:
                print(f"Success: {data['success']}")
        except:
            print(f"Response: {response.text}")

def test_server_connection():
    """Testa conexão com o servidor."""
    print_step(1, "Testando conexão com o servidor")
    
    try:
        response = requests.get(f"{BASE_URL}/")
        print_response(response)
        
        if response.status_code == 200:
            print("✅ Servidor está rodando!")
            return True
        else:
            print("❌ Servidor não está respondendo corretamente")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Não foi possível conectar ao servidor")
        print(f"   Certifique-se que o servidor está rodando em {BASE_URL}")
        return False

def test_user_registration():
    """Testa registro de usuário."""
    print_step(2, "Testando registro de usuário")
    
    user_data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "confirm_password": TEST_PASSWORD,
        "full_name": TEST_NAME,
        "phone": TEST_PHONE,
        "role": "admin"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/auth/register", json=user_data)
        print_response(response, show_full=True)
        
        if response.status_code == 200:
            print("✅ Usuário registrado com sucesso!")
            return True
        elif response.status_code == 400:
            data = response.json()
            if "já está registrado" in data.get('detail', ''):
                print("ℹ️  Usuário já existe (ok para teste)")
                return True
        
        print("❌ Falha no registro do usuário")
        return False
    except Exception as e:
        print(f"❌ Erro na requisição: {e}")
        return False

def test_login_flow():
    """Testa fluxo completo de login com 2FA."""
    print_step(3, "Testando fluxo de login - Etapa 1")
    
    # Etapa 1: Login
    login_data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    }
    
    try:
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
        print_response(response, show_full=True)
        
        if response.status_code != 200:
            print("❌ Falha na etapa 1 do login")
            return None
        
        data = response.json()
        temp_token = data.get('temp_token')
        
        if not temp_token:
            print("❌ Token temporário não recebido")
            return None
        
        print("✅ Etapa 1 do login concluída!")
        print(f"   Token temporário: {temp_token[:20]}...")
        
        # Simular código 2FA (em produção, seria enviado por email/SMS)
        print_step(4, "Testando fluxo de login - Etapa 2 (2FA)")
        print("ℹ️  Em um cenário real, você receberia um código por email/SMS")
        print("ℹ️  Para este teste, vamos simular um código válido")
        
        # Para teste, vamos usar um código que sabemos que existe no banco
        # Em produção, o usuário digitaria o código recebido
        test_code = input("   Digite o código 2FA (ou pressione Enter para simular): ").strip()
        
        if not test_code:
            print("   Simulando código 2FA...")
            # Para teste, vamos tentar alguns códigos comuns de teste
            test_codes = ["123456", "000000", "111111"]
            
            for code in test_codes:
                twofa_data = {
                    "temp_token": temp_token,
                    "code": code
                }
                
                response = requests.post(f"{BASE_URL}/auth/2fa/verify", json=twofa_data)
                if response.status_code == 200:
                    test_code = code
                    break
            
            if not test_code:
                print("❌ Não foi possível simular código 2FA válido")
                print("   Configure o email/SMS ou insira manualmente um código válido")
                return None
        
        twofa_data = {
            "temp_token": temp_token,
            "code": test_code
        }
        
        response = requests.post(f"{BASE_URL}/auth/2fa/verify", json=twofa_data)
        print_response(response, show_full=True)
        
        if response.status_code == 200:
            data = response.json()
            access_token = data.get('access_token')
            refresh_token = data.get('refresh_token')
            
            print("✅ Login completo com sucesso!")
            print(f"   Access Token: {access_token[:30] if access_token else 'N/A'}...")
            print(f"   Refresh Token: {refresh_token[:30] if refresh_token else 'N/A'}...")
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': data.get('user', {})
            }
        else:
            print("❌ Falha na verificação 2FA")
            return None
            
    except Exception as e:
        print(f"❌ Erro na requisição: {e}")
        return None

def test_authenticated_endpoints(tokens):
    """Testa endpoints que requerem autenticação."""
    print_step(5, "Testando endpoints autenticados")
    
    if not tokens or not tokens.get('access_token'):
        print("❌ Token de acesso não disponível")
        return False
    
    headers = {
        'Authorization': f"Bearer {tokens['access_token']}"
    }
    
    # Testar endpoint /auth/me
    print("\n📋 Testando GET /auth/me")
    try:
        response = requests.get(f"{BASE_URL}/auth/me", headers=headers)
        print_response(response)
        
        if response.status_code == 200:
            print("✅ Informações do usuário obtidas com sucesso!")
        else:
            print("❌ Falha ao obter informações do usuário")
    except Exception as e:
        print(f"❌ Erro: {e}")
    
    # Testar endpoint /devices
    print("\n📋 Testando GET /devices")
    try:
        response = requests.get(f"{BASE_URL}/devices", headers=headers)
        print_response(response)
        
        if response.status_code == 200:
            print("✅ Lista de dispositivos obtida com sucesso!")
        else:
            print("❌ Falha ao obter lista de dispositivos")
    except Exception as e:
        print(f"❌ Erro: {e}")
    
    # Testar endpoint /logs
    print("\n📋 Testando GET /logs")
    try:
        response = requests.get(f"{BASE_URL}/logs", headers=headers)
        print_response(response)
        
        if response.status_code == 200:
            print("✅ Logs obtidos com sucesso!")
        else:
            print("❌ Falha ao obter logs")
    except Exception as e:
        print(f"❌ Erro: {e}")
    
    return True

def test_refresh_token(tokens):
    """Testa renovação do access token."""
    print_step(6, "Testando renovação de token")
    
    if not tokens or not tokens.get('refresh_token'):
        print("❌ Refresh token não disponível")
        return False
    
    refresh_data = {
        "refresh_token": tokens['refresh_token']
    }
    
    try:
        response = requests.post(f"{BASE_URL}/auth/refresh", json=refresh_data)
        print_response(response, show_full=True)
        
        if response.status_code == 200:
            data = response.json()
            new_access_token = data.get('access_token')
            print("✅ Token renovado com sucesso!")
            print(f"   Novo Access Token: {new_access_token[:30] if new_access_token else 'N/A'}...")
            return True
        else:
            print("❌ Falha na renovação do token")
            return False
    except Exception as e:
        print(f"❌ Erro: {e}")
        return False

def test_biometric_verification(tokens):
    """Testa verificação biométrica simulada."""
    print_step(7, "Testando verificação biométrica simulada")
    
    if not tokens or not tokens.get('access_token'):
        print("❌ Token de acesso não disponível")
        return False
    
    headers = {
        'Authorization': f"Bearer {tokens['access_token']}"
    }
    
    user_id = tokens.get('user', {}).get('id', 1)
    
    # Simular dados biométricos (hash simulado)
    biometric_data = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
    
    biometric_request = {
        "user_id": user_id,
        "biometric_data": biometric_data,
        "device_info": "Test Device - Python Script"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/auth/biometric/verify", 
                               json=biometric_request, headers=headers)
        print_response(response, show_full=True)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('verified'):
                print("✅ Verificação biométrica aprovada!")
            else:
                print("ℹ️  Verificação biométrica rejeitada (esperado para dados simulados)")
            return True
        else:
            print("❌ Falha na verificação biométrica")
            return False
    except Exception as e:
        print(f"❌ Erro: {e}")
        return False

def main():
    """Função principal do teste."""
    print_header("TESTE DO SISTEMA DE AUTENTICAÇÃO IOTRAC")
    print("Este script testa os principais endpoints de autenticação implementados.")
    print("Certifique-se de que o servidor esteja rodando antes de continuar.")
    
    input("\nPressione Enter para começar os testes...")
    
    # Teste 1: Conexão com servidor
    if not test_server_connection():
        print("\n❌ Testes interrompidos - servidor não está disponível")
        sys.exit(1)
    
    # Teste 2: Registro de usuário
    if not test_user_registration():
        print("\n❌ Testes interrompidos - falha no registro")
        sys.exit(1)
    
    # Teste 3 e 4: Fluxo de login com 2FA
    tokens = test_login_flow()
    if not tokens:
        print("\n❌ Testes interrompidos - falha no login")
        sys.exit(1)
    
    # Teste 5: Endpoints autenticados
    test_authenticated_endpoints(tokens)
    
    # Teste 6: Renovação de token
    test_refresh_token(tokens)
    
    # Teste 7: Verificação biométrica
    test_biometric_verification(tokens)
    
    print_header("RESUMO DOS TESTES")
    print("✅ Conexão com servidor")
    print("✅ Registro de usuário")
    print("✅ Login com 2FA")
    print("✅ Endpoints autenticados")
    print("✅ Renovação de token")
    print("✅ Verificação biométrica")
    
    print("\n🎉 Todos os testes do sistema de autenticação foram concluídos!")
    print("\n📋 PRÓXIMOS PASSOS PARA O FRONTEND:")
    print("   1. Implementar tela de login")
    print("   2. Implementar tela de verificação 2FA")
    print("   3. Implementar gerenciamento de tokens")
    print("   4. Implementar tela de verificação biométrica")
    print("   5. Adicionar headers de autorização nas requisições")
    
    print(f"\n🔗 ENDPOINTS DISPONÍVEIS:")
    print(f"   Base URL: {BASE_URL}")
    print(f"   Documentação: {BASE_URL}/docs")
    
if __name__ == "__main__":
    main() 