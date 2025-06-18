# IoT Security Module

Este módulo fornece funções e classes para segurança em aplicações IoT, incluindo:
- Criptografia e autenticação de pacotes com AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
- Geração e verificação de tokens JWT para autenticação
- Geração e verificação de assinaturas HMAC-SHA256 para comandos

## Principais Classes e Funções

- **AESCipher**: Criptografa e autentica dados usando AES-256-CBC e HMAC-SHA256. Permite especificar o comprimento da chave HMAC e garante integridade dos dados (Encrypt-then-MAC).
- **JWTAuth**: Gera e verifica tokens JWT para autenticação, usando segredo seguro de variável de ambiente.
- **generate_hmac_key(length=32)**: Gera uma chave HMAC aleatória de comprimento seguro (NUNCA use chaves previsíveis!).
- **generate_hmac(key, message)**: Gera uma assinatura HMAC-SHA256 para uma mensagem.
- **verify_hmac(key, message, signature_hex)**: Verifica a assinatura HMAC-SHA256 de uma mensagem.
- **get_env_var(name)**: Obtém uma variável de ambiente, lançando exceção se não definida.
- **setup_logging(level, log_file)**: Configura o sistema de logging do Python para o módulo.

## Instalação

Requer as bibliotecas:
- cryptography
- pyjwt

Instale com:
```
pip install cryptography pyjwt
```

## Configuração de Logging

Você pode configurar o logging para diferentes níveis e/ou para um arquivo:
```python
from iot_security import setup_logging
setup_logging(level=logging.DEBUG, log_file="iot_security.log")
```

## Variáveis de Ambiente e Exemplos de Chaves

**Nunca armazene segredos (chaves, senhas) no código-fonte!**

O módulo espera que as chaves estejam em variáveis de ambiente:
- `AES_KEY`: Chave AES de 32 bytes (256 bits), codificada em UTF-8 ou base64.
  - Exemplo (32 bytes em UTF-8): `b'0123456789abcdef0123456789abcdef'`
  - Exemplo (base64): `'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY='`
- `HMAC_KEY`: Chave HMAC de pelo menos 16 bytes, recomendável 32 bytes, codificada em UTF-8 ou base64.
  - Exemplo (32 bytes em UTF-8): `b'supersecretkeyforhmac1234567890!!'`
  - Exemplo (base64): `'c3VwZXJzZWNyZXRrZXlmb3JobWFjMTIzNDU2Nzg5MCEh'`
- `JWT_SECRET`: Segredo para assinatura de tokens JWT (string forte, pelo menos 16 caracteres).
  - Exemplo: `'minha_senha_super_secreta_123'`

> **Importante:** Sempre gere suas chaves com um gerador criptograficamente seguro, como `os.urandom` ou ferramentas de gerenciamento de segredos. **NUNCA use exemplos, palavras do dicionário ou padrões previsíveis!**

Exemplo de definição no Linux/Mac:
```
export AES_KEY="0123456789abcdef0123456789abcdef"
export HMAC_KEY="supersecretkeyforhmac1234567890!!"
export JWT_SECRET="minha_senha_super_secreta_123"
```
No Windows (cmd):
```
set AES_KEY=0123456789abcdef0123456789abcdef
set HMAC_KEY=supersecretkeyforhmac1234567890!!
set JWT_SECRET=minha_senha_super_secreta_123
```

## Exemplo de Uso Básico

```python
from iot_security import setup_logging, get_env_var, AESCipher, JWTAuth, generate_hmac, verify_hmac
setup_logging(level=logging.INFO)

# Carregar chaves
aes_key = get_env_var('AES_KEY').encode('utf-8')
hmac_key = get_env_var('HMAC_KEY').encode('utf-8')

# Criptografia e autenticação
cipher = AESCipher(aes_key, hmac_key)
mensagem = b"Mensagem IoT confidencial"
iv, ct, mac = cipher.encrypt(mensagem)
plaintext = cipher.decrypt(iv, ct, mac)

# JWT
token = JWTAuth().generate_token({"device_id": 123})
payload = JWTAuth().verify_token(token)

# HMAC simples
sig = generate_hmac(hmac_key, b"comando importante")
valid = verify_hmac(hmac_key, b"comando importante", sig)
```

## Exemplos Avançados e Casos de Uso

### 1. Comunicação Segura entre Dispositivos IoT
```python
# Dispositivo A: envia comando criptografado e autenticado
iv, ciphertext, mac = cipher.encrypt(b"ligar_motor")
# Envia (iv, ciphertext, mac) para o Dispositivo B

# Dispositivo B: recebe e valida
try:
    comando = cipher.decrypt(iv, ciphertext, mac)
    # Executa comando se válido
except Exception as e:
    # Loga tentativa de manipulação ou erro
    logger.warning(f"Falha na validação do comando: {e}")
```

### 2. Autenticação de API com JWT
```python
# Backend gera token JWT para dispositivo autenticado
jwt_auth = JWTAuth()
token = jwt_auth.generate_token({"device_id": "abc123", "role": "sensor"})

# Dispositivo envia token em cada requisição
# Backend valida token antes de processar
try:
    claims = jwt_auth.verify_token(token)
    # Permite acesso se claims válidas
except Exception:
    # Rejeita requisição
    pass
```

### 3. Assinatura e Verificação de Comandos
```python
# Central envia comando assinado
cmd = b"resetar"
sig = generate_hmac(hmac_key, cmd)
# Dispositivo verifica assinatura antes de executar
if verify_hmac(hmac_key, cmd, sig):
    # Executa comando
    pass
else:
    # Rejeita comando
    pass
```

## Testes Unitários e Integração

O módulo inclui testes unitários para todas as funções e classes. Para rodar os testes, altere o bloco final do arquivo para:
```python
if __name__ == "__test__":
    # ...
```
E execute:
```
python iot_security.py
```

> **Recomendação:** Implemente também **testes de integração** para garantir que diferentes partes do sistema (criptografia, autenticação, comunicação entre dispositivos) funcionam corretamente em conjunto no seu ambiente real.

## Práticas Recomendadas de Segurança

- **Gere chaves de forma segura**: Use `os.urandom`, ferramentas de gerenciamento de segredos ou bibliotecas especializadas. Nunca use exemplos ou padrões previsíveis.
- **Rotacione chaves periodicamente**: Troque as chaves de criptografia e HMAC em intervalos regulares ou após suspeita de comprometimento.
- **Valide todos os dados recebidos**: Sempre verifique a integridade e autenticidade dos dados antes de processá-los.
- **Restrinja acesso às chaves**: Armazene chaves em variáveis de ambiente protegidas ou cofres de segredos.
- **Nunca exponha chaves ou payloads sensíveis em logs ou prints.**
- **Monitore e trate exceções**: Implemente logs e alertas para tentativas de uso inválido ou falhas de autenticação.

## Como Contribuir

Contribuições são bem-vindas! Para contribuir:
- Abra um *issue* descrevendo o problema ou sugestão.
- Faça um *fork* do repositório e crie uma branch para sua feature/correção.
- Envie um *pull request* detalhando as mudanças e o motivo.
- Certifique-se de que todos os testes unitários passam antes de enviar o PR.
- Siga o padrão de código PEP8 e mantenha docstrings claras.

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.

## Referências
- [Documentação oficial do PyJWT](https://pyjwt.readthedocs.io/en/stable/)
- [Documentação oficial do cryptography](https://cryptography.io/en/latest/)
- [OWASP: Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) 
