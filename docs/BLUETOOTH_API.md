# API Bluetooth - IOTRAC Backend

## Visão Geral

O IOTRAC agora suporta dispositivos Bluetooth além de WiFi, implementando a mesma camada de proteção e criptografia para garantir comunicações seguras. Esta documentação detalha todos os endpoints e funcionalidades específicas para Bluetooth.

## Funcionalidades Implementadas

### 🔍 Escaneamento de Dispositivos
- Descoberta automática de dispositivos Bluetooth disponíveis
- Configuração de timeout personalizável
- Informações detalhadas sobre cada dispositivo encontrado

### 🔗 Gerenciamento de Conexões
- Conexão/desconexão segura com dispositivos
- Monitoramento de status de conexão em tempo real
- Atualização automática do status no banco de dados

### 📝 Registro de Dispositivos
- Registro permanente de dispositivos Bluetooth
- Validação de endereços MAC
- Suporte a nomes personalizados de dispositivos

### 🛡️ Proteção e Segurança
- Criptografia AES + HMAC para comandos
- Proteção individual por dispositivo
- Logs detalhados de todas as operações

### 📡 Envio de Comandos
- Comandos específicos para dispositivos Bluetooth
- Verificação de status de conexão antes do envio
- Tratamento de erros robusto

## Endpoints Disponíveis

### 1. Escaneamento de Dispositivos

**POST** `/bluetooth/scan`

Escaneia dispositivos Bluetooth disponíveis no ambiente.

**Parâmetros de Entrada:**
```json
{
  "timeout": 10.0  // Opcional: tempo limite em segundos (1-60)
}
```

**Resposta de Sucesso:**
```json
{
  "success": true,
  "message": "5 dispositivos Bluetooth encontrados",
  "devices": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "name": "Smart Lamp Living Room",
      "rssi": -45,
      "discoverable": true,
      "scanned_at": "2024-01-15T10:30:00.000Z"
    }
  ],
  "scan_timeout": 10.0,
  "timestamp": "2024-01-15T10:30:10.000Z"
}
```

**Códigos de Status:**
- `200`: Escaneamento realizado com sucesso
- `503`: Bluetooth não disponível no sistema
- `500`: Erro interno no escaneamento

---

### 2. Conexão com Dispositivo

**POST** `/bluetooth/connect`

Conecta a um dispositivo Bluetooth específico.

**Parâmetros de Entrada:**
```json
{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "timeout": 10.0  // Opcional: tempo limite em segundos (5-30)
}
```

**Resposta de Sucesso:**
```json
{
  "success": true,
  "message": "Conectado com sucesso ao dispositivo AA:BB:CC:DD:EE:FF",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "timestamp": "2024-01-15T10:35:00.000Z"
}
```

**Códigos de Status:**
- `200`: Conexão estabelecida ou falha na conexão (verificar campo `success`)
- `503`: Bluetooth não disponível
- `500`: Erro interno na conexão

---

### 3. Desconexão de Dispositivo

**POST** `/bluetooth/disconnect/{mac_address}`

Desconecta de um dispositivo Bluetooth.

**Parâmetros de URL:**
- `mac_address`: Endereço MAC do dispositivo (formato: AA:BB:CC:DD:EE:FF)

**Resposta de Sucesso:**
```json
{
  "success": true,
  "message": "Desconectado com sucesso do dispositivo AA:BB:CC:DD:EE:FF",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "timestamp": "2024-01-15T10:40:00.000Z"
}
```

---

### 4. Registro de Dispositivo Bluetooth

**POST** `/bluetooth/device/register`

Registra um novo dispositivo Bluetooth no sistema.

**Parâmetros de Entrada:**
```json
{
  "device_type": "smart-lamp",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "device_name": "Lâmpada Sala"  // Opcional
}
```

**Tipos de Dispositivos Suportados:**
- `smart-lamp`: Lâmpadas inteligentes
- `smart-lock`: Fechaduras inteligentes
- `sensor`: Sensores diversos
- `speaker`: Alto-falantes
- `headphones`: Fones de ouvido
- `keyboard`: Teclados
- `mouse`: Mouses
- `smart-watch`: Relógios inteligentes
- `fitness-tracker`: Monitores de atividade física

**Resposta de Sucesso:**
```json
{
  "id": 123,
  "device_type": "smart-lamp",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "device_name": "Lâmpada Sala",
  "connection_type": "bluetooth",
  "registered_at": "2024-01-15T10:45:00.000Z",
  "protection_enabled": true,
  "is_connected": false
}
```

**Códigos de Status:**
- `200`: Dispositivo registrado com sucesso
- `400`: MAC address já registrado ou dados inválidos
- `500`: Erro interno

---

### 5. Listar Dispositivos Bluetooth

**GET** `/bluetooth/devices`

Lista todos os dispositivos Bluetooth registrados.

**Resposta de Sucesso:**
```json
[
  {
    "id": 123,
    "device_type": "smart-lamp",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "device_name": "Lâmpada Sala",
    "registered_at": "2024-01-15T10:45:00.000Z",
    "protection_enabled": true,
    "is_connected": true,
    "last_seen": "2024-01-15T11:00:00.000Z",
    "connection_type": "bluetooth"
  }
]
```

---

### 6. Listar Dispositivos Conectados

**GET** `/bluetooth/devices/connected`

Lista apenas os dispositivos Bluetooth atualmente conectados.

**Resposta:** Mesmo formato do endpoint anterior, mas apenas dispositivos com `is_connected: true`.

---

### 7. Enviar Comando Bluetooth

**POST** `/bluetooth/command`

Envia comando para um dispositivo Bluetooth registrado e conectado.

**Parâmetros de Entrada:**
```json
{
  "device_id": 123,
  "command": "turn_on"
}
```

**Comandos Suportados:**
- `turn_on` / `turn_off`: Ligar/desligar dispositivo
- `set_brightness`: Ajustar brilho (lâmpadas)
- `set_color`: Definir cor (lâmpadas RGB)
- `get_status`: Consultar status do dispositivo
- `play` / `pause`: Controle de reprodução (speakers/headphones)
- `volume_up` / `volume_down`: Controle de volume
- `next_track` / `previous_track`: Navegação de faixas
- `lock` / `unlock`: Controle de fechaduras
- `get_battery`: Consultar nível de bateria
- `sync_time`: Sincronizar horário
- `get_data`: Obter dados do sensor

**Resposta de Sucesso:**
```json
{
  "success": true,
  "message": "Comando 'turn_on' enviado via Bluetooth para smart-lamp com proteção ativa",
  "device_id": 123,
  "command": "turn_on",
  "timestamp": "2024-01-15T11:05:00.000Z",
  "protection_enabled": true
}
```

**Códigos de Status:**
- `200`: Comando processado (verificar campo `success`)
- `400`: Dispositivo não é Bluetooth ou não está conectado
- `404`: Dispositivo não encontrado
- `500`: Erro interno

## Integração com Frontend

### Fluxo Recomendado

1. **Descoberta de Dispositivos:**
   ```javascript
   // Escanear dispositivos disponíveis
   const scanResponse = await fetch('/bluetooth/scan', {
     method: 'POST',
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify({ timeout: 15.0 })
   });
   ```

2. **Conexão e Registro:**
   ```javascript
   // Conectar ao dispositivo
   await fetch('/bluetooth/connect', {
     method: 'POST',
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify({ 
       mac_address: 'AA:BB:CC:DD:EE:FF',
       timeout: 10.0 
     })
   });

   // Registrar dispositivo
   await fetch('/bluetooth/device/register', {
     method: 'POST',
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify({
       device_type: 'smart-lamp',
       mac_address: 'AA:BB:CC:DD:EE:FF',
       device_name: 'Lâmpada Quarto'
     })
   });
   ```

3. **Monitoramento e Controle:**
   ```javascript
   // Listar dispositivos conectados
   const devices = await fetch('/bluetooth/devices/connected');

   // Enviar comando
   await fetch('/bluetooth/command', {
     method: 'POST',
     headers: { 'Content-Type': 'application/json' },
     body: JSON.stringify({
       device_id: 123,
       command: 'turn_on'
     })
   });
   ```

### Estados de Dispositivos

Os dispositivos Bluetooth podem estar em diferentes estados:

- **Descoberto**: Encontrado no escaneamento, mas não registrado
- **Registrado**: Salvo no banco de dados, mas desconectado
- **Conectado**: Registrado e com conexão ativa
- **Protegido**: Com proteção criptográfica ativada

### Tratamento de Erros

**Bluetooth Indisponível (503):**
```javascript
if (response.status === 503) {
  alert('Bluetooth não está disponível neste sistema');
}
```

**Dispositivo Não Conectado (400):**
```javascript
if (response.status === 400 && response.detail.includes('não está conectado')) {
  // Tentar reconectar
  await connectDevice(macAddress);
}
```

## Segurança

### Proteção de Comandos

Quando a proteção está ativada para um dispositivo:
1. Comandos são criptografados com AES-256
2. Integridade verificada com HMAC-SHA256
3. Comandos não criptografados são bloqueados
4. Todas as tentativas são registradas nos logs

### Validações

- **Endereços MAC**: Validação de formato (XX:XX:XX:XX:XX:XX)
- **Tipos de Dispositivos**: Lista restrita de tipos suportados
- **Comandos**: Validação contra lista de comandos permitidos
- **Timeouts**: Limites mínimos e máximos para evitar abusos

## Logs e Monitoramento

Todas as operações Bluetooth são registradas:
- Tentativas de conexão/desconexão
- Comandos enviados (com status de sucesso/falha)
- Erros de comunicação
- Alterações de status de proteção

Os logs podem ser consultados através do endpoint `/logs` existente.

## Dependências

Para usar as funcionalidades Bluetooth, certifique-se de que:

1. **bleak >= 0.20.0** está instalado:
   ```bash
   pip install bleak>=0.20.0
   ```

2. **Bluetooth está habilitado** no sistema operacional

3. **Permissões adequadas** para acesso ao Bluetooth (especialmente no Linux)

## Limitações Conhecidas

- Suporte apenas para Bluetooth Low Energy (BLE) e alguns dispositivos Bluetooth clássicos
- Número limitado de conexões simultâneas (dependente do hardware)
- Alguns comandos podem variar entre fabricantes de dispositivos
- Requer proximidade física com os dispositivos (alcance típico: 10-30 metros)

## Próximos Passos

Esta implementação fornece uma base sólida para funcionalidades Bluetooth. Futuras melhorias podem incluir:

- Suporte a mais tipos de dispositivos
- Conexões automáticas para dispositivos conhecidos
- Notificações push para eventos de dispositivos
- Interface de configuração avançada de dispositivos
- Suporte a protocolos específicos de fabricantes 