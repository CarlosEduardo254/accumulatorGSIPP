# ESP32 Sensor - Código Arduino

Código para ESP32 enviar dados de sensor com verificação criptográfica via MembershipProof.

## 🚀 Quick Start

### Opção 1: PlatformIO (Recomendado)

```bash
# 1. Abrir projeto no VSCode
cd esp32_sensor
code .

# 2. Instalar dependências (PlatformIO faz automaticamente)
pio lib install

# 3. Compilar
pio run

# 4. Gravar código no ESP32
pio run --target upload

# 5. Monitor serial
pio device monitor
```

### Opção 2: Arduino IDE

1. Abra `esp32_sensor.ino` na Arduino IDE
2. Instale a biblioteca **TinyCBOR** (soburi/TinyCBOR):
   - Menu → Sketch → Include Library → Manage Libraries
   - Procure por "TinyCBOR"
   - Instale a versão do **soburi**
3. Selecione a placa: **ESP32 Dev Module**
4. Configure:
   - Upload Speed: 921600
   - Flash Size: 4MB
   - Partition Scheme: **Default 4MB with spiffs**
5. Upload do código

---

## ⚙️ Configuração

Edite as configurações no topo do arquivo `esp32_sensor.ino`:

```cpp
// WiFi
const char* WIFI_SSID = "SeuWiFi";
const char* WIFI_PASSWORD = "SuaSenha";

// Servidor
const char* SERVER_IP = "192.168.1.100";  // IP do controlador
const uint16_t SERVER_PORT = 4242;

// Sensor ID (DEVE corresponder ao usado no setup!)
const char* SENSOR_ID = "ESP-42";

// Intervalo de envio (ms)
const uint32_t SEND_INTERVAL_MS = 3000;  // 3 segundos
```

---

## 📝 Pré-requisitos

### 1. Gerar a MembershipProof

Antes de usar este código, você DEVE:

```bash
# 1. Gerar acumulador e provas
cd ../
cargo run --bin setup

# 2. Gravar a prova no ESP32
python upload_proof_to_esp.py --port COM3 --esp-id ESP-42
```

> ⚠️ **IMPORTANTE**: O `SENSOR_ID` no código DEVE ser o mesmo usado no `upload_proof_to_esp.py`!

### 2. Verificar SPIFFS

O arquivo `.proof` DEVE estar gravado no SPIFFS do ESP32 no caminho `/sensor.proof`.

Para verificar:
```cpp
// No Serial Monitor, você verá:
// ✅ Prova carregada: XXX bytes
```

---

## 🔍 Como Funciona

### Fluxo de Operação

```
1. ESP inicializa
   ├── Conecta WiFi
   ├── Monta SPIFFS
   └── Carrega .proof da flash

2. A cada 3 segundos:
   ├── Cria payload CBOR:
   │   ├── "1": ID do sensor
   │   ├── "2": Timestamp
   │   ├── "3": Contador
   │   └── "4": MembershipProof
   ├── Envia via UDP (porta 4242)
   └── Aguarda próximo ciclo
```

### Estrutura do Pacote CBOR

| Campo | Tipo | Descrição | Exemplo |
|-------|------|-----------|---------|
| `"1"` | String | ID do sensor | `"ESP-42"` |
| `"2"` | uint64 | Timestamp (ms desde boot) | `123456` |
| `"3"` | uint64 | Contador de pacotes | `42` |
| `"4"` | Bytes | MembershipProof (da flash) | `[0xA2, ...]` |

---

## 🖥️ Saída Serial Esperada

```
═══════════════════════════════════════════════
   ESP32 Sensor com Acumulador Criptográfico
═══════════════════════════════════════════════
   Sensor ID: ESP-42
═══════════════════════════════════════════════

💾 Montando sistema de arquivos SPIFFS...
✅ SPIFFS montado

📂 Carregando MembershipProof da flash...
   Tamanho do arquivo: 256 bytes
✅ Prova carregada: 256 bytes
   Primeiros bytes: A2 01 58 80 ...

📡 Conectando ao WiFi...
   SSID: NEIKLOTDRADE 42140
..........
✅ WiFi conectado!
   IP local: 192.168.137.123
   Servidor: 192.168.137.1:4242

═══════════════════════════════════════════════
✅ Inicialização completa!
═══════════════════════════════════════════════
   Enviando pacotes a cada 3 segundos
═══════════════════════════════════════════════

✅ [3012] Pacote enviado: 312 bytes | Reading: 1
✅ [6024] Pacote enviado: 312 bytes | Reading: 2
✅ [9036] Pacote enviado: 312 bytes | Reading: 3
```

---

## 🐛 Troubleshooting

### ❌ "Arquivo .proof não encontrado"

**Problema:** SPIFFS não foi gravado ou está vazio

**Solução:**
```bash
# Gravar a prova novamente
python ../upload_proof_to_esp.py --port COM3 --esp-id ESP-42
```

### ❌ "Falha ao montar SPIFFS"

**Problema:** Partição SPIFFS não está habilitada

**Solução (Arduino IDE):**
- Menu → Tools → Partition Scheme → **Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)**

**Solução (PlatformIO):**
- Já está configurado em `platformio.ini`

### ❌ "Erro ao enviar pacote"

**Problema:** Servidor não está acessível

**Verificar:**
1. IP do servidor está correto?
2. Servidor está rodando? (`cargo run --release`)
3. Firewall bloqueando porta 4242?
4. ESP e servidor na mesma rede?

### ❌ Compilação falha: "cbor.h not found"

**Problema:** Biblioteca TinyCBOR não instalada

**Solução (PlatformIO):**
```bash
pio lib install "intel/TinyCBOR@^0.6.0"
```

**Solução (Arduino IDE):**
- Instale **soburi/TinyCBOR** via Library Manager

---

## 📊 Memória Utilizada

Estimativa de uso para ESP32 (4MB Flash):

- **Código**: ~300 KB
- **Prova (.proof)**: ~256 bytes
- **SPIFFS**: 1.5 MB (partição)
- **RAM em runtime**: ~50 KB

✅ Muito espaço livre para adicionar sensores reais!

---

## 🔐 Segurança

- ✅ **Prova única**: Cada ESP tem sua própria MembershipProof
- ✅ **Imutável**: A prova é gravada uma vez e não muda
- ✅ **Verificável**: O controlador valida criptograficamente
- ✅ **Não forjável**: Sem a chave privada do acumulador

---

## 🎯 Próximos Passos

1. **Adicionar sensores reais**:
   ```cpp
   // Substituir o contador por leitura real
   float temperature = dht.readTemperature();
   cbor_encode_float(&mapEncoder, temperature);
   ```

2. **Suporte LoRa** (ao invés de WiFi):
   ```cpp
   // Trocar WiFiUdp por LoRa
   LoRa.beginPacket();
   LoRa.write(cborBuffer, cborLength);
   LoRa.endPacket();
   ```

3. **Deep Sleep** (economia de energia):
   ```cpp
   // Enviar pacote
   sendCBORPacket();

   // Dormir por 3 segundos
   esp_deep_sleep(3000000);  // 3s em microsegundos
   ```

---

## 📚 Referências

- [TinyCBOR Documentation](https://intel.github.io/tinycbor/)
- [ESP32 Arduino Core](https://github.com/espressif/arduino-esp32)
- [SPIFFS Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/spiffs.html)
