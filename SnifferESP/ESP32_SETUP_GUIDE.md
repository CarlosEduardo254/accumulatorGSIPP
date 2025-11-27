# Guia Completo: Configuração do ESP32

Este guia explica passo a passo como preparar e programar um ESP32 para enviar dados criptograficamente verificáveis para o acumulador.

---

## 📋 Visão Geral do Processo

```mermaid
graph LR
    A[1. Gerar Provas] --> B[2. Gravar no ESP]
    B --> C[3. Programar ESP]
    C --> D[4. ESP Envia CBOR]
    D --> E[5. Controlador Verifica]
```

---

## PASSO 1: Gerar o Acumulador e Provas

### 1.1. Executar o Setup

No diretório `SnifferESP`, execute:

```bash
cd c:\GSIPP\ImplementacaoAC\SnifferESP
cargo run --bin setup
```

### 1.2. O que acontece aqui?

Este comando faz 3 coisas importantes:

1. **Cria o acumulador** com todos os ESPs autorizados
2. **Gera as provas individuais** (MembershipProof) para cada ESP
3. **Salva os arquivos**:
   - `accumulator.dat` → Usado pelo controlador (Raspberry/PC)
   - `proofs/ESP_01.proof` → Prova para o ESP-01
   - `proofs/ESP_02.proof` → Prova para o ESP-02
   - `proofs/ESP_42.proof` → Prova para o ESP-42

### 1.3. Estrutura dos Arquivos

```
SnifferESP/
├── accumulator.dat         ← Usado pelo controlador
└── proofs/
    ├── ESP_01.proof        ← Para gravar no ESP-01
    ├── ESP_02.proof        ← Para gravar no ESP-02
    └── ESP_42.proof        ← Para gravar no ESP-42
```

> **Importante:** Cada arquivo `.proof` contém:
> - **Witness**: Prova criptográfica de que o ESP pertence ao acumulador
> - **PoE (Proof of Exponentiation)**: Prova adicional de validade
> - Formato: Serializado em CBOR (binário)

---

## PASSO 2: Gravar a Prova no ESP32

### 2.1. O que é SPIFFS?

SPIFFS é um filesystem (sistema de arquivos) que permite armazenar dados na memória flash do ESP32, como se fosse um "mini HD".

### 2.2. Preparar o ESP32

1. **Conecte o ESP32** ao PC via USB
2. **Identifique a porta COM** (ex: `COM3`, `COM4` no Windows)

### 2.3. Gravar o arquivo `.proof` usando o script Python

Execute o script de upload:

```bash
python upload_proof_to_esp.py --port COM3 --esp-id ESP-42
```

**Parâmetros:**
- `--port`: Porta serial do ESP (ex: `COM3`)
- `--esp-id`: ID do ESP (ex: `ESP-42`)

### 2.4. O que o script faz?

1. Lê o arquivo `proofs/ESP_XX.proof`
2. Cria uma imagem SPIFFS com o arquivo
3. Grava na partição flash do ESP32
4. Verifica se foi gravado corretamente

### 2.5. Alternativa: Upload Manual via PlatformIO

Se preferir usar PlatformIO:

```ini
# platformio.ini
[env:esp32]
platform = espressif32
board = esp32dev
framework = arduino
board_build.filesystem = spiffs
```

Depois:
```bash
# 1. Copiar o .proof para data/
mkdir -p data
cp proofs/ESP_42.proof data/sensor.proof

# 2. Upload do filesystem
pio run --target uploadfs
```

---

## PASSO 3: Programar o ESP32

### 3.1. Biblioteca CBOR

Usaremos **TinyCBOR** por ser:
- ✅ Otimizada para sistemas embarcados
- ✅ Baixo consumo de memória
- ✅ Não aloca memória em runtime
- ✅ Compatível com ESP32

### 3.2. Instalar TinyCBOR

**Via PlatformIO:**
```ini
# platformio.ini
lib_deps =
    soburi/TinyCBOR@^0.6.0
```

**Via Arduino IDE:**
1. Abra o Library Manager (Ctrl+Shift+I)
2. Procure por "TinyCBOR"
3. Instale a versão `soburi/TinyCBOR`

### 3.3. Código do ESP32

O código completo está em `esp32_sensor/esp32_sensor.ino`

**Estrutura do código:**

```cpp
setup() {
  1. Conectar WiFi
  2. Montar SPIFFS
  3. Carregar o arquivo .proof da flash
  4. Alocar buffer para o .proof
}

loop() {
  1. Criar payload CBOR com 4 campos:
     - "1": ID do sensor
     - "2": Timestamp
     - "3": Leitura do sensor
     - "4": MembershipProof (bytes da flash)

  2. Enviar via UDP para o servidor (porta 4242)

  3. Aguardar 3 segundos
}
```

---

## PASSO 4: Formato do Pacote CBOR

### 4.1. Estrutura do Payload

O ESP32 envia um **mapa CBOR** com 4 campos:

| Campo | Tipo | Descrição | Exemplo |
|-------|------|-----------|---------|
| `"1"` | String | ID do sensor | `"ESP-42"` |
| `"2"` | u64 | Timestamp Unix (ms) | `1700000000` |
| `"3"` | u64 | Valor lido do sensor | `42` |
| `"4"` | Bytes | MembershipProof serializada | `[0xA2, 0x01, ...]` |

### 4.2. Exemplo (Hex dump)

```
A4                      # Map com 4 campos
  61 31                 # Chave "1"
    66 455350-3432      # String "ESP-42"
  61 32                 # Chave "2"
    1B 00000186A0       # u64: 100000
  61 33                 # Chave "3"
    18 2A               # u64: 42
  61 34                 # Chave "4"
    58 80 A2...         # Bytes (proof)
```

---

## PASSO 5: Verificação no Controlador

### 5.1. O que o controlador faz?

Quando o controlador (Raspberry/PC) recebe o pacote:

1. **Deserializa o CBOR** → Extrai os 4 campos
2. **Deserializa a MembershipProof** (campo `"4"`)
3. **Verifica criptograficamente**:
   ```
   witness^hash(id) == accumulator?
   ```
4. **Resultado**:
   - ✅ **Válido**: Sensor autenticado
   - ❌ **Inválido**: Sensor não autorizado ou prova corrompida

### 5.2. Executar o Controlador

```bash
cd c:\GSIPP\ImplementacaoAC\SnifferESP
cargo run --release
```

---

## 🔐 Segurança

### Por que isso é seguro?

1. **MembershipProof é única**: Cada ESP tem sua própria prova
2. **Não pode ser forjada**: Sem a chave privada do acumulador
3. **Verificação rápida**: ~1-2 ms por pacote
4. **Imutável**: Uma vez gerada, a prova não muda

### O que impede fraudes?

- ❌ **ESP não autorizado**: Não tem `.proof` válido
- ❌ **Prova alterada**: Falha na verificação criptográfica
- ❌ **Replay attack**: Cada pacote é único (timestamp/contador)

---

## 📝 Resumo dos Arquivos

| Arquivo | Onde fica | Para que serve |
|---------|-----------|----------------|
| `setup.rs` | PC | Gera acumulador e provas |
| `accumulator.dat` | Controlador | Usado para verificar |
| `ESP_XX.proof` | Flash do ESP32 | Prova de autenticidade |
| `esp32_sensor.ino` | ESP32 | Envia dados + prova |
| `main.rs` (SnifferESP) | Controlador | Recebe e verifica |

---

## 🚀 Checklist Completo

- [ ] 1. Executar `cargo run --bin setup`
- [ ] 2. Verificar que `accumulator.dat` foi criado
- [ ] 3. Verificar que `proofs/ESP_XX.proof` existem
- [ ] 4. Conectar ESP32 via USB
- [ ] 5. Executar `python upload_proof_to_esp.py`
- [ ] 6. Instalar biblioteca TinyCBOR
- [ ] 7. Gravar código no ESP32
- [ ] 8. Executar controlador `cargo run --release`
- [ ] 9. Ligar ESP32 e verificar logs
- [ ] 10. Verificar pacotes válidos no controlador

---

## ❓ Troubleshooting

### Erro: "Arquivo .proof não encontrado"
**Causa:** SPIFFS não montou corretamente
**Solução:** Verificar se fez upload do filesystem

### Erro: "CBOR deserialization failed"
**Causa:** Formato CBOR incorreto
**Solução:** Verificar bibliotecas CBOR (ESP e Rust devem ser compatíveis)

### Erro: "✗ FRAUDE DETECTADA"
**Causa:** Prova inválida ou corrompida
**Solução:** Regerar a prova com `cargo run --bin setup`

---

## 📚 Referências

- [TinyCBOR Documentation](https://intel.github.io/tinycbor/)
- [SPIFFS Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/spiffs.html)
- [RFC 8949 - CBOR Specification](https://www.rfc-editor.org/rfc/rfc8949.html)
