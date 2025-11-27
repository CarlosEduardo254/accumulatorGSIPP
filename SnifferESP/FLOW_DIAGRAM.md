# Fluxo Completo: ESP32 → Controlador

Diagrama visual do processo completo de configuração e operação do sistema.

---

## 1️⃣ FASE DE SETUP (Uma vez apenas)

```mermaid
sequenceDiagram
    participant Dev as Desenvolvedor (PC)
    participant Setup as cargo run --bin setup
    participant Files as Sistema de Arquivos
    participant Script as upload_proof_to_esp.py
    participant ESP as ESP32 (Flash)

    Dev->>Setup: 1. Executar setup
    Setup->>Setup: Gerar acumulador RSA
    Setup->>Setup: Adicionar ESPs ao acumulador
    Setup->>Files: 2. Salvar accumulator.dat
    Setup->>Files: 3. Salvar proofs/ESP_XX.proof

    Note over Dev,ESP: Gravar provas nos ESPs

    Dev->>Script: 4. python upload_proof_to_esp.py
    Script->>Files: 5. Ler ESP_XX.proof
    Script->>Script: 6. Criar imagem SPIFFS
    Script->>ESP: 7. Gravar via USB (esptool)
    ESP->>ESP: 8. Armazenar na flash

    Note over Dev,ESP: Setup completo!
```

---

## 2️⃣ FASE DE OPERAÇÃO (Contínuo)

```mermaid
sequenceDiagram
    participant ESP as ESP32
    participant Flash as SPIFFS (Flash)
    participant UDP as Rede WiFi/UDP
    participant Ctrl as Controlador (Raspberry/PC)
    participant Acc as Acumulador

    Note over ESP,Acc: Boot do ESP32

    ESP->>Flash: 1. Montar SPIFFS
    Flash-->>ESP: OK
    ESP->>Flash: 2. Ler /sensor.proof
    Flash-->>ESP: MembershipProof (256 bytes)
    ESP->>UDP: 3. Conectar WiFi

    Note over ESP,Acc: Loop contínuo (a cada 3s)

    loop A cada 3 segundos
        ESP->>ESP: 4. Ler sensor / incrementar contador
        ESP->>ESP: 5. Criar payload CBOR:<br/>{"1": "ESP-42"<br/>"2": timestamp<br/>"3": reading<br/>"4": proof_bytes}
        ESP->>UDP: 6. Enviar pacote UDP (porta 4242)
        UDP->>Ctrl: 7. Entregar pacote

        Ctrl->>Ctrl: 8. Deserializar CBOR
        Ctrl->>Ctrl: 9. Extrair MembershipProof
        Ctrl->>Acc: 10. verify_membership(id, proof)
        Acc->>Acc: 11. Verificar: witness^hash(id) == acc?

        alt Prova válida
            Acc-->>Ctrl: ✅ VÁLIDO
            Ctrl->>Ctrl: 12. Processar dados
            Note over Ctrl: ✓ [ESP-42] Reading: 42 @ 123456
        else Prova inválida
            Acc-->>Ctrl: ❌ INVÁLIDO
            Ctrl->>Ctrl: 12. Rejeitar
            Note over Ctrl: ✗ FRAUDE DETECTADA! Sensor: ESP-42
        end
    end
```

---

## 3️⃣ ESTRUTURA DE DADOS

### Acumulador (accumulator.dat)

```
┌─────────────────────────────────┐
│  Acumulador RSA (Rsa2048)       │
├─────────────────────────────────┤
│  value: RSA Element             │
│  (representa todos os ESPs)     │
│                                 │
│  ESP-01 ──┐                     │
│  ESP-02 ──┼─→ Acumulado em      │
│  ESP-42 ──┘   um único valor    │
└─────────────────────────────────┘
      ↓
Usado pelo Controlador para verificar
```

### MembershipProof (ESP_XX.proof)

```
┌─────────────────────────────────┐
│  MembershipProof para ESP-42    │
├─────────────────────────────────┤
│  witness: RSA Element           │
│  (prova que ESP-42 pertence)    │
│                                 │
│  poe: PoE                       │
│  (proof of exponentiation)      │
└─────────────────────────────────┘
      ↓
Gravado na flash do ESP-42
```

### Pacote CBOR (enviado pelo ESP)

```
┌─────────────────────────────────┐
│  Mapa CBOR (4 campos)           │
├─────────────────────────────────┤
│  "1": "ESP-42"          (String)│
│  "2": 123456            (u64)   │
│  "3": 42                (u64)   │
│  "4": [0xA2, 0x01...]   (Bytes) │
│       └─ MembershipProof        │
└─────────────────────────────────┘
      ↓
Enviado via UDP porta 4242
```

---

## 4️⃣ VERIFICAÇÃO CRIPTOGRÁFICA

```mermaid
graph TD
    A[Pacote CBOR recebido] --> B{Deserializar CBOR}
    B -->|Sucesso| C[Extrair campos 1,2,3,4]
    B -->|Falha| X1[❌ Rejeitar: CBOR inválido]

    C --> D{Deserializar MembershipProof}
    D -->|Sucesso| E[proof = witness + PoE]
    D -->|Falha| X2[❌ Rejeitar: Prova corrompida]

    E --> F[Calcular hash do ID]
    F --> G[Computar: witness^hash mod N]
    G --> H{Resultado == Acumulador?}

    H -->|Sim| V[✅ VÁLIDO: Sensor autenticado]
    H -->|Não| X3[❌ FRAUDE: Sensor não autorizado]

    V --> I[Processar dados do sensor]
    X1 --> J[Incrementar contador de invalidos]
    X2 --> J
    X3 --> J
```

**Equação matemática:**
```
witness^hash(id) ≡ accumulator (mod N)

Onde:
  - witness: Elemento da prova
  - hash(id): Hash criptográfico do ID do sensor
  - accumulator: Valor do acumulador com todos os ESPs
  - N: Módulo RSA (2048 bits)
```

---

## 5️⃣ CHECKLIST DE IMPLEMENTAÇÃO

### Setup Inicial
- [ ] 1. Definir lista de ESPs autorizados em `setup.rs`
- [ ] 2. Executar `cargo run --bin setup`
- [ ] 3. Verificar que `accumulator.dat` foi criado
- [ ] 4. Verificar que arquivos `proofs/*.proof` existem

### Configuração do ESP32
- [ ] 5. Conectar ESP32 via USB
- [ ] 6. Identificar porta COM (Device Manager no Windows)
- [ ] 7. Instalar dependências Python: `pip install esptool mkspiffs-prebuilt`
- [ ] 8. Executar script de upload: `python upload_proof_to_esp.py --port COMX --esp-id ESP-XX`
- [ ] 9. Verificar log: "✅ Prova gravada com sucesso"

### Programação do ESP32
- [ ] 10. Abrir `esp32_sensor/esp32_sensor.ino`
- [ ] 11. Instalar biblioteca TinyCBOR
- [ ] 12. Configurar WiFi, IP do servidor e SENSOR_ID
- [ ] 13. Compilar e fazer upload do código
- [ ] 14. Abrir Serial Monitor (115200 baud)
- [ ] 15. Verificar: "✅ Inicialização completa!"

### Execução do Controlador
- [ ] 16. Copiar `accumulator.dat` para pasta do controlador
- [ ] 17. Executar: `cargo run --release` (no SnifferESP)
- [ ] 18. Verificar: "✓ Acumulador carregado com sucesso"
- [ ] 19. Aguardar pacotes do ESP

### Validação
- [ ] 20. Verificar logs do ESP: "✅ Pacote enviado"
- [ ] 21. Verificar logs do Controlador: "✓ [ESP-XX] Reading: ..."
- [ ] 22. Verificar estatísticas a cada 10 segundos
- [ ] 23. Testar com ESP não autorizado (deve falhar)

---

## 6️⃣ ARQUIVOS E LOCALIZAÇÃO

```
c:\GSIPP\ImplementacaoAC\
│
├── SnifferESP/
│   ├── src/
│   │   ├── main.rs                    # Controlador (recebe e verifica)
│   │   └── setup.rs                   # Gera acumulador e provas
│   │
│   ├── accumulator.dat                # ← Gerado pelo setup
│   ├── proofs/                        # ← Gerado pelo setup
│   │   ├── ESP_01.proof
│   │   ├── ESP_02.proof
│   │   └── ESP_42.proof
│   │
│   ├── upload_proof_to_esp.py         # Script para gravar no ESP
│   ├── ESP32_SETUP_GUIDE.md           # Guia completo
│   │
│   └── esp32_sensor/
│       ├── esp32_sensor.ino           # Código do ESP32
│       ├── platformio.ini             # Config PlatformIO
│       └── README.md                  # Instruções ESP32
│
└── interfaceCBOR/
    └── test.rs                        # Teste de integração CBOR
```

---

## 7️⃣ FLUXO DE DADOS DETALHADO

### No ESP32:

```cpp
// 1. Ler sensor
uint64_t reading = analogRead(A0);

// 2. Criar CBOR
CborEncoder encoder;
cbor_encoder_create_map(&encoder, &map, 4);
cbor_encode_text_stringz(&map, "1");
cbor_encode_text_stringz(&map, "ESP-42");
cbor_encode_text_stringz(&map, "2");
cbor_encode_uint(&map, timestamp);
cbor_encode_text_stringz(&map, "3");
cbor_encode_uint(&map, reading);
cbor_encode_text_stringz(&map, "4");
cbor_encode_byte_string(&map, proofBytes, proofSize);

// 3. Enviar UDP
udp.beginPacket(serverIP, 4242);
udp.write(cborBuffer, cborLength);
udp.endPacket();
```

### No Controlador (Rust):

```rust
// 1. Receber UDP
let (size, source) = socket.recv_from(&mut buf)?;

// 2. Deserializar CBOR → Payload
let payload: Payload = serde_cbor::from_slice(&buf[..size])?;

// 3. Deserializar MembershipProof
let proof: MembershipProof = serde_cbor::from_slice(&payload.membership_proof)?;

// 4. Verificar
if acc.verify_membership(&payload.id, &proof) {
    println!("✓ Sensor {} autenticado", payload.id);
} else {
    println!("✗ FRAUDE detectada!");
}
```

---

## 8️⃣ SEGURANÇA DO SISTEMA

```mermaid
graph LR
    A[ESP Autorizado] -->|Tem .proof válido| B[✅ Aceito]
    C[ESP Não Autorizado] -->|Sem .proof| D[❌ Rejeitado]
    E[ESP com .proof alterado] -->|Falha verificação| D
    F[ESP com ID errado] -->|witness não corresponde| D

    style B fill:#90EE90
    style D fill:#FFB6C6
```

### Proteções:

1. **Autenticação criptográfica**: Apenas ESPs com `.proof` válido são aceitos
2. **Integridade**: Qualquer alteração na prova é detectada
3. **Não-repúdio**: Cada ESP tem identificação única
4. **Eficiência**: Verificação rápida (~1-2 ms)

---

Este documento fornece uma visão completa do sistema! 🚀
