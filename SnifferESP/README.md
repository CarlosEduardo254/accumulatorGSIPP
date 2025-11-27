# Controlador de Sensores IoT

Sistema de verificação criptográfica para sensores IoT usando acumuladores RSA.

## Arquitetura

```
ESP (Sensor) --[CBOR via LoRa/WiFi]--> Raspberry (Controlador)
                                            |
                                       Verifica MembershipProof
                                            |
                                    ✓ Válido / ✗ Fraude
```

## Como Usar

### 1. Setup Inicial (gerar acumulador e provas)

Execute o script de setup para gerar o acumulador e as provas de cada ESP:

```bash
cd SnifferESP
cargo run --bin setup
```

Isso criará:
- `accumulator.dat` - Acumulador serializado com todos os ESPs autorizados
- `proofs/ESP_XX.proof` - MembershipProof para cada ESP

**Importante:** Grave o arquivo `.proof` correspondente na flash de cada ESP via USB.

### 2. Compilar o Controlador

```bash
cd SnifferESP
cargo build --release
```

### 3. Executar o Controlador

```bash
# Certifique-se que accumulator.dat está na mesma pasta
./target/release/sniffer-controller
```

## Formato do Pacote CBOR

```
{
  "1": "ESP-42",              // ID do sensor (String)
  "2": 1690000000,            // Timestamp (u64)
  "3": 12,                    // Reading/contador (u64)
  "4": [...MembershipProof]   // Prova criptográfica (bytes)
}
```

## Monitoramento

O controlador exibe estatísticas a cada 10 segundos:

```
═════════════════════════════════════════════════
     Controlador de Sensores - Estatísticas
═════════════════════════════════════════════════
Uptime: 0h 5m 30s
Pacotes recebidos: 150
  ✓ Válidos:   149 (99%)
  ✗ Inválidos: 1 (1%)

Desempenho:
  Tempo médio de verificação: 1234 μs (1.23 ms)
  Throughput: 0.45 pkt/s
  Uso de RAM: 45 MB
  CPU: 8.5%
═════════════════════════════════════════════════
```

## Configuração

- **Porta UDP**: 4242 (definida em `src/main.rs`)
- **Intervalo de estatísticas**: 10 segundos
- **Tamanho máximo de pacote**: 512 bytes

## Segurança

- ✅ Verificação criptográfica via MembershipProof (witness + PoE)
- ✅ Proteção contra sensores não autorizados
- ✅ Detecção de tentativas de fraude
- ✅ Processamento em threads separadas (não bloqueia)

## Dependências

- `accumulator` - Biblioteca local do acumulador RSA
- `serde_cbor` - Deserialização CBOR
- `sysinfo` - Métricas de sistema (RAM/CPU)
