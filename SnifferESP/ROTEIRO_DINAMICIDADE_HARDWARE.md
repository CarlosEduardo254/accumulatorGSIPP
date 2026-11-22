# Roteiro — Teste de dinamicidade no hardware real

**Montagem:** Raspberry Pi 3B+ como controlador (`udp_controller`, UDP 4242) + **1 ESP32 físico** + PC, todos na mesma rede Wi-Fi.

| Fase | Pi carregado com | ESP32 físico | PC (via Wi-Fi) | Esperado |
|---|---|---|---|---|
| 1 | A1 = {ESP-01, ESP-02, ESP-42} | ESP-42, firmware padrão | ESP-02, proof de A1 | tudo **ACEITO** |
| 2 | — (o TMC já gerou A2 offline) | — | — | — |
| 3 | A2 = {ESP-01, ESP-02} | ESP-42 **sem regravar** (revogado, assinatura legítima) | ESP-02 com proof de A1 (desatualizada) e de A2 (atualizada) | ESP-42 **REJEITADO V03**; ESP-02/A1 **REJEITADO V03**; ESP-02/A2 **ACEITO** |
| 4 | A3 = {ESP-01, ESP-02, ESP-99} | **regravado como ESP-99** (proof de A3) | ESP-02 com proof de A3 e de A2 | ESP-99 **ACEITO**; ESP-02/A3 **ACEITO**; ESP-02/A2 **REJEITADO V03** |

A chave pública do ESP-42 fica cadastrada no controlador **em todas as fases**.

---

## 0. Preparação (uma vez)

### No PC

1. Gere os artefatos do TMC. **Já foi feito.** Rodar de novo é seguro, porque as chaves são reaproveitadas:
   ```
   target/release/dynamic_tmc.exe
   ```
2. Monte o pacote do Pi com a cross-compilação no WSL. Ele fica em `dist/rpi-aarch64/`:
   ```
   wsl -d Debian -u root -- bash scripts/cross_build_rpi.sh
   ```
3. Copie o pacote para o Pi, trocando `<IP_DO_PI>`:
   ```
   scp -r dist/rpi-aarch64 raspberry@<IP_DO_PI>:~/dinamicidade
   ```

### No Raspberry Pi

```bash
cd ~/dinamicidade
./udp_controller --help      # confere que o binário roda
timedatectl                  # "System clock synchronized: yes" — a janela anti-replay é de 5 s
```

### No ESP32

- Em `SnifferESP/esp32_sensor/wifi_config.h`, `SERVER_IP` precisa ser o **IP do Pi**.
- Sem `sensor_identity.h`, o firmware é o ESP-42 com a proof de A1, igual ao original. Se o ESP32 já está gravado com esse firmware apontando para o Pi, não precisa regravar.
- Para garantir a identidade padrão:
  ```
  python SnifferESP/gen_sensor_identity.py --restore-default
  ```
  Depois faça o upload (`pio run --target upload` em `SnifferESP/esp32_sensor`, ou pelo Arduino IDE).

---

## 1. Fase 1 — A1

1. **No Pi:**
   ```bash
   ./rodar_fase.sh A1
   ```
2. **ESP32:** ligue-o (ou dê reset). Ele envia um pacote a cada 3 s. Deixe chegar pelo menos **20 pacotes**, cerca de 1 minuto.
3. **No PC**, em outro terminal. Este cliente acompanha as 3 fases e pede ENTER antes de cada uma:
   ```
   target/release/dynamic_e2e.exe --host <IP_DO_PI> --no-spawn --sensors ESP-02 --packets 20 --delay-ms 200
   ```
   Pressione ENTER na Fase 1, quando o Pi já estiver aguardando pacotes.
4. Quando o PC terminar de enviar e o ESP32 já tiver mandado uns 20 pacotes, encerre o controlador com **Ctrl+C no Pi**. O resumo fica gravado em `logs/controller_A1_*.log`.

## 2. Fase 3 — A2: revogação do ESP-42

1. **No Pi:**
   ```bash
   ./rodar_fase.sh A2
   ```
2. **ESP32:** **não regrave.** Ele continua enviando como ESP-42, com a chave legítima e a proof antiga.
3. **No PC:** pressione ENTER no cliente para a Fase 3. Ele envia o ESP-02 com a proof de A1 e depois com a de A2.
4. Aguarde ~20 pacotes do ESP32 e encerre com **Ctrl+C no Pi**.

Esperado no log: os pacotes do ESP-42 mostram `Verificação 02: Assinatura RSA-2048 VÁLIDA` seguida de `REJEITADO (V03 Aritmética — Prova Inválida)`.

## 3. Fase 4 — A3: adição do ESP-99

1. **No PC, regrave o ESP32 como ESP-99:**
   ```
   python SnifferESP/gen_sensor_identity.py --sensor ESP-99 --acc A3
   cd SnifferESP/esp32_sensor && pio run --target upload     (ou upload pelo Arduino IDE)
   ```
   No monitor serial deve aparecer `Sensor ID: ESP-99` e `Proof: 551 bytes`.
2. **No Pi:**
   ```bash
   ./rodar_fase.sh A3
   ```
3. **No PC:** pressione ENTER no cliente para a Fase 4. Ele envia o ESP-02 com a proof de A3 e com a de A2.
4. Aguarde ~20 pacotes do ESP32 e encerre com **Ctrl+C no Pi**.

*Controle opcional:* restaure o ESP-42 (`--restore-default` + upload), rode `./rodar_fase.sh A3` de novo e confira que o revogado continua barrado na V03.

## 4. Parte A no Pi (benchmark)

```bash
./rodar_bench.sh                    # completo
./rodar_bench.sh --heavy-reps 3     # mais rápido (menos repetições nas operações O(N))
```

O Pi 3B+ é bem mais lento que o PC, então o completo pode levar dezenas de minutos.

## 5. Resultados

**No Pi:**
```bash
python3 analisar_log.py --json logs/resumo_hardware.json logs/controller_*.log
```

**No PC**, traga tudo para o repositório:
```
scp -r raspberry@<IP_DO_PI>:~/dinamicidade/logs logs_dinamicidade/rpi
```
