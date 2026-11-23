# Relatório Técnico — Dinamicidade do Acumulador Criptográfico RSA-2048 em Hardware Real

**Experimento:** adição de sensores (*join*), revogação (*delete*) e atualização de witnesses no acumulador RSA da biblioteca Cambrian modificada (`accumulatorGSIPP`), com verificação no controlador UDP (porta 4242) executando num **Raspberry Pi 3B+** e um **ESP32 físico** como sensor.
**Branch:** `experimento-dinamicidade` (sem commit, aguardando revisão)
**Data da execução em hardware:** 23/11/2026. Rodada anterior, só em PC (Celeron N3350, loopback): 20/11/2026.

---

## 0. Resumo executivo

| Pergunta | Resultado no hardware real (Raspberry Pi 3B+ + ESP32) |
|---|---|
| A verificação no controlador é O(1) em relação ao tamanho da rede? | **Sim.** A mediana de `verify_membership` no Pi foi **10,82 ms com N=10** e **11,59 ms com N=1000**, razão de **1,07×** para uma rede **100× maior**. No mesmo intervalo, o custo de construir o acumulador cresceu **112,5×**. O estado do controlador (acumulador) tem **531 B para qualquer N**. |
| Quanto custa um evento dinâmico isolado? | No Pi, nenhum custo unitário depende de N: `add` de 1 sensor ≈ **5,9 ms**, proof do novo sensor ≈ **14,5 ms**, `delete` ≈ **9,5 ms**, atualização de 1 witness ≈ **8 ms** (join) / **11 ms** (revogação). |
| E atualizar a rede inteira? | É **linear em N**, com R² > 0,999. No Pi: **8,2 s** (join) e **11,5 s** (revogação) para **N=1000**. É trabalho do **TMC, offline**; o ESP32 só troca a proof armazenada. |
| A revogação funciona de ponta a ponta no hardware? | **Sim.** **40/40 pacotes** do ESP32 com a identidade **revogada (ESP-42)**, com timestamp válido e **assinatura RSA legítima** (V01 e V02 aprovadas), foram **rejeitados na V03 aritmética**, com a chave pública dele **ainda cadastrada** no controlador. |
| A adição funciona de ponta a ponta no hardware? | **Sim.** O ESP32 regravado como **ESP-99**, um sensor novo incluído em A3, teve **30/30 pacotes aceitos**. |
| Witnesses desatualizadas são barradas? | **Sim, em 100% dos casos**, tanto após a revogação (40/40, proof de A1 contra A2) quanto após a adição (20/20, proof de A2 contra A3). Com a witness atualizada, a aceitação foi de 100% (20/20 em A2 e 20/20 em A3). |
| Algum pacote foi decidido pela camada errada? | **Não.** Nos **230 pacotes** das sessões válidas, **230 tiveram exatamente o desfecho esperado**. Não houve rejeição por V01, V01b, V02, V03 sintática ou C00, nem lacuna de sequência ou perda. |
| Quanto custa verificar um pacote no Pi? | De **13,3 a 14,0 ms** com a CPU em clock máximo e de **≈ 31 ms** (proof de 551 B) a **≈ 38–42 ms** (proof de 1064 B) com a CPU em clock reduzido. O Pi usa o governor `ondemand` (DVFS, seção 4.4). A RAM do processo ficou em **2,8 MB**. |

---

## 1. Objetivos e hipóteses

O experimento responde a três questões levantadas sobre o uso do acumulador RSA como camada de autorização do ITS:

1. **Escalabilidade:** a verificação no controlador e os dados trafegados não crescem com o número de sensores.
2. **Dinamicidade:** a biblioteca permite adicionar e revogar sensores, e atualizar as witnesses dos demais, com custo conhecido.
3. **Eficácia em campo:** a revogação e a adição se comportam como esperado num controlador real (Raspberry Pi) com um sensor real (ESP32) em rede sem fio.

Hipóteses testadas:

| # | Hipótese | Como é testada |
|---|---|---|
| H1 | `verify_membership` tem custo **O(1)** em N | Parte A: mediana da verificação para N = 10…1000 |
| H2 | Eventos isolados (add, delete, 1 witness, 1 proof) têm custo **independente de N**; atualizar a rede inteira é **O(N)** | Parte A: custos unitários e em lote para N = 10…1000 |
| H3 | Um sensor **revogado** é rejeitado **mesmo com assinatura válida e chave cadastrada**, e a rejeição ocorre **na V03** | Parte B, Fase 3, com o ESP32 físico |
| H4 | **Toda** mudança no acumulador (adição ou remoção) invalida as witnesses antigas, e a witness **atualizada** volta a ser aceita | Parte B, cenários F3-B/F3-C e F4-B/F4-C |
| H5 | Um sensor **adicionado** após o setup é aceito sem alterar os demais componentes | Parte B, Fase 4, com o ESP32 regravado como ESP-99 |

---

## 2. Metodologia

### 2.1 Montagem e ambiente

```
            Hotspot do celular ("POCO X7 Pro")                Rede cabeada do laboratório (10.5.18.0/24)
 ┌──────────────┐   Wi-Fi    ┌──────────────┐   NAT    ┌───────────────────────────────────────────┐
 │ ESP32 físico │ ─────────▶ │   Celular    │ ───────▶ │ Raspberry Pi 3B+  10.5.18.23  UDP :4242   │
 │ ESP-42/ESP-99│  10.143.x  │ 10.5.40.221  │          │  (udp_controller)                         │
 └──────────────┘            └──────────────┘          │                ▲                          │
                                                       │  Ethernet      │  ESP-02 simulado          │
                                                       │ PC i7-7700  10.5.18.62  (dynamic_e2e)      │
                                                       └───────────────────────────────────────────┘
```

| Papel | Equipamento | Detalhes |
|---|---|---|
| **Controlador** (verificador) | Raspberry Pi 3B+ | Cortex-A53, 4 núcleos, até 1,4 GHz (mínimo 600 MHz), 0,9 GiB de RAM, Debian 13 (aarch64), kernel 6.12.62+rpt-rpi-v8, glibc 2.41. Conectado **por cabo** à rede do laboratório. |
| **Sensor real** | ESP32 (Arduino IDE) | Firmware `SnifferESP/esp32_sensor`: NTP (`pool.ntp.org`), assinatura RSA-2048 (PKCS#1 v1.5 + SHA-256) e envio CBOR via UDP a cada ~3 s. Conectado por **Wi-Fi ao hotspot do celular**, que encaminha (NAT) para a rede cabeada. No controlador, a origem aparece como `10.5.40.221`. |
| **TMC + sensor simulado** | PC do laboratório | Intel Core i7-7700 @ 3,6 GHz (4 núcleos / 8 threads), 15 GiB de RAM, Ubuntu 22.04, rustc 1.99.1. Gera os artefatos do TMC e simula o **ESP-02** (`dynamic_e2e`) por **Ethernet**. |
| **Referência anterior** | PC Windows | Intel Celeron N3350 @ 1,1 GHz (2 núcleos), Windows 10, rodada de 20/11/2026 (Parte A + Parte B em loopback). |

**Cross-compilação.** O Pi não compila o projeto. Os binários aarch64 foram gerados no PC com `cross` 0.2.5, usando a imagem Docker `ghcr.io/cross-rs/aarch64-unknown-linux-gnu:main` (Ubuntu 24.04, gcc 13.3, `Cross.toml` da raiz) e o perfil `release`. O empacotamento seguiu o mesmo procedimento do `scripts/cross_build_rpi.sh`: strip dos binários, cópia dos scripts e dos artefatos **públicos** do TMC (acumuladores e chaves públicas) e geração do `CHECKSUMS.md5`. Os binários exigem no máximo **GLIBC_2.39**, compatível com a 2.41 do Pi. No Pi, `md5sum -c` conferiu **15/15 arquivos**. O pacote anterior que estava no Pi (gerado com outras chaves) foi renomeado para `~/tcc/rpi-aarch64.antigo-20261123-1417`, e os testes usaram apenas o pacote novo.

**Sincronização de tempo.** A V01 aceita uma diferença de no máximo **5 s** entre o timestamp do pacote e o relógio do controlador. O Pi estava sincronizado (`System clock synchronized: yes`), e o ESP32 sincronizou via NTP pelo hotspot.

### 2.2 Como a biblioteca Cambrian executa as operações dinâmicas

O experimento usa **somente a API pública** de `src/accumulator.rs`:

| Operação | Método público | Mecanismo |
|---|---|---|
| Acumulação | `Accumulator::empty().add(&ids)` | A = g^(∏ H(idᵢ)) mod n, com g = 2 e H = `hash_to_prime` (primo de 256 bits via Blake2b + BPSW) |
| Adição (join) | `acc.add(&[novo])` | A' = A^H(novo). A witness do novo sensor é o A anterior. |
| **Deleção (revogação)** | `acc.delete(&[(id, witness)])` | **Sem trapdoor.** O módulo é o RSA-2048 do desafio RSA, cuja fatoração é desconhecida. A biblioteca **exige a witness do elemento removido**, confere w^H(id) = A e aplica o *Shamir trick*. Na remoção de um único elemento, **o novo acumulador é a própria witness do removido** (A' = w_id). |
| Atualização de witness | `acc_novo.update_membership_witness(w, [id], adições, deleções)` | LLX 2007, Seção 4.2. Adição: w' = w^H(x). Deleção: w' = w^b · A'^a, com a·H(id) + b·H(x) = 1 (Euclides estendido). |
| Nova proof | `acc.prove_membership(&[(id, w)])` | `MembershipProof` = witness + PoE de Wesolowski para o acumulador atual |
| Verificação | `acc.verify_membership(&id, &proof)` | Verifica a PoE: Q^ℓ · w^(H(id) mod ℓ) = A |
| Recálculo do zero | `Witness(empty).compute_individual_witnesses(&ids)` | *RootFactor*, O(N log N) |

Isso tem três consequências práticas:

1. Para revogar, o TMC precisa da witness do sensor revogado. Sem ela, só resta reconstruir A a partir do conjunto remanescente.
2. Não há segredo (trapdoor) a proteger no TMC.
3. A atualização de witness usa apenas dados públicos: o novo A e o ID adicionado ou removido.

### 2.3 Parte A — Benchmark das operações dinâmicas (`dynamic_bench`)

**Objetivo:** medir, isolado da rede, o custo de cada operação do acumulador em função do tamanho da rede N, para testar H1 e H2. O benchmark rodou **no próprio Raspberry Pi** (`./rodar_bench.sh`) e, para comparação, **no i7-7700** com parâmetros idênticos.

**Procedimento:** para cada N ∈ {10, 50, 100, 500, 1000}, com sensores `ESP-0001…ESP-N`:

| Grupo | Métrica | O que representa | Repetições |
|---|---|---|---|
| Setup | `add(N)` | Construir o acumulador inicial com N sensores | 5 |
| Setup | N witnesses (RootFactor) | Calcular do zero a witness de todos os sensores | 5 |
| Join | `add` de 1 sensor | TMC incorpora um sensor novo | 20 |
| Join | proof do novo sensor | TMC gera a `MembershipProof` que vai para o novo ESP32 | 20 |
| Join | update de 1 witness | TMC atualiza a witness de **um** sensor existente | 20 |
| Join | nova PoE de 1 sensor | TMC gera a nova proof desse sensor | 20 |
| Join | update em lote (N) | TMC atualiza as witnesses de **todos** os sensores | 5 |
| Revogação | `delete` de 1 sensor | TMC remove um sensor (Shamir trick) | 20 |
| Revogação | update de 1 witness / nova PoE | Igual ao join, para a remoção | 20 |
| Revogação | update em lote (N−1) | TMC atualiza todos os remanescentes | 5 |
| Verificação | `verify_membership` | Custo da V03 no controlador | 200 |
| Verificação | decode CBOR + verify | V03 incluindo a desserialização da proof | 200 |
| Primitivas | `hash_to_prime`, g^p mod n | Blocos básicos, independentes de N | 200 |

Em cada repetição, um sensor diferente é adicionado ou revogado. **Fora da região cronometrada**, o benchmark confere matematicamente cada resultado: novo acumulador correto, proofs atualizadas aceitas, proof do revogado rejeitada, witness antiga rejeitada e `delete` igual à reconstrução do zero. Os tempos são de relógio de parede (`Instant`), num único thread, em build `release`.

**Estatística:** média, mediana, desvio-padrão, p95 (*nearest-rank*) e máximo. A **mediana** é o estimador principal porque é robusta a picos do sistema operacional. Nas operações pesadas (n = 5), o p95 coincide com o máximo.

### 2.4 Parte B — Teste fim-a-fim no hardware (TMC + Pi + ESP32)

**Objetivo:** demonstrar, com o controlador real no Pi e um sensor real, que as mudanças de estado do acumulador produzidas pelo TMC têm o efeito esperado sobre a aceitação dos pacotes (H3, H4, H5), e identificar em **qual camada** cada pacote é barrado.

**Etapa 0 — TMC offline (`dynamic_tmc`, no PC).** Gera os três estados do acumulador usando apenas a API dinâmica:

| Estado | Conjunto | Como é obtido |
|---|---|---|
| A1 | {ESP-01, ESP-02, ESP-42} | `add` (setup) |
| A2 | {ESP-01, ESP-02} | `A1.delete([(ESP-42, w42)])`: revogação do ESP-42 |
| A3 | {ESP-01, ESP-02, ESP-99} | `A2.add([ESP-99])`: adição do ESP-99 |

O TMC também gera as proofs (ESP-02 para A1, A2 e A3; ESP-99 para A3) e pares RSA-2048 **de teste** para ESP-02 e ESP-99. O ESP-42 usa a chave do firmware. **Checagens: 11/11 OK.** A1 é byte a byte idêntico ao `SnifferESP/accumulator.dat`, e a proof do ESP-42 em A1 é idêntica à embutida no firmware. Por isso o ESP32 com o firmware padrão funciona sem regravação na Fase 1. A2 e A3 coincidem com a reconstrução do zero.

**Etapas no hardware.** Em cada fase, o controlador é iniciado no Pi com `./rodar_fase.sh A{k}`, que carrega `accumulator_A{k}.dat` e as chaves públicas de ESP-02 e ESP-99. A **chave do ESP-42 permanece cadastrada em todas as fases**. Assim, a única diferença entre as fases é o valor do acumulador (531 B). O ESP-02 simulado é enviado pelo PC com `dynamic_e2e --no-spawn --sensors ESP-02 --packets 20 --delay-ms 200`.

| Fase | Controlador | ESP32 físico | ESP-02 (PC) | Objetivo de cada cenário |
|---|---|---|---|---|
| **1** | A1 | **ESP-42**, firmware padrão | **F1-B:** proof de A1 | Linha de base: com o estado inicial, os dois sensores legítimos são aceitos. F1-B também prova que a proof de A1 do ESP-02, reusada em F3-B, era válida. |
| **2** | — | — | — | Etapa **offline**: o TMC revoga o ESP-42 e atualiza a witness do ESP-02 (já feita na Etapa 0). |
| **3** | A2 | **ESP-42 sem regravar**: revogado, mas com chave e assinatura legítimas | **F3-B:** proof de A1 (desatualizada); **F3-C:** proof de A2 (atualizada) | ESP-42: **H3**, o revogado é barrado na V03 mesmo passando V01 e V02. F3-B/F3-C: **H4**, a revogação de outro sensor invalida a witness antiga do ESP-02, e a atualizada é aceita. |
| **4** | A3 | **Regravado como ESP-99** (`gen_sensor_identity.py --sensor ESP-99 --acc A3`) | **F4-B:** proof de A3; **F4-C:** proof de A2 (controle) | ESP-99: **H5**, um sensor novo entra só com a nova proof. F4-B/F4-C: **H4** também na **adição**. |

**Medição e critério.** A **fonte da verdade** é o stdout do `udp_controller` no Pi (`logs/controller_A{k}_*.log`), e não o cliente. Para cada pacote, o controlador registra a origem, o ID, o timestamp, o Δ do timestamp, o resultado de V01/V02, o **status final com a camada de bloqueio**, o tempo de verificação e a RAM do processo. O **tempo de verificação** vai do `recv_from` até a decisão e inclui o decode CBOR externo, V01, V01b, V02 (RSA-2048) e V03 completa (sintática + aritmética). Só a impressão do cabeçalho do pacote fica de fora. O critério de sucesso é que **cada pacote** tenha exatamente o desfecho e a camada esperados para o seu cenário.

**Tratamento dos dados.**
- `scripts/rpi/analisar_log.py` resume cada log por sensor e por camada.
- `scripts/rpi/analisar_por_cenario.py`, escrito para esta análise, separa os pacotes do ESP-02 em **blocos consecutivos de 20**, na ordem de envio do cliente, para atribuí-los a cada cenário. Ele também calcula Δ de timestamp, lacunas na sequência `Reading`, tamanhos, origem e os dois regimes de tempo (seção 4.4).

### 2.5 Parte B local — controle no PC (loopback)

**Objetivo:** controle de reprodutibilidade. O mesmo `dynamic_e2e`, sem `--no-spawn`, sobe o controlador localmente no i7-7700 e envia **50 pacotes por cenário via 127.0.0.1**. Isso inclui os cenários do ESP-42/ESP-99 simulados pelo próprio cliente (F1-A, F3-A, F4-A) e o controle **F4-D** (ESP-42 revogado contra A3). Assim, a lógica é validada sem rede e sem o ESP32, e os tempos podem ser comparados com o Pi.

---

## 3. Resultados

### 3.1 Parte B no hardware — desfecho por cenário

Sessões válidas: `controller_A1_20261123_143235.log`, `controller_A2_20261123_155532.log` e `controller_A3_20261123_160544.log`.

| Fase | Acc | Cenário | Sensor (origem) | Proof | Pacotes | Aceitos | Rejeitados | Camada de bloqueio | V02 (assinatura) | t̄ / mediana (ms) | Esperado |
|---|---|---|---|---|---:|---:|---:|---|:---:|---:|:---:|
| 1 | A1 | legítimo | **ESP-42** (ESP32, Wi-Fi) | A1, 1064 B | 40 | **40 (100%)** | 0 | — | 40/40 válida | 36,74 / 38,12 | ✅ |
| 1 | A1 | F1-B: legítimo | ESP-02 (PC, cabo) | A1, 551 B | 20 | **20 (100%)** | 0 | — | 20/20 | 28,45 / 29,87 | ✅ |
| 3 | A2 | **revogado**, assinatura legítima | **ESP-42** (ESP32, Wi-Fi) | A1, 1064 B | 40 | 0 | **40 (100%)** | **V03 aritmética** | **40/40 válida** | 38,64 / 41,59 | ✅ |
| 3 | A2 | F1-B\*: proof de A1 *(repetição)* | ESP-02 (PC) | A1, 551 B | 20 | 0 | **20 (100%)** | **V03 aritmética** | 20/20 | 29,03 / 30,42 | ✅ |
| 3 | A2 | F3-B: witness **desatualizada** | ESP-02 (PC) | A1, 551 B | 20 | 0 | **20 (100%)** | **V03 aritmética** | 20/20 | 28,95 / 30,69 | ✅ |
| 3 | A2 | F3-C: witness **atualizada** | ESP-02 (PC) | A2, 551 B | 20 | **20 (100%)** | 0 | — | 20/20 | 13,54 / 13,49 | ✅ |
| 4 | A3 | **novo sensor** | **ESP-99** (ESP32, Wi-Fi) | A3, 551 B | 30 | **30 (100%)** | 0 | — | 30/30 | 30,08 / 31,16 | ✅ |
| 4 | A3 | F4-B: witness atualizada | ESP-02 (PC) | A3, 550 B | 20 | **20 (100%)** | 0 | — | 20/20 | 19,87 / 13,31 | ✅ |
| 4 | A3 | F4-C: witness de A2 *(controle)* | ESP-02 (PC) | A2, 551 B | 20 | 0 | **20 (100%)** | **V03 aritmética** | 20/20 | 20,35 / 14,17 | ✅ |

\* **F1-B\*:** o cliente foi reiniciado entre as fases e reenviou a Fase 1 (proof de A1) com o controlador já em A2. Na prática, isso é uma **segunda amostra de F3-B**, e o desfecho foi o esperado (rejeição na V03). Na Fase 3, o ESP-02 tem 60 pacotes (40 rejeitados + 20 aceitos), e não 40.

**Resumo do controlador por fase (Pi):**

| Fase | Recebidos | Aceitos | V03 aritmética | V01 / V01b / V02 / V03 sint. / C00 | Lacunas de sequência | RAM do processo |
|---|---:|---:|---:|:---:|---:|---|
| 1 (A1) | 60 | 60 | 0 | 0 / 0 / 0 / 0 / 0 | 0 | 2,76–2,80 MB |
| 3 (A2) | 100 | 20 | 80 | 0 / 0 / 0 / 0 / 0 | 0 | 2,76–2,79 MB |
| 4 (A3) | 70 | 50 | 20 | 0 / 0 / 0 / 0 / 0 | 0 | 2,76–2,79 MB |
| **Total** | **230** | **130** | **100** | **0** | **0** | — |

**Rede e sincronização:**

| Origem | Pacotes | Δ timestamp (V01) | Tamanho UDP | Intervalo médio | Lacunas (`Reading`) |
|---|---:|---|---|---|---:|
| ESP32 via hotspot (10.5.40.221) | 110 (40 + 40 + 30) | 0–1 s | 1350–1351 B (ESP-42) · 837–838 B (ESP-99) | ≈ 3,2 s (40 pacotes em 127 s) | 0 |
| PC via Ethernet (10.5.18.62) | 120 | 0–1 s | 837–838 B | ≈ 0,2 s (rajadas de 20) | 0 |

**Sessões descartadas:** `controller_A1_20261123_142548.log` (0 pacotes) e `controller_A1_20261123_143204.log` (2 pacotes do ESP-42, ambos aceitos). As duas são do diagnóstico de conectividade. Na primeira tentativa, o hotspot do celular estava sem saída para a rede: o NTP do ESP32 falhou e os pacotes não chegavam ao Pi. As sessões estão em `rpi/`, mas ficaram fora das tabelas.

### 3.2 Parte B no hardware — tempo de verificação e regimes de clock

Os tempos do controlador no Pi formam **dois patamares bem separados**, e o patamar **não depende do desfecho** (aceito ou rejeitado):

| Tamanho da proof | Regime | Pacotes | Mediana (ms) | Desvio-padrão (ms) | Aceitos / rejeitados (mediana) |
|---|---|---:|---:|---:|---|
| 550–551 B (ESP-02, ESP-99) | **rápido** | 46 | **13,61** | 0,40 | 13,30 / 14,04 |
| 550–551 B | **lento** | 97 | **30,78** | 1,89 | 30,96 / 30,70 |
| 550–551 B | transição | 7 | — | — | — |
| 1064 B (ESP-42) | rápido | 1 | 17,97 | — | — / 17,97 |
| 1064 B | **lento** | 75 | **38,30** | 2,77 | 38,14 / 41,63 |
| 1064 B | transição | 4 | — | — | — |

A razão entre os patamares das proofs de 551 B é **2,26×**, próxima da razão **1400/600 = 2,33** entre o clock máximo e o mínimo do Cortex-A53 do Pi 3B+. A troca de patamar acontece **no meio das rajadas**: no F4-B, os 9 primeiros pacotes ficaram em ≈ 26–31 ms e os 11 seguintes em ≈ 13 ms; no F4-C, os 13 primeiros ficaram em ≈ 14 ms e os 7 seguintes em ≈ 33 ms. A discussão está na seção 4.4.

### 3.3 Parte B local (i7-7700, loopback) — controle

| Fase | Cenário | Sensor | Proof | Enviados | Aceitos | Rejeitados | Camada | t̄ / mediana (ms) | Resultado |
|---|---|---|---|---:|---:|---:|---|---:|:---:|
| 1 | F1-A: legítimo | ESP-42 | A1 (1064 B) | 50 | 50 | 0 | — | 5,59 / 6,09 | ✅ |
| 1 | F1-B: legítimo | ESP-02 | A1 (551 B) | 50 | 50 | 0 | — | 3,85 / 3,67 | ✅ |
| 3 | F3-A: revogado, assinatura legítima | ESP-42 | A1 (1064 B) | 50 | 0 | 50 | V03 aritmética | 6,60 / 6,73 | ✅ |
| 3 | F3-B: witness desatualizada | ESP-02 | A1 (551 B) | 50 | 0 | 50 | V03 aritmética | 4,36 / 4,73 | ✅ |
| 3 | F3-C: witness atualizada | ESP-02 | A2 (551 B) | 50 | 50 | 0 | — | 4,67 / 4,71 | ✅ |
| 4 | F4-A: novo sensor | ESP-99 | A3 (551 B) | 50 | 50 | 0 | — | 4,15 / 4,70 | ✅ |
| 4 | F4-B: witness atualizada | ESP-02 | A3 (550 B) | 50 | 50 | 0 | — | 4,63 / 4,58 | ✅ |
| 4 | F4-C: witness de A2 | ESP-02 | A2 (551 B) | 50 | 0 | 50 | V03 aritmética | 5,43 / 5,37 | ✅ |
| 4 | F4-D: revogado após o join | ESP-42 | A1 (1064 B) | 50 | 0 | 50 | V03 aritmética | 4,92 / 5,00 | ✅ |

**9/9 cenários, 450/450 pacotes com o desfecho esperado.** É o mesmo resultado da rodada anterior no Celeron. O F4-D, que no roteiro de hardware era um controle opcional, foi coberto aqui.

**TMC (i7-7700, uma execução):**
- **Fase 2:** `delete` do ESP-42 em 2,00 ms, atualização da witness do ESP-02 em 1,93 ms e nova PoE em 1,87 ms.
- **Fase 4:** `add` do ESP-99 em 0,72 ms, proof do ESP-99 em 1,44 ms, atualização da witness do ESP-02 em 0,76 ms e nova PoE em 1,39 ms.

### 3.4 Parte A no Raspberry Pi 3B+ — medianas (ms)

| N | Setup `add(N)` | Setup N witnesses | **Join** add | Join proof novo | Join upd. witness (1) | Join lote (N) | **Revog.** delete | Revog. upd. witness (1) | Revog. lote (N−1) | **Verificação** `verify` | decode CBOR + verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 49,00 | 151,34 | 5,87 | 13,65 | 7,60 | 73,63 | 9,54 | 11,36 | 102,03 | **10,82** | 10,89 |
| 50 | 275,98 | 1.253,21 | 6,10 | 14,88 | 8,60 | 405,51 | 9,90 | 12,16 | 613,33 | **11,57** | 11,66 |
| 100 | 563,30 | 2.912,56 | 6,13 | 15,24 | 9,30 | 867,51 | 10,05 | 11,72 | 1.253,04 | **13,40** | 13,43 |
| 500 | 2.696,32 | 18.921,55 | 5,85 | 14,10 | 7,92 | 4.249,03 | 9,25 | 10,98 | 5.683,38 | **11,44** | 11,62 |
| 1000 | 5.512,46 | 41.881,43 | 5,67 | 14,94 | 7,80 | 8.221,70 | 9,30 | 11,06 | 11.453,52 | **11,59** | 11,63 |

A nova PoE de um sensor existente levou de 13,6 a 15,8 ms (mediana) para qualquer N, tanto no join quanto na revogação. As tabelas completas (média, desvio-padrão, p95 e máximo) estão no Apêndice A.

**Escala com N, de N=10 a N=1000 (100×):**

| Operação | Razão das medianas | Ajuste linear (ms por sensor) | R² | Comportamento |
|---|---:|---:|---:|---|
| `verify_membership` | **1,07×** | — | — | **constante** |
| `add`, `delete`, 1 witness, 1 PoE, proof do novo sensor | 0,97–1,09× | — | — | **constante** |
| Setup `add(N)` | 112,5× | 5,50 | 0,99986 | linear |
| Join, lote de N witnesses | 111,7× | 8,25 | 0,99969 | linear |
| Revogação, lote de N−1 witnesses | 112,3× | 11,40 | 0,99988 | linear |
| N witnesses do zero (RootFactor) | 276,7× | — | — | superlinear, compatível com O(N log N): N·log N cresce 300× nesse intervalo |

**Tamanhos (CBOR, iguais em todas as máquinas e para todo N):** acumulador **531 B**, witness **530–531 B**, `MembershipProof` **550–1064 B**. O tamanho da proof é bimodal conforme o ID, e não conforme N: na PoE, Q = w^⌊H(id)/ℓ⌋ e, como H(id) e ℓ são primos de 256 bits, o quociente é 0 (Q = 1, ≈ 550 B) ou 1 (Q = w, ≈ 1064 B). O ESP-42 cai no segundo caso; ESP-02 e ESP-99, no primeiro.

**Primitivas no Pi (200 amostras):**
- `hash_to_prime`: mediana 1,85 ms (média 2,42; dp 1,80; p95 5,19).
- g^p mod n (2048 × 256 bits): mediana 3,04 ms (dp 0,03).

A variabilidade do `hash_to_prime` é intrínseca: o número de candidatos testados até achar um primo varia com o ID.

### 3.5 Comparação entre máquinas (medianas com N=1000, em ms)

| Operação | **Raspberry Pi 3B+** | i7-7700 (este laboratório) | Celeron N3350 (rodada anterior) | Pi ÷ i7 | Pi ÷ Celeron |
|---|---:|---:|---:|---:|---:|
| `verify_membership` | **11,59** | 1,08 | 3,22 | 10,7× | 3,6× |
| Join: `add` de 1 sensor | **5,67** | 0,51 | 1,58 | 11,1× | 3,6× |
| Join: proof do novo sensor | **14,94** | 1,52 | 4,34 | 9,8× | 3,4× |
| Join: update de 1 witness | **7,80** | 0,77 | 2,40 | 10,2× | 3,3× |
| Revogação: `delete` | **9,30** | 0,81 | 2,42 | 11,4× | 3,8× |
| Revogação: update de 1 witness | **11,06** | 1,02 | 3,78 | 10,9× | 2,9× |
| Join: lote (N) | **8.221,70** | 823,11 | 2.569,70 | 10,0× | 3,2× |
| Revogação: lote (N−1) | **11.453,52** | 1.074,90 | 3.389,81 | 10,7× | 3,4× |
| Setup N witnesses (RootFactor) | **41.881,43** | 3.475,03 | 11.204,91 | 12,1× | 3,7× |
| Primitiva `hash_to_prime` | 1,85 | 0,22 | 0,68 | 8,4× | 2,7× |
| Primitiva g^p mod n | 3,04 | 0,24 | 0,73 | 12,4× | 4,2× |

Em **todas** as operações do benchmark e para **todos** os N, o Pi foi **≈ 10× mais lento que o i7-7700** (faixa de 9,5–12,1×) e **≈ 3,3× mais lento que o Celeron N3350** (faixa de 2,8–3,8×). O fator é praticamente uniforme, o que indica que as **formas de crescimento** medidas no PC (O(1) e O(N)) **se transferem sem distorção** para o Pi: só muda a constante multiplicativa.

---

## 4. Discussão

### 4.1 Verificação O(1) confirmada no dispositivo-alvo (H1)

No Pi, a mediana de `verify_membership` oscilou entre **10,8 e 13,4 ms**, **sem tendência** com N. O valor de N=100 é o maior, e os de N=500 e N=1000 estão entre os menores. Isso é ruído, não crescimento. A explicação está na própria operação: a verificação calcula Q^ℓ · w^(H(id) mod ℓ) e compara com A, com expoentes primos de **256 bits** e operandos de **2048 bits**, qualquer que seja N. O custo esperado de ≈ 2 `hash_to_prime` + ≈ 2 exponenciações é **2 × 1,85 + 2 × 3,04 ≈ 9,8 ms**, compatível com os 10,8–11,6 ms medidos.

Além do tempo, **o estado do controlador e o pacote do sensor também são O(1)**: o acumulador tem 531 B para 10 ou 1000 sensores, e a proof tem 550 ou 1064 B conforme o ID, nunca conforme N. Para o ITS, isso significa que um controlador de cruzamento de baixo custo como o Pi 3B+ verifica cada sensor sempre com o mesmo custo, independentemente do tamanho da rede.

### 4.2 Custo dos eventos dinâmicos (H2)

| Operação (1 evento) | Onde executa | No Pi (mediana) | No i7-7700 | Escala com N |
|---|---|---|---|---|
| Adicionar sensor (`add`) | TMC | 5,7–6,1 ms | 0,5–0,6 ms | constante |
| Proof do novo sensor | TMC | 13,6–15,2 ms | 1,4–1,5 ms | constante |
| Revogar sensor (`delete`) | TMC | 9,3–10,1 ms | 0,8–0,9 ms | constante |
| Atualizar 1 witness (join) | TMC | 7,6–9,3 ms | 0,7–1,0 ms | constante |
| Atualizar 1 witness (revogação) | TMC | 11,0–12,2 ms | 1,0–1,3 ms | constante |
| Atualizar **toda a rede** (join) | TMC | 8,25 ms × N → **8,2 s** (N=1000) | 0,82 s | **linear** |
| Atualizar **toda a rede** (revogação) | TMC | 11,40 ms × N → **11,5 s** (N=1000) | 1,07 s | **linear** |
| Recalcular tudo do zero (RootFactor) | TMC | **41,9 s** (N=1000) | 3,5 s | O(N log N) |
| Verificar um pacote | Controlador | ≈ 11,6 ms (só a V03) | ≈ 1,1 ms | **constante** |
| Operação no ESP32 | Sensor | **nenhuma**: só troca a proof armazenada | — | — |

Leituras principais:

- **A revogação é ≈ 1,4× mais cara que a adição** por witness atualizada no Pi (11,06 contra 7,80 ms; nos lotes, 11,40 contra 8,25 ms/sensor), a mesma relação vista no PC. Na adição, a atualização é uma exponenciação (w' = w^H(x)). Na deleção, é preciso resolver Euclides estendido e fazer duas exponenciações (w^b · A'^a), com inversão modular para o coeficiente negativo.
- **O `delete` em si é barato:** para um único elemento, a biblioteca só confere w^H(x) = A e adota w como o novo A.
- **A atualização incremental compensa:** atualizar witness por witness custa **8,2 s (join) e 11,5 s (revogação)**, contra **41,9 s** do RootFactor para N=1000 no Pi, de **3,7× a 5,1× mais barato**.
- **Onde o custo fica:** todo o trabalho O(N) é do **TMC, offline**. Mesmo no pior caso, com o TMC rodando num hardware tão modesto quanto o Pi, preparar as novas proofs de uma rede de **1000 sensores após uma revogação leva ≈ 11,5 s**. Num servidor comparável ao i7-7700, leva ≈ 1,1 s. O controlador só troca um valor de 531 B.

### 4.3 Revogação e adição no hardware real (H3, H4, H5)

**H3 — revogação.** Na Fase 3, o ESP32 continuou enviando como ESP-42, **sem nenhuma alteração**: mesma chave privada, mesma proof, timestamp sincronizado. Os 40 pacotes passaram na **V01** (Δ de 0–1 s) e na **V02** (`Assinatura RSA-2048 VÁLIDA` em 40/40). Mesmo assim, **100% foram rejeitados na V03 aritmética**. No controlador, a única mudança entre as Fases 1 e 3 foi o arquivo do acumulador: o `HashMap` de chaves públicas continuou com o ESP-42 cadastrado. Esse é o cenário de um sensor **comprometido ou descomissionado cuja chave continua válida**, e o acumulador o barra sem nenhuma lista de revogação.

**H4 — witnesses desatualizadas.** O ESP-02 é legítimo em todos os estados, mas foi rejeitado sempre que apresentou uma proof de um estado anterior:
- 40/40 pacotes com a proof de A1 contra A2, ou seja, **depois de uma remoção** (F1-B\* + F3-B);
- 20/20 com a proof de A2 contra A3, ou seja, **depois de uma adição** (F4-C).

Com a proof atualizada, ele foi aceito em 100% dos casos (F3-C e F4-B). Isso confirma a propriedade e o custo operacional do esquema: **qualquer** mudança em A exige redistribuir as proofs.

**H5 — adição.** Bastou regravar o ESP32 com a nova identidade (ID, chave e proof de A3) e carregar A3 no controlador para que os **30/30 pacotes do ESP-99** fossem aceitos. Nenhum outro componente foi alterado. A chave pública do ESP-99 está cadastrada em todas as fases, mas o ESP-99 não enviou pacotes contra A1 ou A2. O caso "chave cadastrada, mas fora do acumulador" foi exercitado pelo ESP-42 na Fase 3.

**O que o acumulador entrega além da assinatura pura:**

1. **Revogação pela troca de um único valor de tamanho constante (531 B).** Não há lista de revogação, consulta online nem edição da base de chaves. Num ITS com muitos controladores (RSUs, cruzamentos), revogar equivale a difundir um valor autenticável pelo TMC, em vez de sincronizar uma CRL que cresce com o tempo.
2. **Separação entre autenticação e autorização.** A assinatura prova *quem* enviou; o acumulador prova que o remetente *pertence ao conjunto autorizado no estado atual*. Uma chave vazada ou de um sensor desativado deixa de valer assim que A muda.
3. **Estado mínimo e constante no controlador:** 531 B, independentemente de N.

**Leitura honesta:** neste protótipo, com um único controlador, **remover a chave do ESP-42 do `HashMap` também o bloquearia**, já na V02 e com menos custo por pacote. O ganho do acumulador é **operacional e de escala**: revogação com estado constante, distribuível a muitos verificadores, sem listas crescentes. Os dois mecanismos são complementares, e a arquitetura usa ambos.

### 4.4 Desempenho do controlador no Pi e o efeito do DVFS

O tempo de um pacote no controlador do Pi **não é um valor único**: ele se divide em dois patamares, de **≈ 13,6 ms** e **≈ 30,8 ms** para proofs de 551 B (seção 3.2). A causa é o **escalonamento dinâmico de frequência (DVFS)** da CPU, e não o acumulador. O Pi usava o governor **`ondemand`** (`/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor`), que mantém a CPU no clock mínimo enquanto ela está ociosa e só sobe para o máximo quando a carga aumenta. Quatro observações nos dados confirmam isso:

1. A razão entre os patamares (**2,26×**) é próxima de **1400 MHz / 600 MHz = 2,33**, os dois pontos de operação do Cortex-A53 do Pi 3B+. O próprio `dynamic_bench` registrou **600 MHz** ao iniciar, com a CPU ociosa.
2. **Dentro de cada patamar, a dispersão é mínima** (σ = 0,40 ms no rápido), e o patamar **muda no meio da rajada**, sem nenhuma mudança no tipo de pacote (F4-B e F4-C).
3. **Aceitos e rejeitados custam o mesmo** dentro de cada patamar (13,30 contra 14,04 ms; 30,96 contra 30,70 ms). Logo, o desfecho da V03 não altera o custo, e a verificação é executada por inteiro nos dois casos.
4. No **benchmark**, com a CPU ocupada continuamente e, portanto, no clock máximo, a V03 sozinha leva ≈ 11,6 ms. Isso é coerente com o patamar rápido do controlador (≈ 13,6 ms = V03 + RSA-2048 + decode CBOR).

Os pacotes do ESP32, que chegam a cada ≈ 3 s, encontraram a CPU quase sempre no clock mínimo (75 de 80 no patamar lento com a proof de 1064 B). Por isso, **o tempo típico em campo, com tráfego esparso, é o do patamar lento: ≈ 31 ms (proof de 551 B) e ≈ 38–42 ms (proof de 1064 B)**. Com tráfego intenso, o governor sobe o clock e o custo cai para ≈ 13–18 ms.

**Capacidade estimada (ordem de grandeza).** O `udp_controller` processa os pacotes sequencialmente, num único thread. Com ≈ 13,6 ms por pacote no clock máximo, ele atende ≈ 73 pacotes/s, ou ≈ 220 sensores enviando a cada 3 s. No clock mínimo, ≈ 32 pacotes/s, ou ≈ 97 sensores. A estimativa ignora fila, rede e a impressão do log, e não usa os outros 3 núcleos do Pi. Para dimensionamento real, recomenda-se fixar o governor em `performance` ou paralelizar a verificação.

**Memória:** **2,76–2,80 MB** de RAM no processo, estável nas três fases. Isso é menos que os ≈ 7,3 MB medidos no Windows/Celeron. A diferença reflete o SO, o alocador e a forma de contabilizar a memória, e não o acumulador, cujo estado é de 531 B.

### 4.5 Acertos, falhas e incidentes do experimento

**Acertos:**
- **Todas as hipóteses foram confirmadas:** 230/230 pacotes no hardware e 450/450 no controle local tiveram exatamente o desfecho e a camada esperados, sem nenhum falso positivo ou falso negativo.
- **Reprodutibilidade:** os artefatos do TMC foram gerados do zero nesta máquina, com chaves novas. A1 saiu idêntico ao `accumulator.dat` original, o pacote do Pi foi conferido por MD5, e o resultado funcional coincidiu com o da rodada do Celeron.
- **Isolamento do efeito do acumulador:** como nenhum pacote foi rejeitado por V01, V02 ou C00, toda rejeição observada é atribuível à V03.
- **Rede sem perdas:** 0 lacunas de sequência em 230 pacotes, com o ESP32 passando por Wi-Fi + NAT do celular.

**Falhas e incidentes (nenhum afeta as conclusões):**
1. **Primeira tentativa sem conectividade.** Na Fase 1, o hotspot do celular inicialmente não tinha saída: o NTP do ESP32 falhou (`Usando tempo interno`) e nenhum pacote chegou ao Pi. Depois de restabelecer a conexão do celular e reiniciar o ESP32, o NTP sincronizou. As duas sessões dessa etapa foram descartadas (seção 3.1). **Lição:** o ESP32 só tenta o NTP na inicialização. Se o NTP falhar, os pacotes chegariam com relógio errado e seriam barrados na V01, o que confundiria a análise. É preciso verificar `NTP sincronizado!` antes de cada fase.
2. **Reenvio da Fase 1 do cliente com o controlador em A2.** Isso aumentou o número de pacotes do ESP-02 na Fase 3 (60 em vez de 40), mas o efeito foi neutro, até positivo: uma amostra extra de witness desatualizada, rejeitada como esperado.
3. **Sobrescrita de resultado versionado.** Em modo remoto, o `dynamic_e2e` grava `logs_dinamicidade/resultados_e2e.json`, o resultado da rodada do Celeron, com campos vazios ("?"), porque não tem acesso ao log do Pi. O arquivo original foi restaurado do Git. **Recomendação:** passar `--json` explícito no modo `--no-spawn`, ou ajustar o binário para não gravar nesse caso.
4. **Cross-build fora do WSL.** O `scripts/cross_build_rpi.sh` pressupõe WSL com o toolchain `aarch64-linux-gnu`. Neste PC (Linux nativo), o equivalente foi feito com `cross` (Docker), com o mesmo empacotamento.
5. **Assimetria de rede.** O ESP32 chegou por Wi-Fi + NAT, mas o ESP-02 simulado chegou por Ethernet. Como o tempo medido começa no `recv_from`, a latência de rede não entra nos números do controlador.

---

## 5. Limitações e ameaças à validade

1. **Toda mudança em A invalida todas as witnesses, inclusive na adição** (F3-B, F1-B\* e F4-C). Depois de cada evento, o TMC precisa recalcular e **redistribuir** a proof dos sensores remanescentes. O canal de distribuição (OTA, MQTT, provisionamento) **não foi implementado nem medido**: neste experimento, a nova identidade foi gravada por cabo no ESP32.
2. **Janela de inconsistência.** Até todos os sensores receberem as novas proofs, os legítimos ainda não atualizados são rejeitados. E enquanto o controlador não carregar o novo A, o revogado continua aceito. O `udp_controller` lê A **só na inicialização** (cada fase exigiu reiniciá-lo). Recarga a quente, versionamento por época e um período de graça para A_anterior ficam como trabalho futuro; o período de graça reabre a janela para o revogado.
3. **Deleção sem trapdoor exige estado no TMC:** a witness atual de cada sensor, ou o conjunto completo para reconstruir A (no Pi, ≈ 5,5 s para N=1000).
4. **Sem atualização em lote nativa:** o "lote" é um laço de N chamadas a `update_membership_witness`.
5. **Cuidados da biblioteca:** o acumulador é um **multiconjunto**, então IDs repetidos exigem controle no TMC. A biblioteca se declara *research-grade*, sem auditoria independente.
6. **PoE trivial para um único elemento:** Q vale 1 ou w, e o tamanho da proof é bimodal (550/1064 B) conforme o ID. Isso também afeta o tempo: proofs de 1064 B custam ≈ 25% a mais no controlador.
7. **Validade dos números:**
   - Os tempos do controlador no Pi dependem do **governor de frequência** (seção 4.4). O Pi usava o padrão `ondemand`, sem fixar o clock. Uma repetição com `performance` mostraria só o patamar rápido. As medianas por cenário misturam os dois regimes em proporções diferentes, então para comparar cenários devem-se usar os patamares da seção 3.2, e não as médias.
   - As operações pesadas tiveram 5 repetições (p95 = máximo).
   - A amostra no hardware é de 20–40 pacotes por cenário, suficiente para o resultado funcional (desfechos determinísticos), mas pequena para caracterizar a cauda da latência.
   - **Um único ESP32** e um único controlador; não houve teste de carga com muitos sensores simultâneos.
   - A comparação com o Celeron envolve SO, compilador e versão da GMP diferentes. A comparação com o i7-7700 usa o mesmo código-fonte, o mesmo rustc e a GMP 6.3.0 embutida no `gmp-mpfr-sys`, mas outra arquitetura.
8. **Correção de uma premissa da rodada anterior:** o relatório de 20/11 supunha que o Celeron N3350 estava "na mesma ordem de grandeza" do Cortex-A53. Na medição real, o Pi 3B+ foi **≈ 3,3× mais lento** que o Celeron. Os números do Celeron **não** devem ser usados como estimativa do Pi.
9. **Possível evolução (não medida):** como a atualização de witness usa apenas dados públicos, o próprio sensor poderia atualizar sua witness a partir de um *delta* difundido por broadcast (o ID afetado e o novo A). Isso trocaria a distribuição individualizada O(N) por um broadcast O(1), ao custo de ≈ 2 exponenciações de 2048 bits no ESP32, que precisariam ser medidas.

---

## 6. Conclusão

O experimento no hardware real confirmou as cinco hipóteses:

- **Verificação O(1):** no Raspberry Pi 3B+, a V03 custa ≈ 11,6 ms com 10 ou com 1000 sensores (razão de 1,07× para uma rede 100× maior). O estado do controlador é sempre de 531 B.
- **Eventos dinâmicos baratos e independentes de N:** adicionar ou revogar um sensor custa ≈ 6–10 ms. Só a redistribuição para a rede inteira é linear: 8,2 s (join) e 11,5 s (revogação) para 1000 sensores no próprio Pi, ou ≈ 1 s num PC. Esse trabalho é do TMC, offline.
- **Revogação efetiva sem tocar na base de chaves:** o ESP32 revogado, com assinatura legítima, foi barrado em 100% dos pacotes, exatamente na V03.
- **Witnesses desatualizadas barradas** depois de remoções e adições, e aceitas depois de atualizadas.
- **Adição de um sensor novo** com 100% de aceitação, sem alterar os demais componentes.

Os custos medidos no Pi são ≈ 10× maiores que num i7-7700 e ≈ 3,3× maiores que no Celeron da rodada anterior, mas as **formas de crescimento são as mesmas**. No controlador, o custo por pacote fica entre ≈ 13 e ≈ 42 ms, conforme o clock da CPU e o tamanho da proof. Isso é pequeno diante do intervalo de envio de 3 s do sensor. O preço do esquema é operacional: cada mudança no conjunto exige redistribuir as proofs. Esse canal, e a recarga a quente do acumulador no controlador, são os próximos passos para uso em campo.

---

## 7. Reprodução

```bash
# ── No PC (Linux; raiz do repositório) ─────────────────────────────────────
cargo build --release --bin udp_controller --bin dynamic_bench --bin dynamic_tmc \
    --bin dynamic_e2e --bin interface_cbor
./target/release/dynamic_tmc                      # gera target/e2e_dinamicidade/ (11 checagens)

# Cross-build para o Pi: no WSL, `bash scripts/cross_build_rpi.sh`;
# em Linux nativo, o equivalente com `cross` (Docker):
cross build --release --target aarch64-unknown-linux-gnu --bin udp_controller \
    --bin dynamic_bench --bin dynamic_tmc --bin dynamic_e2e --bin interface_cbor
#   (depois: strip, cópia de scripts/rpi/* e dos artefatos públicos, CHECKSUMS.md5 —
#    mesmos passos do scripts/cross_build_rpi.sh)

scp -r dist/rpi-aarch64 raspberry@<IP_DO_PI>:~/tcc/rpi-aarch64
ssh raspberry@<IP_DO_PI> 'cd ~/tcc/rpi-aarch64 && md5sum -c CHECKSUMS.md5'

# Partes A e B locais no PC (controle):
./target/release/dynamic_bench --ns 10,50,100,500,1000 --reps 20 --heavy-reps 5 \
    --verify-reps 200 --out logs_dinamicidade/pc_lab/resultados_dinamicidade_pc.json
./target/release/dynamic_e2e --host 127.0.0.1 --packets 50 --no-pause \
    --json logs_dinamicidade/pc_lab/resultados_e2e_pc.json \
    --controller-log logs_dinamicidade/pc_lab/e2e_controller_pc.log

# ── Fases no hardware ─────────────────────────────────────────────────────
# ESP32: wifi_config.h com SSID/senha e SERVER_IP = IP do Pi; sem sensor_identity.h = ESP-42/A1.
# Pi:    ./rodar_fase.sh A1   (depois A2 e A3; Ctrl+C encerra cada fase)
# PC:    ./target/release/dynamic_e2e --host <IP_DO_PI> --no-spawn --sensors ESP-02 \
#            --packets 20 --delay-ms 200 --json /tmp/e2e_remoto.json
# Fase 4: python3 SnifferESP/gen_sensor_identity.py --sensor ESP-99 --acc A3 + upload
# Pi:    ./rodar_bench.sh     (Parte A)

# ── Análise ───────────────────────────────────────────────────────────────
scp -r raspberry@<IP_DO_PI>:~/tcc/rpi-aarch64/logs logs_dinamicidade/rpi
python3 scripts/rpi/analisar_log.py --json logs_dinamicidade/rpi/resumo_hardware.json \
    logs_dinamicidade/rpi/controller_A{1,2,3}_*.log
python3 scripts/rpi/analisar_por_cenario.py --json logs_dinamicidade/rpi/resumo_por_cenario.json \
    A1=<log A1> "A2=<log A2>:F1-B*,F3-B,F3-C" A3=<log A3>
```

## 8. Arquivos

| Arquivo | Conteúdo |
|---|---|
| `rpi/controller_A1_20261123_143235.log` | Fase 1 no Pi (sessão válida): stdout completo do controlador |
| `rpi/controller_A2_20261123_155532.log` | Fase 3 no Pi |
| `rpi/controller_A3_20261123_160544.log` | Fase 4 no Pi |
| `rpi/controller_A1_20261123_142548.log`, `rpi/controller_A1_20261123_143204.log` | Sessões de diagnóstico de conectividade (**descartadas**) |
| `rpi/dynamic_bench_rpi_20261123_163019.log` / `.json` | Parte A no Pi: saída e amostras brutas + estatísticas |
| `rpi/resumo_hardware.json` | Resumo por sensor e camada (`analisar_log.py`) das 3 sessões válidas |
| `rpi/resumo_por_cenario.json` | Resumo por cenário, regimes de tempo, Δ timestamp, lacunas (`analisar_por_cenario.py`) |
| `pc_lab/dynamic_bench_pc_20261123_131323.log` / `resultados_dinamicidade_pc_*.json` | Parte A no i7-7700 |
| `pc_lab/e2e_client_pc.log`, `pc_lab/e2e_controller_pc.log`, `pc_lab/resultados_e2e_pc.json` | Parte B local (loopback) no i7-7700 |
| `pc_lab/tmc_manifest_pc.json` | Manifesto do TMC desta rodada (tempos, tamanhos, 11 checagens) |
| `dynamic_bench.log`, `resultados_dinamicidade.json`, `e2e_*.log`, `resultados_e2e.json` | Rodada anterior (Celeron N3350, 20/11/2026), mantida como referência |

Os nomes dos logs do Pi trazem a hora do relógio do Pi (UTC). Os do PC trazem a hora local (UTC−3).

## 9. Alterações de código na branch

**Da rodada anterior:**
- **Novos binários:** `src/bin/dynamic_bench.rs`, `src/bin/dynamic_tmc.rs` e `src/bin/dynamic_e2e.rs`.
- **`interfaceCBOR/main.rs`:** novas flags `--acc`, `--pubkey`, `--bind` e `--max-packets`. Sem flags, o comportamento é idêntico ao original.
- **`Cargo.toml`:** registro dos binários, `serde_json`, feature `getrandom` do `rsa`, `rug` restrito a `integer` e feature `system-gmp`.
- **`src/uint.rs`:** portabilidade para Windows (tipos da GMP), sem mudança no Linux/Pi.
- **Scripts:** `scripts/rpi/*`, `scripts/setup_wsl_cross.sh`, `scripts/cross_build_rpi.sh` e `SnifferESP/gen_sensor_identity.py`.

**Nesta rodada:**
- **Nenhuma mudança no código Rust.**
- **Novo:** `scripts/rpi/analisar_por_cenario.py`.
- **Configuração local do ESP32:** `SnifferESP/esp32_sensor/wifi_config.h` (SSID do hotspot e IP do Pi).

---

## Apêndice A — Tabelas completas da Parte A no Raspberry Pi 3B+ (ms)

Formato: média / mediana / desvio-padrão / p95 / máximo. Repetições: setup e lotes n = 5; operações unitárias n = 20; verificação n = 200.

| Métrica | N=10 | N=50 | N=100 | N=500 | N=1000 |
|---|---|---|---|---|---|
| Setup `add(N)` | 49,00 / 49,00 / 0,03 / 49,04 / 49,04 | 276,07 / 275,98 / 0,32 / 276,42 / 276,42 | 563,23 / 563,30 / 0,13 / 563,33 / 563,33 | 2.696,74 / 2.696,32 / 1,31 / 2.698,23 / 2.698,23 | 5.512,01 / 5.512,46 / 1,07 / 5.513,14 / 5.513,14 |
| Setup N witnesses | 151,29 / 151,34 / 0,17 / 151,45 / 151,45 | 1.253,45 / 1.253,21 / 0,84 / 1.254,91 / 1.254,91 | 2.913,32 / 2.912,56 / 1,89 / 2.916,21 / 2.916,21 | 18.923,10 / 18.921,55 / 4,47 / 18.928,62 / 18.928,62 | 41.884,50 / 41.881,43 / 8,45 / 41.894,04 / 41.894,04 |
| Join: add | 5,99 / 5,87 / 1,02 / 7,90 / 8,42 | 6,66 / 6,10 / 1,77 / 10,07 / 10,49 | 6,40 / 6,13 / 1,42 / 8,81 / 10,46 | 6,08 / 5,85 / 0,89 / 7,53 / 7,97 | 6,28 / 5,67 / 1,70 / 10,40 / 10,56 |
| Join: proof novo | 14,36 / 13,65 / 2,22 / 17,85 / 18,14 | 15,87 / 14,88 / 4,20 / 22,85 / 23,60 | 15,83 / 15,24 / 3,24 / 20,73 / 23,85 | 14,32 / 14,10 / 2,54 / 17,68 / 20,26 | 14,95 / 14,94 / 3,09 / 21,70 / 22,58 |
| Join: upd. witness (1) | 7,78 / 7,60 / 1,48 / 9,97 / 11,24 | 9,32 / 8,60 / 2,60 / 14,56 / 15,58 | 9,12 / 9,30 / 2,04 / 12,21 / 12,44 | 7,98 / 7,92 / 1,51 / 10,89 / 11,42 | 8,45 / 7,80 / 2,02 / 12,14 / 12,74 |
| Join: nova PoE (1) | 13,99 / 13,78 / 2,54 / 17,69 / 21,09 | 16,25 / 15,08 / 4,52 / 24,35 / 26,67 | 16,50 / 15,77 / 3,46 / 22,82 / 23,52 | 14,65 / 14,32 / 2,67 / 18,31 / 20,83 | 14,77 / 14,16 / 3,75 / 23,07 / 24,31 |
| Join: lote (N) | 79,30 / 73,63 / 14,09 / 102,31 / 102,31 | 395,80 / 405,51 / 30,24 / 431,76 / 431,76 | 852,36 / 867,51 / 102,58 / 957,13 / 957,13 | 4.272,10 / 4.249,03 / 337,87 / 4.644,17 / 4.644,17 | 8.215,27 / 8.221,70 / 740,09 / 9.127,43 / 9.127,43 |
| Revog.: delete | 9,73 / 9,54 / 0,92 / 11,69 / 11,69 | 10,32 / 9,90 / 1,36 / 12,98 / 13,54 | 10,34 / 10,05 / 1,35 / 13,00 / 13,25 | 9,80 / 9,25 / 1,27 / 12,81 / 13,20 | 9,89 / 9,30 / 1,35 / 12,69 / 13,86 |
| Revog.: upd. witness (1) | 11,49 / 11,36 / 1,05 / 13,63 / 13,65 | 12,55 / 12,16 / 1,96 / 14,46 / 18,58 | 12,24 / 11,72 / 1,61 / 14,89 / 14,94 | 11,78 / 10,98 / 2,21 / 14,33 / 18,96 | 12,69 / 11,06 / 3,53 / 19,20 / 21,35 |
| Revog.: nova PoE (1) | 13,99 / 12,95 / 3,01 / 18,98 / 19,12 | 15,05 / 14,56 / 3,28 / 21,23 / 22,92 | 14,55 / 14,17 / 2,66 / 18,11 / 22,28 | 14,76 / 14,11 / 3,88 / 21,37 / 24,82 | 16,05 / 13,64 / 5,24 / 24,88 / 29,64 |
| Revog.: lote (N−1) | 101,83 / 102,03 / 5,91 / 111,21 / 111,21 | 640,78 / 613,33 / 80,34 / 781,98 / 781,98 | 1.248,47 / 1.253,04 / 40,06 / 1.298,87 / 1.298,87 | 5.986,48 / 5.683,38 / 814,51 / 7.436,05 / 7.436,05 | 12.065,28 / 11.453,52 / 1.635,22 / 14.975,48 / 14.975,48 |
| `verify_membership` | 11,48 / 10,82 / 1,98 / 15,41 / 15,56 | 13,03 / 11,57 / 3,23 / 19,53 / 19,82 | 13,80 / 13,40 / 2,40 / 20,18 / 20,43 | 11,63 / 11,44 / 1,53 / 14,51 / 15,01 | 11,79 / 11,59 / 1,29 / 15,04 / 15,09 |
| decode CBOR + verify | 11,52 / 10,89 / 1,98 / 15,45 / 15,74 | 13,06 / 11,66 / 3,23 / 19,55 / 19,77 | 13,84 / 13,43 / 2,41 / 20,23 / 20,63 | 11,66 / 11,62 / 1,52 / 14,54 / 14,69 | 11,83 / 11,63 / 1,30 / 15,08 / 15,24 |

## Apêndice B — Rodada anterior (Celeron N3350, Windows 10, 20/11/2026): medianas (ms)

| N | Setup `add(N)` | Setup N witnesses | Join add | Join proof novo | Join upd. witness (1) | Join lote (N) | Revog. delete | Revog. upd. witness (1) | Revog. lote (N−1) | `verify` | decode + verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 15,11 | 42,49 | 1,70 | 3,92 | 2,45 | 23,96 | 2,71 | 3,29 | 29,87 | 3,08 | 3,12 |
| 50 | 82,79 | 336,39 | 1,73 | 4,19 | 2,59 | 129,04 | 2,74 | 3,48 | 182,52 | 3,55 | 3,66 |
| 100 | 170,69 | 772,49 | 1,82 | 4,92 | 2,91 | 270,21 | 2,81 | 3,49 | 381,07 | 4,00 | 4,05 |
| 500 | 812,98 | 4.989,77 | 1,63 | 4,07 | 2,48 | 1.444,07 | 2,50 | 3,34 | 1.678,59 | 3,33 | 3,36 |
| 1000 | 1.664,89 | 11.204,91 | 1,58 | 4,34 | 2,40 | 2.569,70 | 2,42 | 3,78 | 3.389,81 | 3,22 | 3,25 |

Na Parte B em loopback no Celeron, os 9 cenários × 50 pacotes também tiveram 100% do desfecho esperado, com mediana de 3,8–5,6 ms no controlador. As tabelas completas dessa rodada estão em `dynamic_bench.log` e `resultados_dinamicidade.json`, e o histórico do Git tem a versão anterior deste relatório.
