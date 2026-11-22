# Relatório Técnico — Dinamicidade do Acumulador Criptográfico RSA-2048

**Experimento:** adição de sensores (*join*), revogação/remoção (*delete*) e atualização de witnesses no acumulador RSA da biblioteca Cambrian modificada (`accumulatorGSIPP`), com verificação no controlador UDP (porta 4242).
**Branch:** `experimento-dinamicidade` (sem commit — aguardando revisão)
**Data da execução:** 20/11/2026

---

## 0. Resumo executivo

| Pergunta dos revisores | Resultado empírico |
|---|---|
| A verificação no controlador é O(1) em relação ao tamanho da rede? | **Sim.** A mediana de `verify_membership` foi de **3,08 ms (N=10)** e **3,22 ms (N=1000)**: razão de **1,05×** para uma rede **100× maior**. O acumulador (531 B), a witness (530–531 B) e a `MembershipProof` (550–1064 B) têm o **mesmo tamanho para todo N**. |
| Quanto custa adicionar um sensor? | **~1,6 ms** no TMC para atualizar o acumulador, **~4,3 ms** para gerar a proof do novo sensor e **~2,5 ms** por witness existente atualizada. Os custos unitários não dependem de N. |
| Quanto custa revogar um sensor? | **~2,5 ms** no TMC para o `delete`, mais **~3,5 ms** por witness remanescente atualizada. Também independem de N. |
| E o custo de atualizar a rede inteira? | Linear em N: **2,57 s** (join) e **3,39 s** (revogação) para **1000** sensores nesta CPU modesta. Esse trabalho é feito **offline no TMC**; o ESP32 apenas recebe a nova proof. |
| A revogação funciona no controlador real, sem alterar o `HashMap` de chaves? | **Sim.** **50/50** pacotes do ESP-42 revogado, **assinados com a chave RSA legítima**, foram **rejeitados na V03 aritmética**, mesmo com a chave pública dele ainda carregada. Os sensores legítimos com witness atualizada tiveram **100% de aceitação**; com witness desatualizada, **100% de rejeição**. |

**Parte B:** 9 cenários × 50 pacotes = **450 pacotes, 9/9 cenários com o desfecho esperado em 100% dos pacotes.**

> ⚠️ **Aviso sobre os números.** Os tempos foram medidos num **PC de desenvolvimento Windows com Intel Celeron N3350**, não no Raspberry Pi 3B+. Eles servem como **prova funcional e evidência de tendência** (constância O(1), linearidade O(N)). Os **números finais do TCC** devem vir da reexecução no Raspberry Pi 3B+ (seção 7), com os mesmos binários e parâmetros. Na Parte B, o tráfego UDP passou pela **interface de loopback (127.0.0.1)**; o teste via **Wi-Fi** com o controlador no Pi usa o mesmo cliente com `--host <IP_DO_PI>`.

---

## 1. Ambiente de execução

| Item | Valor |
|---|---|
| CPU | Intel® Celeron® N3350 @ 1,10 GHz (2 núcleos / 2 threads, sem Hyper-Threading) |
| RAM | 3,8 GiB |
| SO | Windows 10 Pro Education 22H2 (build 19045), x86_64 |
| Toolchain | rustc 1.100.0, alvo `x86_64-pc-windows-gnu` (MSYS2 UCRT64, gcc) |
| GMP | 6.3.0 (pacote MSYS2, ligada via `--features system-gmp`) |
| Perfil | `--release` (opt-level 3) |
| Repetições | operações unitárias: **20**; operações O(N)/O(N log N): **5**; verificação: **200** |

Em termos de desempenho por núcleo, o Celeron N3350 é uma CPU de baixo consumo e está na mesma ordem de grandeza do Cortex-A53 do Raspberry Pi 3B+. Mesmo assim, **não se deve transpor os valores absolutos**: o Pi usa outra arquitetura (aarch64), outro clock (1,4 GHz) e outra GMP.

---

## 2. Como a biblioteca Cambrian executa as operações dinâmicas

Antes de escrever código, analisei a API pública em `src/accumulator.rs`. Ela fornece:

| Operação | Método público | Mecanismo |
|---|---|---|
| Acumulação | `Accumulator::empty().add(&ids)` | A = g^(∏ H(idᵢ)) mod n, com g = 2 e H = `hash_to_prime` (primo de 256 bits via Blake2b + BPSW) |
| Adição (join) | `acc.add(&[novo])` / `add_with_proof` | A' = A^H(novo). A witness do novo sensor é o próprio A antigo. |
| **Deleção (revogação)** | `acc.delete(&[(id, witness)])` | **Sem trapdoor.** O módulo é o RSA-2048 do desafio RSA, cuja fatoração é desconhecida, então não dá para extrair raízes. A biblioteca **exige a witness do elemento removido**, confere que w^H(id) = A e aplica o *Shamir trick*. Na remoção de um único elemento, **o novo acumulador é a própria witness do removido** (A' = w_id). |
| Atualização de witness | `acc_novo.update_membership_witness(w, [id], adições, deleções)` | LLX 2007, Seção 4.2. Adição: w' = w^H(x). Deleção: w' = w^b · A'^a, com a·H(id) + b·H(x) = 1 (Euclides estendido). |
| Nova proof | `acc.prove_membership(&[(id, w)])` | Gera a `MembershipProof` (witness + PoE de Wesolowski) para o acumulador atual. |
| Verificação | `acc.verify_membership(&id, &proof)` | Verifica a PoE: Q^ℓ · w^(H(id) mod ℓ) = A. |
| Lote (do zero) | `Witness(empty).compute_individual_witnesses(&ids)` | *RootFactor*, O(N log N): recalcula todas as N witnesses. |

Consequências práticas:

1. **Para revogar, o TMC precisa ter a witness do sensor revogado.** Na falta dela, o caminho é reconstruir o acumulador a partir do conjunto remanescente, ao custo de um `add(N−1)` (~1,7 s para N=1000 nesta máquina).
2. **Não há segredo (trapdoor) para proteger no TMC.** Isso simplifica a confiança no TMC, mas torna a deleção dependente do estado (witnesses ou conjunto completo).
3. A atualização de witness usa **apenas dados públicos**: o novo A e o ID adicionado ou removido.

---

## 3. Parte A — Escalabilidade e operações dinâmicas (`dynamic_bench`)

Os sensores foram identificados como `ESP-0001 … ESP-N`, e todas as amostras estão em `resultados_dinamicidade.json`. Em cada repetição, um sensor diferente foi adicionado ou revogado. Fora da área cronometrada, o benchmark confere matematicamente cada resultado:

- novo acumulador correto;
- proofs atualizadas aceitas;
- proof do revogado rejeitada;
- witness antiga rejeitada;
- `delete` igual à reconstrução do zero.

### 3.1 Tabela consolidada (medianas, em ms)

| N | Setup `add(N)` | Setup N witnesses | **Join** add | Join proof novo | Join upd. witness (1) | Join lote (N) | **Revog.** delete | Revog. upd. witness (1) | Revog. lote (N−1) | **Verificação** `verify` | decode CBOR + verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 15,11 | 42,49 | 1,70 | 3,92 | 2,45 | 23,96 | 2,71 | 3,29 | 29,87 | **3,08** | 3,12 |
| 50 | 82,79 | 336,39 | 1,73 | 4,19 | 2,59 | 129,04 | 2,74 | 3,48 | 182,52 | **3,55** | 3,66 |
| 100 | 170,69 | 772,49 | 1,82 | 4,92 | 2,91 | 270,21 | 2,81 | 3,49 | 381,07 | **4,00** | 4,05 |
| 500 | 812,98 | 4.989,77 | 1,63 | 4,07 | 2,48 | 1.444,07 | 2,50 | 3,34 | 1.678,59 | **3,33** | 3,36 |
| 1000 | 1.664,89 | 11.204,91 | 1,58 | 4,34 | 2,40 | 2.569,70 | 2,42 | 3,78 | 3.389,81 | **3,22** | 3,25 |

A nova PoE do sensor existente, gerada após a atualização da witness, levou ~4,2–5,0 ms (mediana) para qualquer N, tanto no join quanto na revogação.

### 3.2 Tamanhos serializados (CBOR, mesmo formato do `accumulator.dat`)

| N | Acumulador | Witness | `MembershipProof` |
|---:|---:|---:|---:|
| 10 | 531 B | 530–531 B | 551–1064 B |
| 50 | 531 B | 530–531 B | 550–1064 B |
| 100 | 531 B | 530–531 B | 550–1064 B |
| 500 | 531 B | 530–531 B | 550–1064 B |
| 1000 | 531 B | 530–531 B | 550–1064 B |

O tamanho da proof é **bimodal, mas independente de N**. Na PoE, Q = w^⌊H(id)/ℓ⌋. Como H(id) e ℓ são primos de 256 bits, o quociente vale 0 (Q = 1, proof ≈ 550 B) ou 1 (Q = w, proof ≈ 1064 B), conforme o ID. O ESP-42 cai no segundo caso (1064 B, idêntico ao firmware); ESP-02 e ESP-99 caem no primeiro.

### 3.3 Primitivas (independentes de N, 200 amostras)

| Primitiva | Média | Mediana | Desvio-padrão | p95 |
|---|---:|---:|---:|---:|
| `hash_to_prime(id)` → primo de 256 bits | 1,63 | 0,68 | 9,68 | 2,77 |
| g^p mod n (n: 2048 bits; p: 256 bits) | 1,37 | 0,73 | 5,51 | 1,42 |

Média e desvio-padrão altos refletem poucos picos do SO (escalonador do Windows). A **mediana** é o estimador robusto aqui.

### 3.4 Tabelas completas (ms): média, mediana, desvio-padrão e p95

Nas operações pesadas (setup e lote), foram 5 amostras; com n=5, o p95 pelo método *nearest-rank* coincide com o máximo.

#### Acumulação inicial

**`add(N)` — construção do acumulador com N sensores**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 5 | 15,09 | 15,11 | 0,33 | 15,53 |
| 50 | 5 | 84,19 | 82,79 | 3,04 | 89,57 |
| 100 | 5 | 171,45 | 170,69 | 2,26 | 175,41 |
| 500 | 5 | 815,51 | 812,98 | 6,43 | 826,17 |
| 1000 | 5 | 1.698,25 | 1.664,89 | 86,74 | 1.852,70 |

**Geração das N witnesses (RootFactor)**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 5 | 42,71 | 42,49 | 0,68 | 43,81 |
| 50 | 5 | 335,75 | 336,39 | 2,80 | 339,36 |
| 100 | 5 | 775,01 | 772,49 | 7,25 | 786,68 |
| 500 | 5 | 4.995,09 | 4.989,77 | 16,64 | 5.018,36 |
| 1000 | 5 | 11.170,20 | 11.204,91 | 153,93 | 11.345,89 |

#### Adição dinâmica (Node Join)

**Join: `add` de 1 sensor no TMC**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 20 | 1,72 | 1,70 | 0,38 | 2,23 |
| 50 | 20 | 1,97 | 1,73 | 0,72 | 3,43 |
| 100 | 20 | 1,97 | 1,82 | 0,61 | 3,01 |
| 500 | 20 | 1,73 | 1,63 | 0,31 | 2,26 |
| 1000 | 20 | 1,73 | 1,58 | 0,54 | 3,05 |

**Join: `MembershipProof` do novo sensor**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 20 | 4,50 | 3,92 | 1,09 | 6,43 |
| 50 | 20 | 4,56 | 4,19 | 1,35 | 6,73 |
| 100 | 20 | 4,92 | 4,92 | 1,20 | 6,62 |
| 500 | 20 | 4,35 | 4,07 | 1,04 | 5,74 |
| 1000 | 20 | 4,52 | 4,34 | 1,08 | 6,29 |

**Join: atualização da witness de 1 sensor existente**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 20 | 2,52 | 2,45 | 0,56 | 3,30 |
| 50 | 20 | 2,94 | 2,59 | 1,16 | 5,44 |
| 100 | 20 | 2,99 | 2,91 | 1,03 | 5,12 |
| 500 | 20 | 2,53 | 2,48 | 0,71 | 3,36 |
| 1000 | 20 | 2,58 | 2,40 | 0,63 | 3,63 |

**Join: nova PoE do sensor existente (após atualizar a witness)**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 20 | 4,48 | 4,31 | 1,19 | 6,65 |
| 50 | 20 | 5,33 | 4,83 | 1,45 | 8,03 |
| 100 | 20 | 5,19 | 4,66 | 1,47 | 7,49 |
| 500 | 20 | 4,77 | 4,74 | 1,29 | 6,83 |
| 1000 | 20 | 4,99 | 4,98 | 1,53 | 7,82 |

**Join: atualização em lote das N witnesses**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 5 | 25,62 | 23,96 | 4,50 | 32,45 |
| 50 | 5 | 124,17 | 129,04 | 10,99 | 133,67 |
| 100 | 5 | 267,57 | 270,21 | 33,71 | 300,60 |
| 500 | 5 | 1.390,91 | 1.444,07 | 98,00 | 1.473,47 |
| 1000 | 5 | 2.575,92 | 2.569,70 | 261,28 | 2.900,50 |

#### Revogação dinâmica (Node Revocation)

**Revogação: `delete` de 1 sensor (Shamir trick, sem trapdoor)**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 20 | 2,91 | 2,71 | 0,60 | 3,87 |
| 50 | 20 | 2,93 | 2,74 | 0,66 | 4,02 |
| 100 | 20 | 3,00 | 2,81 | 0,61 | 3,73 |
| 500 | 20 | 2,74 | 2,50 | 0,51 | 3,65 |
| 1000 | 20 | 2,71 | 2,42 | 0,49 | 3,44 |

**Revogação: atualização da witness de 1 sensor legítimo**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 20 | 3,55 | 3,29 | 0,86 | 5,70 |
| 50 | 20 | 3,69 | 3,48 | 0,95 | 5,06 |
| 100 | 20 | 3,76 | 3,49 | 0,90 | 5,34 |
| 500 | 20 | 3,53 | 3,34 | 0,96 | 5,02 |
| 1000 | 20 | 3,92 | 3,78 | 1,14 | 6,19 |

**Revogação: nova PoE do sensor legítimo**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 20 | 5,78 | 4,67 | 3,96 | 12,67 |
| 50 | 20 | 4,72 | 4,48 | 1,29 | 7,03 |
| 100 | 20 | 4,54 | 4,43 | 1,01 | 5,90 |
| 500 | 20 | 4,62 | 4,24 | 1,53 | 7,50 |
| 1000 | 20 | 4,98 | 4,24 | 1,93 | 8,13 |

**Revogação: atualização em lote das N−1 witnesses remanescentes**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 5 | 29,97 | 29,87 | 2,10 | 32,88 |
| 50 | 5 | 194,88 | 182,52 | 27,29 | 243,29 |
| 100 | 5 | 375,84 | 381,07 | 14,13 | 388,66 |
| 500 | 5 | 1.776,17 | 1.678,59 | 269,39 | 2.255,31 |
| 1000 | 5 | 3.588,67 | 3.389,81 | 547,49 | 4.562,63 |

#### Verificação no controlador

**`verify_membership` (V03b, apenas aritmética)**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 200 | 4,48 | 3,08 | 5,53 | 8,35 |
| 50 | 200 | 3,94 | 3,55 | 1,27 | 6,28 |
| 100 | 200 | 4,20 | 4,00 | 1,00 | 6,51 |
| 500 | 200 | 3,43 | 3,33 | 0,71 | 4,81 |
| 1000 | 200 | 3,50 | 3,22 | 0,63 | 4,67 |

**Desserialização CBOR da proof + `verify_membership` (V03a + V03b, como no `udp_controller`)**

| N | amostras | média | mediana | desvio-padrão | p95 |
|---:|---:|---:|---:|---:|---:|
| 10 | 200 | 5,92 | 3,12 | 17,08 | 8,62 |
| 50 | 200 | 4,03 | 3,66 | 1,32 | 6,33 |
| 100 | 200 | 4,30 | 4,05 | 1,05 | 6,74 |
| 500 | 200 | 3,51 | 3,36 | 0,76 | 4,76 |
| 1000 | 200 | 3,55 | 3,25 | 0,70 | 4,74 |

Em N=10, média e desvio-padrão maiores vêm de 2 picos isolados (66 ms e 205 ms), típicos de interrupção do SO nas primeiras medições. Mediana e p95 não são afetados. Por isso a comparação de escala usa a **mediana**.

---

## 4. Parte B — Teste funcional fim-a-fim via UDP (`dynamic_tmc` + `dynamic_e2e`)

### 4.1 Procedimento

1. **TMC offline (`dynamic_tmc`).** Gera os três estados do acumulador usando **somente a API dinâmica**:
   - A1 = {ESP-01, ESP-02, ESP-42};
   - A2 = `A1.delete([(ESP-42, w42)])`;
   - A3 = `A2.add([ESP-99])`.

   Também gera as proofs (ESP-02 atualizada para A2 e A3; ESP-99 nova) e pares RSA-2048 **de teste** para ESP-02 e ESP-99. O ESP-42 usa a chave do firmware.
   - Checagens: **11/11 OK**. A1 é **byte a byte idêntico** ao `SnifferESP/accumulator.dat`, e a proof do ESP-42 em A1 é idêntica a `SnifferESP/proofs/ESP_42.proof`. A2 e A3 coincidem com a reconstrução do zero, ou seja, o `delete` e o `add` dinâmicos produzem exatamente o acumulador esperado.
2. **Controlador real (`udp_controller`).** Em cada fase, ele é iniciado com `--acc accumulator_A{k}.dat`, com `--pubkey` para ESP-02 e ESP-99, e com a **chave do ESP-42 mantida no `HashMap` em todas as fases** (o log mostra `Chaves públicas carregadas: 3 sensor(es)`).
3. **Cliente.** Monta pacotes CBOR idênticos aos do ESP32 (id, timestamp atual, leitura crescente, assinatura PKCS#1 v1.5 + SHA-256 de `"id|ts|leitura"`, proof) e envia 50 pacotes por cenário via UDP. O **desfecho de cada pacote é lido do stdout do controlador**, que é a fonte da verdade, e não inferido pelo cliente.

### 4.2 Resultados

| Fase | Acumulador | Cenário | Sensor | Proof | Enviados | Aceitos | Rejeitados | Camada de bloqueio | t̄ / mediana no controlador (ms) | Esperado |
|---|---|---|---|---|---:|---:|---:|---|---:|:---:|
| 1 | A1 | F1-A: legítimo | ESP-42 | A1 (1064 B) | 50 | **50 (100%)** | 0 | — | 6,09 / 4,93 | ✅ |
| 1 | A1 | F1-B: legítimo *(controle adicional)* | ESP-02 | A1 (551 B) | 50 | **50 (100%)** | 0 | — | 4,92 / 3,86 | ✅ |
| 2 | — | TMC revoga ESP-42 → A2 e atualiza a witness de ESP-02 | — | — | — | — | — | — | delete 6,52 · upd 3,71 · PoE 3,27 | — |
| 3 | A2 | F3-A: **revogado**, assinatura RSA legítima + proof antiga | ESP-42 | A1 (1064 B) | 50 | 0 | **50 (100%)** | **V03 aritmética** (passou V01, V01b e V02) | 7,04 / 5,62 | ✅ |
| 3 | A2 | F3-B: witness **desatualizada** | ESP-02 | A1 (551 B) | 50 | 0 | **50 (100%)** | **V03 aritmética** | 4,89 / 3,85 | ✅ |
| 3 | A2 | F3-C: witness **atualizada** | ESP-02 | A2 (551 B) | 50 | **50 (100%)** | 0 | — | 4,76 / 3,78 | ✅ |
| 4 | A3 | F4-A: **novo sensor** | ESP-99 | A3 (551 B) | 50 | **50 (100%)** | 0 | — | 4,83 / 3,94 | ✅ |
| 4 | A3 | F4-B: witness atualizada para A3 | ESP-02 | A3 (550 B) | 50 | **50 (100%)** | 0 | — | 4,86 / 3,89 | ✅ |
| 4 | A3 | F4-C: witness de A2 *(controle adicional)* | ESP-02 | A2 (551 B) | 50 | 0 | **50 (100%)** | **V03 aritmética** | 5,05 / 4,19 | ✅ |
| 4 | A3 | F4-D: revogado *(controle adicional)* | ESP-42 | A1 (1064 B) | 50 | 0 | **50 (100%)** | **V03 aritmética** | 5,28 / 4,29 | ✅ |

O tempo no controlador inclui o decode CBOR externo, as verificações V01, V01b e V02 (RSA-2048) e a V03 completa. A fase 2 mostra os tempos do TMC, em ms, para uma única execução.

**Resumo do controlador por fase:**

| Fase | Recebidos | Aceitos | V03 aritmética | Outras camadas | Perdidos | RAM do processo (mín.–máx.) |
|---|---:|---:|---:|---:|---:|---|
| 1 (A1) | 100 | 100 | 0 | 0 | 0 | 7,24–22,50 MB |
| 3 (A2) | 150 | 50 | 100 | 0 | 0 | 7,25–7,31 MB |
| 4 (A3) | 200 | 100 | 100 | 0 | 0 | 7,25–7,31 MB |

O pico de 22,5 MB na fase 1 é o *working set* reportado pelo Windows (via `sysinfo`), que oscila com a paginação do SO. Nas fases 3 e 4, com o mesmo código, a RAM ficou estável em ~7,3 MB.

Nenhum pacote foi rejeitado por outra camada (V01, V01b, V02, V03 sintática ou C00), e não houve gaps de sequência. Os cenários isolam exatamente o efeito do acumulador.

Os controles adicionais (F1-B, F4-C, F4-D) não estavam no roteiro mínimo e foram incluídos para fortalecer a conclusão. F1-B mostra que a proof de ESP-02 usada em F3-B era válida em A1. F4-C mostra que **até uma adição** invalida as witnesses antigas. F4-D mostra que o revogado continua barrado após o join.

---

## 5. Análise técnica (para o TCC e para os revisores)

### 5.1 Comprovação empírica da verificação em tempo constante O(1)

- Entre N=10 e N=1000, a mediana de `verify_membership` foi de 3,08 para 3,22 ms (**razão 1,05×**), enquanto o custo de construir o acumulador cresceu **110×** (15,1 → 1.664,9 ms). As medianas oscilam entre 3,1 e 4,0 ms **sem tendência** com N: o valor de N=100 é o maior e o de N=1000 está entre os menores. A oscilação vem de ruído do SO e não do tamanho da rede.
- A razão teórica é que a verificação calcula Q^ℓ · w^(H(id) mod ℓ) e compara com A. Os expoentes são sempre primos de **256 bits**, e os operandos, elementos de **2048 bits**, qualquer que seja N. O custo é ~2 `hash_to_prime` + ~2 exponenciações de 256 bits. Isso bate com as primitivas medidas (0,68 + 0,73 ms de mediana cada), que somam ~3 ms.
- **O estado do controlador também é O(1):** um único valor de 531 bytes (`accumulator.dat`) para 10 ou 1000 sensores. O pacote do sensor não cresce com a rede: a proof tem 550 ou 1064 bytes, conforme o ID e não conforme N.
- No controlador real (Parte B), a verificação completa com RSA-2048 e CBOR ficou em **~3,8–5,6 ms de mediana** nesta máquina. O primeiro pacote de cada execução é mais lento (~33 ms) por efeito de cache frio.

### 5.2 Custo real de adição × revogação × atualização de witness

| Operação (1 evento) | Onde executa | Custo (mediana) | Escala com N |
|---|---|---|---|
| Adicionar sensor (`add`) | TMC | 1,6–1,8 ms | constante |
| Proof do novo sensor | TMC | 3,9–4,9 ms | constante |
| Revogar sensor (`delete`) | TMC | 2,4–2,8 ms | constante |
| Atualizar 1 witness (join) | TMC | 2,4–2,9 ms | constante |
| Atualizar 1 witness (revogação) | TMC | 3,3–3,8 ms | constante |
| Nova PoE de 1 sensor | TMC | 4,2–5,0 ms | constante |
| **Atualizar toda a rede** (join) | TMC | ~2,6 ms × N → **2,57 s** (N=1000) | **linear** |
| **Atualizar toda a rede** (revogação) | TMC | ~3,4 ms × (N−1) → **3,39 s** (N=1000) | **linear** |
| Recalcular todas as witnesses do zero (RootFactor) | TMC | **11,2 s** (N=1000) | O(N log N) |
| Verificar um pacote | Controlador | ~3,2 ms | **constante** |
| Operação no ESP32 | Sensor | **nenhuma**: apenas troca a proof armazenada | — |

Observações:

- **A revogação é ~1,5× mais cara que a adição** por witness atualizada (≈3,5 vs ≈2,5 ms). Na adição, a atualização é uma única exponenciação (w' = w^H(x)). Na deleção, é preciso resolver Euclides estendido e fazer duas exponenciações (w^b · A'^a), e o coeficiente negativo exige ainda uma inversão modular.
- O `delete` em si é barato (~2,5 ms) porque, para um único elemento, a biblioteca só confere a witness (w^H(x) = A) e adota w como novo acumulador.
- **Atualizar witness por witness é ~4× mais barato que recalcular tudo com RootFactor** (2,6–3,4 s vs 11,2 s para N=1000). Para eventos isolados, a atualização incremental é a estratégia certa no TMC.
- **Arquitetura:** todo o custo O(N) fica no **TMC, offline**, onde há CPU e energia de sobra. O controlador apenas troca um valor escalar A, e o ESP32 não executa nenhuma operação do acumulador: recebe a nova `MembershipProof` (≈0,5–1 KB) e passa a enviá-la. No pior caso medido (revogação com N=1000), o TMC leva ~3,4 s **nesta CPU de baixo consumo** para preparar as novas proofs de toda a rede.

### 5.3 Defesa contra o sensor revogado (Fase 3)

O cenário F3-A modela um sensor **comprometido ou descomissionado cuja chave privada continua válida**: os pacotes do ESP-42 têm timestamp atual, não são duplicados e **são assinados com a chave RSA legítima**. Por isso passam em V01, V01b e V02. Ainda assim, **100% foram rejeitados na V03 aritmética**, porque a proof antiga não verifica contra A2.

O acumulador entrega o seguinte além da assinatura pura:

1. **Revogação por troca de um único valor.** O único dado alterado no controlador foi o arquivo do acumulador (531 bytes). **O `HashMap` de chaves públicas não foi modificado**, o ESP-42 continuou cadastrado, e não houve distribuição de CRL nem consulta OCSP. Num ITS com vários controladores (RSUs/cruzamentos), revogar equivale a difundir um valor de tamanho constante, autenticável pelo TMC. A alternativa seria editar a base de chaves de cada controlador ou manter uma lista de revogação que cresce com o tempo.
2. **Separação entre autenticação e autorização.** A assinatura RSA prova *quem* enviou; o acumulador prova que esse remetente *ainda pertence ao conjunto autorizado no estado atual*. Uma chave vazada ou um sensor descomissionado deixa de ser aceito assim que A muda, mesmo que a chave continue "válida".
3. **Estado mínimo no controlador.** O controlador não precisa conhecer o conjunto de sensores autorizados, só o valor A.

**Leitura honesta:** neste protótipo, com um único controlador, **remover a chave do ESP-42 do `HashMap` também bloquearia o sensor**, só que já na V02 e com menos custo. O ganho do acumulador é **operacional e de escala**: revogação com estado de tamanho constante, distribuível a muitos verificadores, sem listas crescentes e sem precisar administrar a base de chaves de cada controlador. Os dois mecanismos são complementares.

---

## 6. Limitações e trade-offs observados

1. **Toda mudança em A invalida todas as witnesses, inclusive na adição.** Os cenários F3-B (após revogação) e F4-C (após *join*) provam que um sensor legítimo com witness desatualizada é rejeitado (100%). Depois de cada evento, o TMC precisa recalcular (O(N), seção 5.2) **e redistribuir** a nova proof aos N−1 sensores remanescentes. O canal de distribuição (OTA, MQTT, provisionamento) **não foi implementado nem medido** neste experimento: as proofs foram entregues por arquivo. Hoje o firmware traz a proof embutida, então uma atualização em campo exige esse canal.
2. **Janela de inconsistência.** Entre o TMC gerar o novo A e todos os sensores receberem as novas proofs, os legítimos ainda não atualizados são rejeitados, o que afeta a disponibilidade. Do lado do controlador, enquanto ele não carregar o novo A, o revogado continua aceito. Hoje o `udp_controller` lê o A **na inicialização**; **recarga a quente** e versionamento/época de A ficam como trabalho futuro. Algumas mitigações possíveis: agrupar revogações por época e aceitar A_anterior por um período de graça. Esta última reabre a janela para o revogado e precisa ser ponderada.
3. **Deleção sem trapdoor exige estado no TMC.** O `delete` da Cambrian precisa da witness do sensor removido, ou do conjunto completo para reconstruir A (~1,7 s para N=1000 nesta máquina). Portanto o TMC deve manter as witnesses atuais de todos os sensores. A vantagem é não haver segredo a proteger, já que a fatoração do módulo RSA-2048 do desafio é desconhecida.
4. **A API não tem atualização em lote de witnesses distintas.** O "lote" medido é um laço de N chamadas a `update_membership_witness`. A outra opção é o `compute_individual_witnesses` (RootFactor), que recalcula tudo do zero e foi ~4× mais lento para N=1000.
5. **Cuidados da biblioteca:** o acumulador se comporta como **multiconjunto**, então adicionar o mesmo ID duas vezes faz um `delete` remover apenas uma cópia. Cabe ao TMC garantir IDs únicos. A própria biblioteca se declara *research-grade*, sem auditoria independente.
6. **PoE trivial para um único elemento.** Como o expoente é um único primo de 256 bits, a PoE de Wesolowski não reduz o custo da verificação: Q vale 1 ou w. O tamanho da proof é bimodal (550/1064 B) conforme o ID. Isso não afeta a correção nem a constância O(1), mas vale registrar no texto.
7. **Validade dos números:**
   - Medições num PC Windows (Celeron N3350), não no Raspberry Pi 3B+.
   - A Parte B usou loopback, sem rádio ou Wi-Fi real; latência e perda de rede não foram exercitadas.
   - As operações pesadas tiveram só 5 repetições (p95 = máximo).
   - Picos isolados do SO elevam médias e desvios em N=10; as medianas são robustas.
8. **Possível evolução (não medida):** como a atualização de witness usa apenas dados públicos (novo A e ID afetado), o próprio sensor poderia atualizar sua witness ao receber esse *delta* por broadcast, em vez de cada sensor receber uma proof individual. Isso troca a distribuição O(N) individualizada por um broadcast O(1), ao custo de ~2 exponenciações de 2048 bits e um `hash_to_prime` no ESP32. A viabilidade no ESP32 precisa ser medida.

---

## 7. Reprodução (inclusive no Raspberry Pi 3B+)

O Raspberry Pi não compila o projeto. Os binários aarch64 são gerados neste PC (via WSL2, scripts em `scripts/`) e copiados para o Pi.

```bash
# Neste PC (Windows + MSYS2 UCRT64)
cargo +stable-x86_64-pc-windows-gnu build --release --features system-gmp \
    --bin udp_controller --bin dynamic_bench --bin dynamic_tmc --bin dynamic_e2e
./target/release/dynamic_bench --ns 10,50,100,500,1000 --reps 20 --heavy-reps 5 \
    --verify-reps 200 --out logs_dinamicidade/resultados_dinamicidade.json
./target/release/dynamic_tmc                              # gera target/e2e_dinamicidade/
./target/release/dynamic_e2e --host 127.0.0.1 --packets 50

# Cross-compilação para o Pi (dentro do WSL2 Debian; uma vez):
bash scripts/setup_wsl_cross.sh        # como root
bash scripts/cross_build_rpi.sh        # gera dist/rpi-aarch64/

# No Raspberry Pi (copiar dist/rpi-aarch64/ e target/e2e_dinamicidade/):
./dynamic_bench --reps 20 --heavy-reps 5 --out resultados_dinamicidade_rpi.json
./udp_controller --acc target/e2e_dinamicidade/accumulator_A1.dat \
    --pubkey ESP-02=target/e2e_dinamicidade/keys/ESP_02.pub.pem \
    --pubkey ESP-99=target/e2e_dinamicidade/keys/ESP_99.pub.pem --max-packets 100
#   (fases 3 e 4: accumulator_A2.dat com --max-packets 150; accumulator_A3.dat com 200)

# Neste PC, via Wi-Fi, com o controlador rodando no Pi:
./target/release/dynamic_e2e --host <IP_DO_PI> --no-spawn --packets 50
```

## 8. Arquivos gerados

| Arquivo | Conteúdo |
|---|---|
| `dynamic_bench.log` | Saída completa do benchmark (Parte A) |
| `resultados_dinamicidade.json` | Todas as amostras brutas + estatísticas + especificação da máquina |
| `e2e_tmc.log` | Saída do TMC: geração de A1/A2/A3, tempos e checagens |
| `e2e_controller.log` | Stdout completo do `udp_controller` nas fases 1, 3 e 4 (cada pacote + resumo da sessão) |
| `e2e_client.log` | Stdout do cliente de testes `dynamic_e2e` |
| `resultados_e2e.json` | Desfecho por cenário (camada de bloqueio, aceitação, tempos) |

## 9. Alterações de código feitas nesta branch

- **Novos binários:** `src/bin/dynamic_bench.rs` (Parte A), `src/bin/dynamic_tmc.rs` (TMC da Parte B) e `src/bin/dynamic_e2e.rs` (cliente e orquestrador da Parte B, escrito em Rust porque o PC não tinha Python na época).
- **`interfaceCBOR/main.rs`:** novas flags opcionais `--acc`, `--pubkey ID=arquivo.pem`, `--bind` e `--max-packets`. **Sem flags, o comportamento é idêntico ao original**, e a chave embutida do ESP-42 continua sempre cadastrada.
- **`Cargo.toml`:**
  - registro dos 3 binários; `serde_json`; feature `getrandom` do `rsa` (geração das chaves de teste);
  - `rug` restrito a `integer` e `gmp-mpfr-sys` sem MPFR/MPC e com `c-no-tests`, porque o código só usa `rug::Integer` e isso corta horas do build da biblioteca C;
  - nova feature opcional `system-gmp`.
- **`src/uint.rs`:** portabilidade para Windows. O `mp_size_t`/`unsigned long` da GMP tem 32 bits no Windows e 64 no Linux; o código fixava `i64`/`u64` e por isso nunca tinha compilado no Windows. Agora usa os tipos da própria GMP (`gmp::size_t`). **No Linux/Pi não há mudança de comportamento.** Os **65 testes unitários da biblioteca passaram** (`cargo test --release --lib`).
- **`scripts/setup_wsl_cross.sh`, `scripts/cross_build_rpi.sh`, `.gitattributes`** (LF nos `.sh`) e `dist/` no `.gitignore`.
