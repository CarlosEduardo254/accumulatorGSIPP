# Acumulador Criptográfico × Somente Assinatura Digital — Relatório Comparativo

**Projeto:** TCC — Arquitetura GSIPP para autenticação de sensores em ITS
**Data das coletas:** 18–19/11/2026 (desempenho) · 09/09/2026 (bateria de ataques)
**Hardware:** ESP32 + EBYTE E49-400T20D (433 MHz, GFSK, UART 115200) → Raspberry Pi 3B+ (`/dev/serial0`)

---

## 1. Resumo

Este relatório compara duas versões do protocolo de autenticação de sensores:

- **Completo (com acumulador):** assinatura RSA-2048 (V02) + prova de pertencimento ao acumulador RSA com PoE de Wesolowski (V03). Pacote CBOR de 5 campos.
- **Baseline (somente assinatura):** a mesma assinatura RSA-2048, sem a V03. Pacote CBOR de 4 campos.

Principais conclusões:

1. **O acumulador acrescenta uma garantia que a assinatura sozinha não oferece.** Com ele, possuir a chave de assinatura de um sensor deixa de bastar para ser aceito: também é preciso uma credencial de pertencimento válida, emitida pela autoridade e revogável. Na bateria de ataques, **300 de 300 pacotes com assinatura RSA válida, mas proof inválida, foram rejeitados pela V03** (S1–S3). No baseline, esses pacotes passariam por todas as verificações existentes.
2. **O custo é mensurável, mas viável.** A verificação no Raspberry Pi 3B+ sobe de 5,3 ms para 33,6 ms por pacote (+28,3 ms). Mesmo assim, um único núcleo do Pi verifica cerca de 30 pacotes/s, o suficiente para cerca de 119 sensores enviando a cada 4 s.
3. **O maior custo está no enlace de rádio, não na CPU.** A proof acrescenta 1.064 B (o pacote vai de 282 B para 1.351 B, 4,8×), o que exige 7 quadros em vez de 1 e aumenta a latência fim a fim em cerca de 1,9 s.
4. **A confiabilidade não foi afetada de forma estatisticamente significativa.** PER de 0,79% (2/253) no completo contra 0% (0/401) no baseline, com p = 0,15 no teste exato de Fisher.
5. **Há uma otimização direta para reduzir esse custo.** A proof é serializada como texto hexadecimal. A codificação binária reduziria a proof para cerca de 540 B e o pacote para cerca de 820 B (seção 6.2).

---

## 2. Desenho experimental

### 2.1 Versões comparadas

| | Completo | Baseline |
|---|---|---|
| Branch | `comunicacao-radio` | `baseline-radio-signature-only` |
| Campos CBOR | 1 id · 2 timestamp · 3 dado · 4 assinatura · **5 MembershipProof** | 1 id · 2 timestamp · 3 dado · 4 assinatura |
| Verificações | C00 · V01 · V01b · V02 · **V03 (sintática + aritmética)** | C00 · V01 · V01b · V02 |
| Estado no controlador | chaves públicas + `accumulator.dat` (531 B) | chaves públicas |
| Fragmentação | 200 B/fragmento → 7 quadros | 400 B/fragmento → 1 quadro |

Etapas de verificação: C00 = decodificação do CBOR externo; V01 = janela de timestamp (5 s); V01b = deduplicação anti-replay; V02 = assinatura RSA-2048 (PKCS#1 v1.5 + SHA-256); V03 = MembershipProof (`witness^H(id) ≡ acc mod N` + PoE de Wesolowski).

### 2.2 Coletas

| Coleta | Enlace | Pacotes | Duração | Arquivo |
|---|---|---|---|---|
| Completo | Rádio E49 | 253 enviados / 251 recebidos | 26,9 min | `completo_radio_rpi.log` |
| Baseline | Rádio E49 | 401 / 401 | 29,0 min | `baseline_radio_rpi.log`, `esp_baseline_radio_rpi.log` |
| Baseline (referência) | Wi-Fi/UDP | 100 / 100 | 5,3 min | `log_controlador_assinatura.log` |
| Bateria de ataques (completo) | Wi-Fi/UDP | 700 | — | `teste_100x.log`, `resultados_teste.json` |
| Bateria de ataques (baseline) | UDP local | 504 | — | `resultados_baseline.json` |

As duas coletas de rádio foram feitas no mesmo dia, com o mesmo hardware, a mesma posição das antenas, o mesmo intervalo de envio (4 s) e o mesmo procedimento.

### 2.3 Testes estatísticos

- **Tempos e latências:** teste U de Mann-Whitney, bilateral (os tempos não seguem distribuição normal).
- **PER:** teste exato de Fisher, com intervalos de confiança de Clopper-Pearson a 95%.

---

## 3. Resultados de desempenho

### 3.1 Tabela geral (enlace de rádio)

| Métrica | Completo | Baseline | Diferença |
|---|---|---|---|
| Tamanho do pacote CBOR (B) | 1.350,9 | 282,3 | +1.068,6 B (4,79×) |
| — dos quais: MembershipProof (B) | 1.064 | — | 78,8% do pacote completo |
| Quadros de rádio por pacote | 7 | 1 | +6 |
| Verificação no RPi — média (ms) | **33,556** | **5,290** | +28,27 ms (6,34×) |
| Verificação no RPi — mediana (ms) | 33,001 | 5,306 | +27,70 ms |
| Verificação no RPi — desvio (ms) | 2,530 | 0,373 | — |
| Verificação no RPi — p95 (ms) | 38,465 | 5,797 | — |
| RSS do controlador — média (MB) | 2,86 | 2,41 | +0,45 MB (+18,7%) |
| Δ de timestamp (V01) — média (s) | 2,594 | 0,718 | +1,876 s |
| Período real entre envios no ESP32 (s) | 6,404 | 4,348 | +2,056 s |
| PER | 0,79% (2/253) | 0,00% (0/401) | p = 0,15 (n.s.) |
| Rejeições indevidas de pacotes legítimos | 0 | 0 | — |

### 3.2 Tempo de verificação no controlador

- A V03 custa **cerca de 28,3 ms por pacote**, que correspondem a **84% do tempo total** de verificação do protocolo completo. O restante (C00 + V01 + V01b + V02) é idêntico nas duas versões, cerca de 5,3 ms.
- A diferença é estatisticamente inequívoca: Mann-Whitney com z = 21,5, p ≈ 10⁻¹⁰². Todos os 251 pacotes do completo levaram mais tempo que qualquer pacote do baseline.
- O tempo é estável: desvio de 2,5 ms e p95 de 38,5 ms. Dois pacotes do completo (#67 e #200) levaram cerca de 16,2 ms. Eles não coincidem com perdas no rádio e não alteram a mediana.
- **O enlace não interfere no custo criptográfico.** O baseline levou 5,290 ms no rádio e 5,396 ms no Wi-Fi, diferença sem significância estatística (p = 0,06).

**Capacidade de um controlador** (um núcleo, só o tempo de verificação):

| | Pacotes/s | Sensores suportados (envio a cada 4 s) |
|---|---|---|
| Completo | ≈ 29,8 | ≈ 119 |
| Baseline | ≈ 189,0 | ≈ 756 |

O Raspberry Pi 3B+ tem 4 núcleos e o controlador atual usa apenas um. Paralelizar a verificação multiplicaria essa capacidade.

### 3.3 Memória do controlador

O RSS ficou estável nas duas versões durante cerca de 27–29 minutos:

- completo: de 2,83 para 2,87 MB;
- baseline: de 2,39 para 2,42 MB.

O acréscimo de 0,45 MB do completo vem da biblioteca do acumulador e do estado carregado de `accumulator.dat`. Esse arquivo tem 531 B e **não cresce com o número de sensores** (seção 5.3). Não há indício de vazamento de memória em nenhuma das versões.

### 3.4 Latência fim a fim e ocupação do canal

O timestamp do ESP32 tem resolução de 1 s. Por isso a latência é estimada pelo Δ inteiro da V01 (recepção − envio). Esse valor inclui os cerca de 198 ms da assinatura, a UART, o tempo no ar e a diferença entre os relógios do ESP e do Pi, sincronizados por NTP.

- Completo: Δ = 2 s em 102 pacotes e 3 s em 149 (média 2,594 s).
- Baseline: Δ = 0 s em 113 pacotes e 1 s em 288 (média 0,718 s).
- A diferença de **cerca de 1,9 s** é significativa (p ≈ 10⁻¹¹⁴). Ela equivale aos cerca de 1.100 B a mais transmitidos, numa taxa efetiva estimada de cerca de 4,8 kbps no enlace.

O mesmo efeito aparece no ESP32. A fase de envio passa de cerca de 0,15 s para cerca de 2,2 s por pacote, porque o firmware espera o pino AUX liberar entre fragmentos. Com isso o período real entre envios sobe de 4,35 s para 6,40 s.

**No rádio, o custo do acumulador é principalmente de tempo no ar.**

### 3.5 Confiabilidade do enlace (PER)

| | Perdas | PER | IC 95% |
|---|---|---|---|
| Completo (pacotes) | 2/253 | 0,79% | [0,10%; 2,83%] |
| Completo (fragmentos) | 2/1.771 | 0,11% | [0,01%; 0,41%] |
| Baseline (pacotes) | 0/401 | 0,00% | [0,00%; 0,92%] |

- As duas perdas do completo têm a mesma causa. Um fragmento chegou truncado (154 B), gerou erro de COBS e o pacote correspondente expirou na remontagem com 6 de 7 fragmentos (pacotes #140 e #187).
- **A diferença de PER não é estatisticamente significativa** (Fisher, p = 0,15).
- Mesmo assim, o resultado é coerente com a física do enlace. Se a probabilidade de erro por byte fosse a mesma nas duas versões, o baseline teria PER esperado de cerca de 0,17%, ou cerca de 0,7 perdas em 401 pacotes. Observar zero perdas nessa situação tem 51% de chance.
- Conclusão: o acumulador aumenta a exposição a perdas na proporção dos bytes transmitidos, mas, neste enlace, essa exposição é baixa (PER abaixo de 1%) e **nenhum pacote legítimo foi rejeitado pelas verificações criptográficas**.

### 3.6 Processamento no ESP32

- Baseline: 198,2 ± 1,0 ms (mediana 198 ms), sem contar o primeiro pacote, que levou 489 ms por aquecimento.
- Completo: **não medido nesta sessão**, porque o log do monitor serial ficou vazio.

Por construção, a diferença esperada é desprezível. A assinatura é idêntica nas duas versões, e a proof é uma constante gravada na flash, copiada para o buffer CBOR (cerca de 1 KB de `memcpy`, na ordem de microssegundos). O custo do acumulador no sensor fica no **tamanho do pacote e no tempo de transmissão**, não na CPU.

---

## 4. Resultados de segurança

### 4.1 Bateria de ataques

Os pacotes de ataque são assinados com a **chave privada legítima do ESP-42**, exceto no S4. Isso simula um atacante que extraiu ou clonou a chave de assinatura de um dispositivo.

| ID | Cenário | Assinatura | Completo | Baseline |
|---|---|---|---|---|
| B1 | Pacote legítimo | válida | ✅ aceito | ✅ aceito |
| S1 | Proof forjada (bytes aleatórios) | **válida** | ⛔ **rejeitado na V03** (100/100) | ⚠️ sem V03: o pacote equivale ao B1 e é aceito |
| S2 | Proof nula (0 B) | **válida** | ⛔ **rejeitado na V03** (100/100) | ⚠️ aceito |
| S3 | Proof adulterada (bit flip) | **válida** | ⛔ **rejeitado na V03** (100/100) | ⚠️ aceito |
| S5 | Proof válida de outro sensor (ESP-02) | **válida** | ⛔ rejeitado na V03 aritmética *(implementado, ainda não executado)* | ⚠️ aceito |
| S4 | Chave do atacante com ID clonado | inválida | ⛔ rejeitado na V02 (100/100) | ⛔ rejeitado na V02 (100/100) |
| R1 | Timestamp expirado | válida | ⛔ V01 (100/100) | ⛔ V01 (100/100) |
| R2 | Replay dentro da janela | válida | ⛔ V01b (100/100) | ⛔ V01b (100/100) |
| D1/D2 | Pacotes malformados / rajada | — | ⛔ C00 | ⛔ C00 (104/104) |

No baseline, os cenários S1, S2, S3 e S5 foram desativados porque não existe campo "5". Isso não é uma limitação do teste. Sem esse campo, o pacote de ataque desses cenários fica idêntico a um pacote legítimo assinado com a chave do ESP-42, e é **aceito**. Para o controlador baseline, ter a chave privada é condição **suficiente** para se passar pelo sensor.

### 4.2 Interpretação

| Propriedade | Completo | Baseline |
|---|---|---|
| Autenticidade e integridade da mensagem | ✅ V02 | ✅ V02 |
| Proteção contra replay | ✅ V01/V01b | ✅ V01/V01b |
| Autorização: o sensor pertence ao conjunto ativo? | ✅ V03 | ❌ limitada à presença da chave na tabela do controlador |
| Ter a chave de assinatura basta para ser aceito? | ❌ não: também é preciso uma proof válida para aquele ID | ✅ sim |
| Proof vinculada à identidade | ✅ `H(id)` entra na verificação; a proof de outro sensor falha | — |

Observação: a proof não é secreta, porque viaja em claro em cada pacote. A proteção da V03 não vem de esconder a proof. Vem do **vínculo criptográfico entre a identidade e o valor atual do acumulador**, que só a autoridade de registro pode alterar. É isso que torna possível a **revogação** (seção 5.1).

---

## 5. Vantagens do acumulador sobre somente assinatura

### 5.1 Revogação de sensores com um único valor público

Quando um sensor é comprometido, removido ou desativado, a autoridade remove o ID dele do acumulador e publica o novo valor, de tamanho constante (≈ 256 B de elemento do grupo RSA-2048; 531 B serializado). A partir daí, **a witness antiga do sensor revogado deixa de satisfazer `witness^H(id) ≡ acc`**, mesmo que o atacante tenha a chave privada e uma proof capturada do ar. A biblioteca usada já implementa essas operações:

- `Accumulator::delete` / `delete_with_proof`: remoção de membros;
- `update_membership_witness`: atualização das witnesses dos sensores que continuam no conjunto;
- `prove_nonmembership` / `verify_nonmembership`: prova de não pertencimento (por exemplo, para listas de bloqueio).

No baseline, revogar exige remover a chave de **cada** controlador e manter essa lista sincronizada. Com várias RSUs ou controladores, isso vira uma lista de revogação (CRL) que cresce com o número de sensores.

### 5.2 Defesa em profundidade: dois fatores independentes

O protocolo completo exige **duas credenciais de naturezas diferentes**:

1. a **chave privada** do dispositivo, que prova autoria (V02);
2. a **credencial de pertencimento**, emitida e revogável pela autoridade, que prova autorização (V03).

O resultado de 300/300 rejeições em S1–S3, todos com assinatura válida, mostra que a V03 funciona como barreira independente. No baseline, a mesma situação significa comprometimento total.

### 5.3 Estado de pertencimento de tamanho constante

O que o controlador precisa saber para decidir se o sensor pertence ao conjunto é **um único valor de 531 B**, seja o conjunto de 3 sensores (como hoje: ESP-01, ESP-02 e ESP-42) ou de milhares. O custo da verificação também não depende do número de membros: o PoE de Wesolowski verifica a exponenciação em tempo constante.

No protótipo atual, o controlador ainda guarda as chaves públicas para a V02. A evolução natural é acumular `H(id ‖ chave pública)`. Assim o sensor envia a própria chave junto com a proof, e o controlador passa a depender **apenas** do valor do acumulador. Isso torna os verificadores praticamente sem estado (*stateless*) e fáceis de replicar em várias RSUs.

### 5.4 Custo previsível e viável

- A V03 adiciona **28 ms por pacote** com baixa variação (desvio de 2,5 ms) e sem rejeições indevidas.
- A memória adicional é de **0,45 MB** e permaneceu estável durante quase 30 minutos de operação.
- O overhead de rede é **fixo** (1.064 B) e não cresce com o número de sensores.
- Para cenários ITS com envios na ordem de segundos, um Raspberry Pi 3B+ de baixo custo atende cerca de 119 sensores por núcleo só com a verificação.

### 5.5 Provas agregadas

A biblioteca oferece `add_with_proof` e `verify_membership_batch` para **uma única prova agregada de vários elementos**. Por exemplo, um gateway poderia provar de uma vez o pertencimento de vários sensores que ele agrega. Esse recurso não foi explorado neste experimento, e a aplicação à arquitetura GSIPP ainda precisa ser avaliada.

---

## 6. Vantagens da assinatura sozinha e como reduzi-las

### 6.1 O que o baseline faz melhor

| Aspecto | Vantagem do baseline |
|---|---|
| Tamanho do pacote | 4,8× menor (282 B contra 1.351 B) e cabe em 1 quadro de rádio |
| Latência fim a fim | cerca de 1,9 s menor no rádio E49 |
| Ocupação do canal (433 MHz) | cerca de 4,7× menos bytes no ar por pacote (≈ 298 B contra ≈ 1.412 B, já com o enquadramento), com menos colisões e mais folga para limites de *duty cycle* |
| Verificação | 6,3× mais rápida (5,3 ms contra 33,6 ms) |
| Memória | 0,45 MB a menos no controlador |
| Exposição a perdas | menos bytes no ar, portanto menor probabilidade de perder um fragmento |
| Simplicidade | não exige *trusted setup*, emissão e atualização de witnesses nem autoridade de registro |
| Energia no sensor *(não medida)* | menos tempo de transmissão tende a reduzir o consumo do rádio |

### 6.2 Como reduzir o custo do acumulador

1. **Serializar a proof em binário.** A `MembershipProof` é serializada hoje com os elementos do grupo como **texto hexadecimal**: a witness e o `Q` do PoE ocupam 512 caracteres cada (cabeçalho CBOR `0x79 0x0200`). Em binário, cada um ocupa 256 B. A proof cairia de **1.064 B para cerca de 540 B**, e o pacote para **cerca de 820 B**. Isso reduz pela metade o overhead de rede e o tempo no ar, sem nenhuma perda de segurança.
2. **Usar fragmentos de 400 B também no completo.** O completo usou 200 B por fragmento, o baseline 400 B. Com 400 B, o pacote atual iria em 4 quadros. Com a proof binária, iria em 3 quadros, ou 2 com fragmentos de cerca de 410 B.
3. **Verificar em paralelo** no controlador, usando os 4 núcleos do Pi, para multiplicar a capacidade da seção 3.2.
4. **Enviar a proof com menos frequência.** Por exemplo, a cada N pacotes ou só quando o acumulador for atualizado, com os pacotes intermediários autenticados apenas pela assinatura dentro de uma sessão já validada.

---

## 7. Limitações e próximos passos

| Item | Situação | Recomendação |
|---|---|---|
| Experimento de revogação | **Não executado.** A vantagem central (5.1) está argumentada, mas não medida. | Remover o ESP-42 com `delete` (ou gerar um `accumulator.dat` sem ele) e mostrar que pacotes com assinatura válida passam a ser rejeitados na V03 aritmética, enquanto ESP-01 e ESP-02 continuam aceitos. **É a evidência mais forte para o TCC.** |
| Cenário S5 | Implementado no `attack_tests.py`, sem execução registrada | Rodar `--test spoofing` contra o controlador completo |
| Bateria de ataques | Executada em 09/09, com versão anterior do controlador e via Wi-Fi | Repetir com o código atual |
| Processamento no ESP32 (completo) | Log do monitor serial vazio | Recapturar cerca de 50 pacotes (≈ 5 min) só com o ESP |
| Fragmentação diferente (200 B × 400 B) | Contribui para a diferença no número de quadros | Repetir o completo com `FRAG_SIZE = 400` |
| Latência com resolução de 1 s | Permite comparar as versões, mas não dá o valor absoluto | Medir no controlador o tempo do primeiro byte até a remontagem, em ms |
| Energia no ESP32 | Não medida | Medir a corrente média por ciclo nas duas versões |
| Amostra do completo | 253 pacotes (o planejado eram 401) | Suficiente para tempos e RSS; para o PER, o IC fica em [0,10%; 2,83%] |

---

## 8. Conclusão

Os dados mostram um compromisso claro:

- **o baseline é mais leve** em todas as métricas de desempenho, sobretudo no enlace de rádio;
- **o acumulador entrega uma garantia que a assinatura sozinha não oferece**: a autorização de pertencimento, revogável e vinculada à identidade, verificada contra um único valor público de tamanho constante.

Na bateria de ataques, 300 de 300 pacotes com assinatura legítima e credencial de pertencimento inválida foram bloqueados apenas pela V03. No baseline, esses pacotes não seriam bloqueados por nenhuma verificação.

O preço dessa garantia (28 ms de verificação, 0,45 MB de memória e cerca de 1 KB por pacote) é compatível com um controlador de baixo custo e não comprometeu a confiabilidade do enlace (PER abaixo de 1%, diferença sem significância estatística). Esse preço também pode ser reduzido pela metade no rádio com a serialização binária da proof.

Para sistemas ITS com muitos sensores, vários verificadores e necessidade de revogação, o acumulador é a abordagem mais adequada. A assinatura sozinha se justifica apenas em cenários pequenos, centralizados e sem exigência de revogação dinâmica.
