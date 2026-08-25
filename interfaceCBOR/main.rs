// ═══════════════════════════════════════════════════════════════════════
// Controller — Servidor de Verificação para ITS (Arquitetura TCC GSIPP)
// ═══════════════════════════════════════════════════════════════════════
//
// Fluxo de 3 verificações para cada pacote recebido de um sensor ESP32:
//   1. Timestamp (anti-replay): diferença máxima de 5s
//   2. Assinatura RSA-2048: SHA-256 + PKCS#1 v1.5
//   3. Acumulador criptográfico: verify_membership (Witness + PoE)
//
// Métricas de desempenho e resiliência:
//   - Tempo de verificação no controlador (ms)
//   - RAM consumida pelo processo (MB)
//   - Rastreamento de gaps de sequência e perdas de fragmentos
//   - Estatísticas de sessão em tempo real e no encerramento (Ctrl+C)
//
// Executar: cargo run --bin udp_controller --release

use accumulator::{group::Rsa2048, Accumulator, MembershipProof};
use anyhow::{Context, Result};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::System;

// ============================================
// CONFIGURAÇÕES
// ============================================

const SERIAL_PORT: &str = "/dev/serial0";
const BAUD_RATE: u32 = 115200;
/// Tolerância máxima de timestamp (em segundos) para proteção anti-replay
const REPLAY_WINDOW_SECS: u64 = 5;
/// Timeout de inatividade para descarte de fragmentos incompletos (em segundos)
const REASSEMBLY_TIMEOUT_SECS: u64 = 10;
/// Máximo de pacotes em reassembly simultâneo — limita alocação em caso de flood
const MAX_CONCURRENT_PACKETS: usize = 8;

// ============================================
// CHAVE PÚBLICA RSA-2048 DE TESTE
// ============================================
// Corresponde à chave privada embutida no ESP32.
// Gerada com: openssl pkey -in private.pem -pubout

const ESP42_PUBLIC_KEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4PP4AVHSx53z4n6beCvx
x+uJLPYUwYCa1tBj/uqzFN53RM4K97WykBKvcobUBztIlUx5hSkx1pMHb4gYsozz
pKe6bH15OPUER++LIvVmUWRYLGhXQr7ZoDbY8vCW33YrzQ+4JHI6L6eaN4efqG74
oDg1oarkXbqq2Gzu87PwBC8PaV5R7vdhuZP94bbGX9F9TWkGcfyhgKcVexkG+Rb6
RMAw03A1Xl05oMV62m5rfb4zHhyJUWVJRJNdTCqhjnzDyahWMzVQ2tff0BnIybGT
j8bWPgy8EwVUO3N2+EZ4TWpwYQXqNfqJnk/IcwHcRpLEjwBNdqxD53HlGprkbyNU
PQIDAQAB
-----END PUBLIC KEY-----";

// ============================================
// PAYLOAD CBOR — 5 campos
// ============================================

#[derive(Deserialize, Debug)]
struct Payload {
    /// Campo "1": ID do sensor
    #[serde(rename = "1")]
    id: String,

    /// Campo "2": Timestamp UNIX (segundos)
    #[serde(rename = "2")]
    timestamp: u64,

    /// Campo "3": Dado do sensor (counter)
    #[serde(rename = "3")]
    reading: u64,

    /// Campo "4": Assinatura digital RSA-2048 (256 bytes)
    #[serde(rename = "4", with = "serde_bytes")]
    signature: Vec<u8>,

    /// Campo "5": MembershipProof serializada (Witness + PoE)
    #[serde(rename = "5", with = "serde_bytes")]
    membership_proof: Vec<u8>,
}

// ============================================
// ESTATÍSTICAS DE SESSÃO
// ============================================

#[derive(Default, Debug)]
struct SessionStats {
    total_reconstructed: u64,
    accepted: u64,
    rejected_replay: u64,
    rejected_unknown_sensor: u64,
    rejected_invalid_sig: u64,
    rejected_invalid_proof: u64,
    corrupted_cbor: u64,
    reassembly_timeouts: u64,
    sequence_gaps: u64,
    total_verification_time_ms: f64,
    verification_count: u64,
}

impl SessionStats {
    fn print_summary(&self) {
        println!("\n═══════════════════════════════════════════════════════");
        println!("             📊 RESUMO DA SESSÃO — ITS GSIPP           ");
        println!("═══════════════════════════════════════════════════════");
        println!(" Total de pacotes remontados:      {}", self.total_reconstructed);
        println!(
            " ✅ Aceitos (3 etapas validadas):  {} ({:.1}%)",
            self.accepted,
            if self.total_reconstructed > 0 {
                (self.accepted as f64 / self.total_reconstructed as f64) * 100.0
            } else {
                0.0
            }
        );
        println!(" ❌ Rejeitados por Anti-Replay:    {}", self.rejected_replay);
        println!(" ❌ Rejeitados por Sensor Descon.: {}", self.rejected_unknown_sensor);
        println!(" ❌ Rejeitados por Assinatura RSA: {}", self.rejected_invalid_sig);
        println!(" ❌ Rejeitados por Prova Acumul.:  {}", self.rejected_invalid_proof);
        println!(" ❌ CBOR Corrompido / Inválido:    {}", self.corrupted_cbor);
        println!(" ⚠️ Pacotes incompletos (timeout): {}", self.reassembly_timeouts);
        println!(" ⚠️ Gaps de sequência detectados:  {}", self.sequence_gaps);

        let avg_time = if self.verification_count > 0 {
            self.total_verification_time_ms / self.verification_count as f64
        } else {
            0.0
        };
        println!(" ⏱️ Tempo médio verificação:       {:.3} ms", avg_time);
        println!("═══════════════════════════════════════════════════════\n");
    }
}

// ============================================
// DICIONÁRIO DE CHAVES PÚBLICAS — O(1)
// ============================================

/// Constrói o HashMap<sensor_id, RsaPublicKey> simulando o banco de dados
/// do controlador. Em produção, isso viria de um banco real ou arquivo de config.
fn build_key_store() -> HashMap<String, RsaPublicKey> {
    let mut store = HashMap::new();

    // Parsear a chave pública PEM do ESP-42
    let pub_key = RsaPublicKey::from_public_key_pem(ESP42_PUBLIC_KEY_PEM)
        .expect("Falha ao parsear chave pública PEM do ESP-42");

    store.insert("ESP-42".to_string(), pub_key);

    // ⚠️ Adicione mais sensores aqui conforme necessário:
    // store.insert("ESP-43".to_string(), outra_chave);

    store
}

// ============================================
// PROCESSAMENTO DO PACOTE — 3 VERIFICAÇÕES
// ============================================

fn process_packet(
    raw: &[u8],
    key_store: &HashMap<String, RsaPublicKey>,
    acc: &Accumulator<Rsa2048, String>,
    sys: &mut System,
    stats: &mut SessionStats,
    last_readings: &mut HashMap<String, u64>,
    replay_seen: &mut HashSet<(String, u64, u64)>,
) -> Result<()> {
    stats.total_reconstructed += 1;

    // --- Desserializar CBOR ---
    let payload: Payload = match serde_cbor::from_slice(raw) {
        Ok(p) => p,
        Err(e) => {
            stats.corrupted_cbor += 1;
            println!("❌ Erro ao desserializar CBOR: {:#}", e);
            return Ok(());
        }
    };

    println!("\n════════════════════════════════════════════════════");
    println!("📦 Pacote recebido de: {}", payload.id);
    println!("   Timestamp:  {}", payload.timestamp);
    println!("   Reading:    {}", payload.reading);
    println!("   Assinatura: {} bytes", payload.signature.len());
    println!("   Proof:      {} bytes", payload.membership_proof.len());

    // ──────────────────────────────────────────────────
    // DETECÇÃO DE GAP DE SEQUÊNCIA
    // ──────────────────────────────────────────────────
    if let Some(&prev_reading) = last_readings.get(&payload.id) {
        if payload.reading > prev_reading + 1 {
            let lost = payload.reading - prev_reading - 1;
            stats.sequence_gaps += lost;
            println!(
                "   ⚠️ ALERTA DE GAP: Sequência saltou de #{} para #{} ({} pacote(s) perdido(s) no rádio)",
                prev_reading, payload.reading, lost
            );
        } else if payload.reading <= prev_reading {
            println!(
                "   ⚠️ ALERTA DE SEQUÊNCIA: Leitura não-crescente (anterior: #{}, atual: #{})",
                prev_reading, payload.reading
            );
        }
    }
    last_readings.insert(payload.id.clone(), payload.reading);
    println!("════════════════════════════════════════════════════");

    // ════════════════════════════════════════════════════
    // INÍCIO DA MEDIÇÃO DE DESEMPENHO
    // ════════════════════════════════════════════════════
    let t_start = Instant::now();

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 01: Timestamp (Anti-Replay)
    // ──────────────────────────────────────────────────
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Erro ao obter tempo do sistema")?
        .as_secs();

    let time_diff = if now_unix >= payload.timestamp {
        now_unix - payload.timestamp
    } else {
        payload.timestamp - now_unix
    };

    if time_diff > REPLAY_WINDOW_SECS {
        let elapsed = t_start.elapsed();
        stats.rejected_replay += 1;
        stats.total_verification_time_ms += elapsed.as_secs_f64() * 1000.0;
        stats.verification_count += 1;

        print_metrics("REJEITADO (Replay Attack)", elapsed, raw.len(), sys, stats);
        println!(
            "   ✗ Verificação 01 FALHOU: Diferença de timestamp = {}s (máx: {}s)",
            time_diff, REPLAY_WINDOW_SECS
        );
        println!(
            "   ✗ Pacote do sensor {} descartado como possível ataque de repetição.\n",
            payload.id
        );
        return Ok(());
    }
    println!(
        "   ✓ Verificação 01: Timestamp OK (Δ = {}s ≤ {}s)",
        time_diff, REPLAY_WINDOW_SECS
    );

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 01b: Anti-Replay Intra-Janela
    // Rejeita pacote com (id, timestamp, reading) já visto dentro do Δt.
    // ──────────────────────────────────────────────────

    // Limpar entradas expiradas do cache (timestamp anterior ao início da janela)
    replay_seen.retain(|(_, ts, _)| now_unix.saturating_sub(*ts) <= REPLAY_WINDOW_SECS);

    let replay_key = (payload.id.clone(), payload.timestamp, payload.reading);
    if replay_seen.contains(&replay_key) {
        let elapsed = t_start.elapsed();
        stats.rejected_replay += 1;
        stats.total_verification_time_ms += elapsed.as_secs_f64() * 1000.0;
        stats.verification_count += 1;
        print_metrics("REJEITADO (Replay Intra-Janela)", elapsed, raw.len(), sys, stats);
        println!(
            "   ✗ Verificação 01b FALHOU: Pacote duplicado dentro da janela (id={}, ts={}, reading={})\n",
            payload.id, payload.timestamp, payload.reading
        );
        return Ok(());
    }

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 02: Assinatura Digital RSA-2048
    // ──────────────────────────────────────────────────
    let pub_key = match key_store.get(&payload.id) {
        Some(key) => key,
        None => {
            let elapsed = t_start.elapsed();
            stats.rejected_unknown_sensor += 1;
            stats.total_verification_time_ms += elapsed.as_secs_f64() * 1000.0;
            stats.verification_count += 1;

            print_metrics("REJEITADO (Sensor Desconhecido)", elapsed, raw.len(), sys, stats);
            println!(
                "   ✗ Verificação 02 FALHOU: Chave pública não encontrada para '{}'\n",
                payload.id
            );
            return Ok(());
        }
    };

    // Recalcular o hash SHA-256 da concatenação: id + timestamp + reading
    // (mesmo formato usado pelo ESP32: sprintf "%s%llu%llu")
    // Delimitador '|' previne ambiguidade: id="A1"+ts="23" ≠ id="A"+ts="123"
    let data_to_hash = format!("{}|{}|{}", payload.id, payload.timestamp, payload.reading);
    let hash = {
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(data_to_hash.as_bytes());
        hasher.finalize()
    };

    // Verificar a assinatura PKCS#1 v1.5 + SHA-256
    let verification_scheme = Pkcs1v15Sign::new::<Sha256>();
    match pub_key.verify(verification_scheme, &hash, &payload.signature) {
        Ok(_) => {
            println!("   ✓ Verificação 02: Assinatura RSA-2048 VÁLIDA");
        }
        Err(e) => {
            let elapsed = t_start.elapsed();
            stats.rejected_invalid_sig += 1;
            stats.total_verification_time_ms += elapsed.as_secs_f64() * 1000.0;
            stats.verification_count += 1;

            print_metrics("REJEITADO (Assinatura Inválida)", elapsed, raw.len(), sys, stats);
            println!("   ✗ Verificação 02 FALHOU: Assinatura inválida — {}\n", e);
            return Ok(());
        }
    }

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 03: Acumulador Criptográfico
    // ──────────────────────────────────────────────────
    let proof: MembershipProof<Rsa2048, String> = match serde_cbor::from_slice(&payload.membership_proof) {
        Ok(p) => p,
        Err(e) => {
            let elapsed = t_start.elapsed();
            stats.corrupted_cbor += 1;
            print_metrics("REJEITADO (Proof Inválida)", elapsed, raw.len(), sys, stats);
            println!("   ✗ Verificação 03 FALHOU ao desserializar MembershipProof: {:#}\n", e);
            return Ok(());
        }
    };

    if acc.verify_membership(&payload.id, &proof) {
        println!("   ✓ Verificação 03: MembershipProof VÁLIDA (witness^hash(id) == acc)");
    } else {
        let elapsed = t_start.elapsed();
        stats.rejected_invalid_proof += 1;
        stats.total_verification_time_ms += elapsed.as_secs_f64() * 1000.0;
        stats.verification_count += 1;

        print_metrics("REJEITADO (Prova Inválida)", elapsed, raw.len(), sys, stats);
        println!(
            "   ✗ Verificação 03 FALHOU: O sensor '{}' NÃO pertence ao acumulador.\n",
            payload.id
        );
        return Ok(());
    }

    // ════════════════════════════════════════════════════
    // FIM DA MEDIÇÃO — PACOTE ACEITO
    // ════════════════════════════════════════════════════

    // Registrar no cache intra-replay (apenas pacotes que passaram nas 3 etapas)
    replay_seen.insert(replay_key);

    let elapsed = t_start.elapsed();
    stats.accepted += 1;
    stats.total_verification_time_ms += elapsed.as_secs_f64() * 1000.0;
    stats.verification_count += 1;

    print_metrics("ACEITO ✓", elapsed, raw.len(), sys, stats);
    println!();

    Ok(())
}

// ============================================
// MÉTRICAS DE DESEMPENHO
// ============================================

fn print_metrics(
    status: &str,
    elapsed: std::time::Duration,
    packet_size: usize,
    sys: &mut System,
    stats: &SessionStats,
) {
    // Atualizar informações de memória do processo
    sys.refresh_memory();
    sys.refresh_processes();

    let pid = sysinfo::get_current_pid().expect("Falha ao obter PID");

    let ram_mb = sys
        .process(pid)
        .map(|p| p.memory() as f64 / (1024.0 * 1024.0))
        .unwrap_or(0.0);

    println!("────────────────────────────────────────────────────");
    println!("📊 Status: {}", status);
    println!(
        "   Tempo de verificação no controlador (ms): {:.3}",
        elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "   Overhead de rede e tamanho do pacote (bytes): {}",
        packet_size
    );
    println!("   RAM consumida pelo processo (MB): {:.2}", ram_mb);
    println!(
        "   📈 Sessão: {} aceitos | {} rejeitados | {} perdidos",
        stats.accepted,
        stats.rejected_replay
            + stats.rejected_unknown_sensor
            + stats.rejected_invalid_sig
            + stats.rejected_invalid_proof
            + stats.corrupted_cbor,
        stats.reassembly_timeouts + stats.sequence_gaps
    );
    println!("────────────────────────────────────────────────────");
}

// ============================================
// ESTRUTURAS DE REASSEMBLY
// ============================================

struct ReassemblyBuffer {
    // packet_id -> (total_fragments, received_count, fragments_map)
    packets: HashMap<u8, (u8, u8, HashMap<u8, Vec<u8>>)>,
    last_activity: Instant,
}

impl ReassemblyBuffer {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
            last_activity: Instant::now(),
        }
    }

    /// Limpa pacotes incompletos após timeout de inatividade e loga detalhes do descarte.
    fn check_timeout(&mut self, stats: &mut SessionStats) {
        if self.last_activity.elapsed().as_secs() >= REASSEMBLY_TIMEOUT_SECS && !self.packets.is_empty() {
            for (packet_id, (total_frags, received_count, frags_map)) in self.packets.drain() {
                stats.reassembly_timeouts += 1;
                let missing_indices: Vec<u8> = (0..total_frags)
                    .filter(|i| !frags_map.contains_key(i))
                    .map(|i| i + 1) // 1-indexed para log legível
                    .collect();

                println!(
                    "⚠️ [Reassembly Timeout] Pacote ID {} descartado após {}s de inatividade! Recebidos: {}/{} (Faltaram fragmentos: {:?})",
                    packet_id, REASSEMBLY_TIMEOUT_SECS, received_count, total_frags, missing_indices
                );
            }
        }
    }

    // Adiciona fragmento e retorna Some(payload_completo) se terminar
    fn add_fragment(
        &mut self,
        packet_id: u8,
        total_frags: u8,
        frag_idx: u8,
        payload: Vec<u8>,
        stats: &mut SessionStats,
    ) -> Option<Vec<u8>> {
        self.check_timeout(stats);
        self.last_activity = Instant::now();

        // Limite anti-flood: descartar fragmento se o buffer já está cheio com outros pacotes
        if !self.packets.contains_key(&packet_id) && self.packets.len() >= MAX_CONCURRENT_PACKETS {
            println!(
                "⚠️ [Reassembly] Limite de {} pacotes simultâneos atingido. Fragmento ID={} descartado (possível flood).",
                MAX_CONCURRENT_PACKETS, packet_id
            );
            return None;
        }

        let entry = self
            .packets
            .entry(packet_id)
            .or_insert_with(|| (total_frags, 0, HashMap::new()));

        // Evitar duplicatas
        if !entry.2.contains_key(&frag_idx) {
            entry.2.insert(frag_idx, payload);
            entry.1 += 1;
        }

        if entry.1 == entry.0 {
            // Remontar payload completo ordenadamente
            let mut full_payload = Vec::new();
            for i in 0..entry.0 {
                if let Some(frag) = entry.2.get(&i) {
                    full_payload.extend_from_slice(frag);
                }
            }
            self.packets.remove(&packet_id);
            Some(full_payload)
        } else {
            None
        }
    }
}

// ============================================
// MAIN — Controlador Serial (Rádio)
// ============================================

fn main() -> Result<()> {
    println!("═══════════════════════════════════════════════════════");
    println!("  Controller — ITS (Arquitetura TCC GSIPP) via Rádio");
    println!("═══════════════════════════════════════════════════════");
    println!("  Verificações: Timestamp + RSA-2048 + Acumulador");
    println!("  Rádio UART:   {} a {} bps", SERIAL_PORT, BAUD_RATE);
    println!("  Anti-Replay:  Janela de {}s", REPLAY_WINDOW_SECS);
    println!("  Reassembly:   Timeout de {}s", REASSEMBLY_TIMEOUT_SECS);
    println!("═══════════════════════════════════════════════════════\n");

    // --- 1. Construir dicionário de chaves públicas ---
    let key_store = build_key_store();
    println!(
        "🔑 Chaves públicas carregadas: {} sensor(es)",
        key_store.len()
    );
    for sensor_id in key_store.keys() {
        println!("   - {}", sensor_id);
    }

    // --- 2. Carregar acumulador serializado do disco ---
    let acc_bytes = std::fs::read("accumulator.dat").expect(
        "❌ Arquivo 'accumulator.dat' não encontrado! Execute 'cargo run --bin setup' primeiro.",
    );
    let acc: Accumulator<Rsa2048, String> =
        serde_cbor::from_slice(&acc_bytes).context("Falha ao desserializar accumulator.dat")?;
    println!("\n🔐 Acumulador carregado com sucesso do disco.");

    // --- 3. Inicializar monitor de sistema e estatísticas ---
    let mut sys = System::new();
    let stats_arc = Arc::new(Mutex::new(SessionStats::default()));
    let mut last_readings: HashMap<String, u64> = HashMap::new();
    // Cache de (id, timestamp, reading) vistos — descarta replays dentro da janela Δt
    let mut replay_seen: HashSet<(String, u64, u64)> = HashSet::new();

    // --- 4. Configurar handler para Ctrl+C (relatório final) ---
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        let stats_clone = stats_arc.clone();
        ctrlc::set_handler(move || {
            println!("\n🛑 Interrupção recebida (Ctrl+C)... Encerrando controlador.");
            if let Ok(st) = stats_clone.lock() {
                st.print_summary();
            }
            r.store(false, Ordering::SeqCst);
            std::process::exit(0);
        })
        .expect("Erro ao configurar handler de Ctrl+C");
    }

    // --- 5. Abrir porta serial ---
    let mut port = serialport::new(SERIAL_PORT, BAUD_RATE)
        .timeout(Duration::from_millis(100))
        .open()
        .context(format!("Falha ao abrir porta serial {}", SERIAL_PORT))?;

    println!("\n📡 Aguardando dados de rádio em {}...\n", SERIAL_PORT);

    let mut reassembly = ReassemblyBuffer::new();
    let mut buf = [0u8; 1024];
    let mut stream_buffer = Vec::new();

    while running.load(Ordering::SeqCst) {
        match port.read(&mut buf) {
            Ok(t) if t > 0 => {
                stream_buffer.extend_from_slice(&buf[..t]);

                // Parse stream contínuo com detecção otimizada de sincronismo
                loop {
                    if stream_buffer.len() < 6 {
                        break;
                    }

                    // Procurar cabeçalho 0xAA 0xBB
                    if stream_buffer[0] == 0xAA && stream_buffer[1] == 0xBB {
                        let packet_id = stream_buffer[2];
                        let total_frags = stream_buffer[3];
                        let frag_idx = stream_buffer[4];
                        let payload_len = stream_buffer[5] as usize;

                        // Validação de sanidade do cabeçalho
                        if total_frags == 0 || frag_idx >= total_frags || payload_len == 0 || payload_len > 250 {
                            println!(
                                "⚠️ [Radio] Cabeçalho corrompido descartado: ID={}, Total={}, Frag={}, Len={}",
                                packet_id, total_frags, frag_idx, payload_len
                            );
                            stream_buffer.drain(..2);
                            continue;
                        }

                        if stream_buffer.len() >= 6 + payload_len {
                            // Fragmento completo disponível
                            let payload = stream_buffer[6..6 + payload_len].to_vec();
                            stream_buffer.drain(..6 + payload_len);

                            println!(
                                "   [Radio] RX: Fragmento {}/{} (Pacote ID: {}) — {} bytes",
                                frag_idx + 1,
                                total_frags,
                                packet_id,
                                payload_len
                            );

                            let mut stats = stats_arc.lock().unwrap();
                            if let Some(full_cb_raw) = reassembly.add_fragment(
                                packet_id,
                                total_frags,
                                frag_idx,
                                payload,
                                &mut stats,
                            ) {
                                println!(
                                    "──── Pacote Completo Reconstruído ({} bytes) ────",
                                    full_cb_raw.len()
                                );
                                if let Err(e) = process_packet(
                                    &full_cb_raw,
                                    &key_store,
                                    &acc,
                                    &mut sys,
                                    &mut stats,
                                    &mut last_readings,
                                    &mut replay_seen,
                                ) {
                                    eprintln!("❌ Erro ao processar pacote CBOR: {:#}", e);
                                }
                            }
                        } else {
                            // Esperar mais bytes para completar o fragmento
                            break;
                        }
                    } else {
                        // Sincronismo não encontrado no início; procurar o próximo 0xAA 0xBB
                        if let Some(pos) = stream_buffer.windows(2).position(|w| w == [0xAA, 0xBB]) {
                            stream_buffer.drain(..pos);
                        } else {
                            // Se o último byte for 0xAA, mantê-lo caso o próximo seja 0xBB
                            if stream_buffer.last() == Some(&0xAA) {
                                stream_buffer.drain(..stream_buffer.len() - 1);
                            } else {
                                stream_buffer.clear();
                            }
                            break;
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Verificar timeouts de pacotes fragmentados mesmo se a serial estiver ociosa
                let mut stats = stats_arc.lock().unwrap();
                reassembly.check_timeout(&mut stats);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // EINTR causado pelo Ctrl+C — o handler de sinal já trata o encerramento,
                // apenas saímos do loop sem imprimir erro para não corromper o resumo final.
            }
            Err(e) => {
                eprintln!("❌ Erro de leitura serial: {:?}", e);
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }

    Ok(())
}
