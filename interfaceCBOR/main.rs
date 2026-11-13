// ═══════════════════════════════════════════════════════════════════════
// Controller — Servidor de Verificação para ITS (Arquitetura TCC GSIPP)
// ═══════════════════════════════════════════════════════════════════════
//
// Fluxo de verificações para cada pacote remontado de um sensor ESP32:
//   0. Camada 00: desserialização do mapa CBOR externo (pacote malformado)
//   1. Timestamp (anti-replay): diferença máxima de 5s
//      1b. Anti-replay intra-janela (deduplicação dentro do Δt)
//   2. Assinatura RSA-2048: SHA-256 (com delimitador) + PKCS#1 v1.5
//   3. Acumulador criptográfico (Witness + PoE de Wesolowski):
//      3a. Sintática:  desserialização da MembershipProof
//      3b. Aritmética: acc.verify_membership(id, proof) == false
//
// Métricas de desempenho e resiliência:
//   - Tempo de verificação no controlador (ms), medido a partir da remontagem
//     completa do pacote (inclui o decode CBOR externo; exclui I/O de log)
//   - RAM consumida pelo processo (MB)
//   - Rastreamento de gaps de sequência e perdas de fragmentos
//   - Estatísticas de sessão em tempo real e no encerramento (Ctrl+C)
//
// Executar (da raiz do repositório): cargo run --bin udp_controller --release

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
use sysinfo::{Pid, System};
use cobs::decode_vec;

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
/// Maior frame válido no fio: cabeçalho (5) + payload (até 255, pois o campo
/// de tamanho é u8) + overhead COBS (até 2) + delimitador 0x00 (1).
const MAX_FRAME_LEN: usize = 5 + 255 + 2 + 1;
/// Bytes exibidos no dump hexadecimal de frames inválidos
const HEX_DUMP_LEN: usize = 16;
/// Locais onde o accumulator.dat é procurado (em ordem). O primeiro permite
/// `cargo run --bin udp_controller` direto da raiz do repositório.
const ACCUMULATOR_PATHS: [&str; 2] = ["SnifferESP/accumulator.dat", "./accumulator.dat"];

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

/// Contador + tempo acumulado de uma categoria de desfecho.
#[derive(Default, Debug, Clone, Copy)]
struct Bucket {
    count: u64,
    total_ms: f64,
}

impl Bucket {
    fn record(&mut self, elapsed: Duration) {
        self.count += 1;
        self.total_ms += elapsed.as_secs_f64() * 1000.0;
    }

    fn avg_ms(&self) -> f64 {
        if self.count > 0 {
            self.total_ms / self.count as f64
        } else {
            0.0
        }
    }
}

#[derive(Default, Debug)]
struct SessionStats {
    total_reconstructed: u64,
    accepted: Bucket,
    /// Verificação 01 — timestamp fora da janela Δt
    rejected_replay: Bucket,
    /// Verificação 01b — duplicata intra-janela
    rejected_replay_duplicate: Bucket,
    /// Verificação 02 — ID sem chave pública cadastrada
    rejected_unknown_sensor: Bucket,
    /// Verificação 02 — assinatura RSA inválida
    rejected_invalid_sig: Bucket,
    /// Verificação 03 sintática — MembershipProof não desserializa
    rejected_proof_syntax: Bucket,
    /// Verificação 03 aritmética — verify_membership == false
    rejected_invalid_proof: Bucket,
    /// Camada 00 — mapa CBOR externo malformado
    corrupted_cbor: Bucket,
    reassembly_timeouts: u64,
    sequence_gaps: u64,
}

impl SessionStats {
    /// Pacotes cujo CBOR externo foi decodificado e passaram pelas verificações.
    fn verified_buckets(&self) -> [&Bucket; 7] {
        [
            &self.accepted,
            &self.rejected_replay,
            &self.rejected_replay_duplicate,
            &self.rejected_unknown_sensor,
            &self.rejected_invalid_sig,
            &self.rejected_proof_syntax,
            &self.rejected_invalid_proof,
        ]
    }

    fn total_rejected(&self) -> u64 {
        self.verified_buckets().iter().map(|b| b.count).sum::<u64>() - self.accepted.count
            + self.corrupted_cbor.count
    }

    fn print_summary(&self) {
        let pct = |n: u64| {
            if self.total_reconstructed > 0 {
                (n as f64 / self.total_reconstructed as f64) * 100.0
            } else {
                0.0
            }
        };
        let line = |label: &str, b: &Bucket| {
            println!(
                "  {:<34} {:>6} ({:>5.1}%) | média {:>8.3} ms",
                label,
                b.count,
                pct(b.count),
                b.avg_ms()
            );
        };

        println!("\n═══════════════════════════════════════════════════════════════════════");
        println!("                  RESUMO DA SESSÃO — ITS GSIPP (Rádio)");
        println!("═══════════════════════════════════════════════════════════════════════");
        println!(" Total de pacotes remontados:       {}", self.total_reconstructed);
        line("Aceitos (3 etapas validadas):", &self.accepted);
        line("V01  Anti-Replay (timestamp):", &self.rejected_replay);
        line("V01b Anti-Replay (duplicata):", &self.rejected_replay_duplicate);
        line("V02  Sensor desconhecido:", &self.rejected_unknown_sensor);
        line("V02  Assinatura RSA inválida:", &self.rejected_invalid_sig);
        line("V03  Proof sintática (CBOR):", &self.rejected_proof_syntax);
        line("V03  Proof aritmética (PoE):", &self.rejected_invalid_proof);
        line("C00  CBOR externo malformado:", &self.corrupted_cbor);
        println!("  Pacotes incompletos (timeout):     {}", self.reassembly_timeouts);
        println!("  Gaps de sequência detectados:      {}", self.sequence_gaps);

        let (n, total_ms) = self
            .verified_buckets()
            .iter()
            .fold((0u64, 0.0f64), |(n, t), b| (n + b.count, t + b.total_ms));
        let avg_time = if n > 0 { total_ms / n as f64 } else { 0.0 };
        println!(
            "  Tempo médio verificação (V01–V03): {:.3} ms (exclui Camada 00)",
            avg_time
        );
        println!("═══════════════════════════════════════════════════════════════════════\n");
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

    // Adicione mais sensores aqui conforme necessário:
    // store.insert("ESP-43".to_string(), outra_chave);

    store
}

// ============================================
// MONITOR DE RAM DO PRÓPRIO PROCESSO
// ============================================

/// Atualiza apenas o processo do controlador (e não todos os processos do
/// sistema), o que é bem mais barato no Raspberry Pi.
struct ProcMonitor {
    sys: System,
    pid: Pid,
}

impl ProcMonitor {
    fn new() -> Self {
        let pid = sysinfo::get_current_pid().expect("Falha ao obter PID");
        Self {
            sys: System::new(),
            pid,
        }
    }

    fn ram_mb(&mut self) -> f64 {
        self.sys.refresh_process(self.pid);
        self.sys
            .process(self.pid)
            .map(|p| p.memory() as f64 / (1024.0 * 1024.0))
            .unwrap_or(0.0)
    }
}

// ============================================
// PROCESSAMENTO DO PACOTE — 3 VERIFICAÇÕES
// ============================================

fn process_packet(
    raw: &[u8],
    key_store: &HashMap<String, RsaPublicKey>,
    acc: &Accumulator<Rsa2048, String>,
    mon: &mut ProcMonitor,
    stats: &mut SessionStats,
    last_readings: &mut HashMap<String, u64>,
    replay_seen: &mut HashSet<(String, u64, u64)>,
) -> Result<()> {
    stats.total_reconstructed += 1;

    // ════════════════════════════════════════════════════
    // INÍCIO DA MEDIÇÃO — imediatamente após a remontagem do pacote
    // ════════════════════════════════════════════════════
    let t_recv = Instant::now();

    // ──────────────────────────────────────────────────
    // CAMADA 00: Desserialização do mapa CBOR externo
    // ──────────────────────────────────────────────────
    let payload: Payload = match serde_cbor::from_slice(raw) {
        Ok(p) => p,
        Err(e) => {
            let elapsed = t_recv.elapsed();
            stats.corrupted_cbor.record(elapsed);
            print_metrics(
                "REJEITADO (CBOR Externo Malformado)",
                elapsed,
                raw.len(),
                mon,
                stats,
            );
            println!(
                "   Camada 00 FALHOU: mapa CBOR externo inválido ({} bytes) — {:#}\n",
                raw.len(),
                e
            );
            return Ok(());
        }
    };
    // O tempo do decode externo é somado ao das verificações; o I/O de log
    // abaixo (cabeçalho + gap) fica fora da medição.
    let t_decode = t_recv.elapsed();

    println!("\n════════════════════════════════════════════════════");
    println!("Pacote recebido de: {}", payload.id);
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
                "   ALERTA DE GAP: Sequência saltou de #{} para #{} ({} pacote(s) perdido(s) no rádio)",
                prev_reading, payload.reading, lost
            );
        } else if payload.reading <= prev_reading {
            println!(
                "   ALERTA DE SEQUÊNCIA: Leitura não-crescente (anterior: #{}, atual: #{})",
                prev_reading, payload.reading
            );
        }
    }
    last_readings.insert(payload.id.clone(), payload.reading);
    println!("════════════════════════════════════════════════════");

    // ════════════════════════════════════════════════════
    // RETOMADA DA MEDIÇÃO — verificações V01 a V03
    // ════════════════════════════════════════════════════
    let t_start = Instant::now();
    let since_recv = move || t_decode + t_start.elapsed();

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
        let elapsed = since_recv();
        stats.rejected_replay.record(elapsed);

        print_metrics("REJEITADO (Replay Attack)", elapsed, raw.len(), mon, stats);
        println!(
            "   Verificação 01 FALHOU: Diferença de timestamp = {}s (máx: {}s)",
            time_diff, REPLAY_WINDOW_SECS
        );
        println!(
            "   Pacote do sensor {} descartado como possível ataque de repetição.\n",
            payload.id
        );
        return Ok(());
    }
    println!(
        "   Verificação 01: Timestamp OK (Δ = {}s ≤ {}s)",
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
        let elapsed = since_recv();
        stats.rejected_replay_duplicate.record(elapsed);
        print_metrics(
            "REJEITADO (Replay Intra-Janela)",
            elapsed,
            raw.len(),
            mon,
            stats,
        );
        println!(
            "   Verificação 01b FALHOU: Pacote duplicado dentro da janela (id={}, ts={}, reading={})\n",
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
            let elapsed = since_recv();
            stats.rejected_unknown_sensor.record(elapsed);

            print_metrics(
                "REJEITADO (Sensor Desconhecido)",
                elapsed,
                raw.len(),
                mon,
                stats,
            );
            println!(
                "   Verificação 02 FALHOU: Chave pública não encontrada para '{}'\n",
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
            println!("   Verificação 02: Assinatura RSA-2048 VÁLIDA");
        }
        Err(e) => {
            let elapsed = since_recv();
            stats.rejected_invalid_sig.record(elapsed);

            print_metrics(
                "REJEITADO (Assinatura Inválida)",
                elapsed,
                raw.len(),
                mon,
                stats,
            );
            println!("   Verificação 02 FALHOU: Assinatura inválida — {}\n", e);
            return Ok(());
        }
    }

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 03: Acumulador Criptográfico
    // ──────────────────────────────────────────────────
    // 03a — Sintática: a MembershipProof (campo "5") precisa desserializar.
    let proof: MembershipProof<Rsa2048, String> =
        match serde_cbor::from_slice(&payload.membership_proof) {
            Ok(p) => p,
            Err(e) => {
                let elapsed = since_recv();
                stats.rejected_proof_syntax.record(elapsed);
                print_metrics(
                    "REJEITADO (V03 Sintática — Proof Malformada)",
                    elapsed,
                    raw.len(),
                    mon,
                    stats,
                );
                println!(
                    "   Verificação 03 (sintática) FALHOU em {:.3} ms ao desserializar MembershipProof ({} bytes): {:#}\n",
                    elapsed.as_secs_f64() * 1000.0,
                    payload.membership_proof.len(),
                    e
                );
                return Ok(());
            }
        };

    // 03b — Aritmética: witness + PoE de Wesolowski contra o acumulador.
    if acc.verify_membership(&payload.id, &proof) {
        println!("   Verificação 03: MembershipProof VÁLIDA (witness^hash(id) == acc)");
    } else {
        let elapsed = since_recv();
        stats.rejected_invalid_proof.record(elapsed);

        print_metrics(
            "REJEITADO (V03 Aritmética — Prova Inválida)",
            elapsed,
            raw.len(),
            mon,
            stats,
        );
        println!(
            "   Verificação 03 (aritmética) FALHOU em {:.3} ms: o sensor '{}' NÃO pertence ao acumulador com esta prova.\n",
            elapsed.as_secs_f64() * 1000.0,
            payload.id
        );
        return Ok(());
    }

    // ════════════════════════════════════════════════════
    // FIM DA MEDIÇÃO — PACOTE ACEITO
    // ════════════════════════════════════════════════════

    // Registrar no cache intra-replay (apenas pacotes que passaram nas 3 etapas)
    replay_seen.insert(replay_key);

    let elapsed = since_recv();
    stats.accepted.record(elapsed);

    print_metrics("ACEITO", elapsed, raw.len(), mon, stats);
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
    mon: &mut ProcMonitor,
    stats: &SessionStats,
) {
    let ram_mb = mon.ram_mb();

    println!("────────────────────────────────────────────────────");
    println!("Status: {}", status);
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
        "   Sessão: {} aceitos | {} rejeitados | {} perdidos",
        stats.accepted.count,
        stats.total_rejected(),
        stats.reassembly_timeouts + stats.sequence_gaps
    );
    println!("────────────────────────────────────────────────────");
}

/// Primeiros `HEX_DUMP_LEN` bytes de um frame em hexadecimal (para diagnóstico).
fn hex_prefix(bytes: &[u8]) -> String {
    let mut s = bytes
        .iter()
        .take(HEX_DUMP_LEN)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > HEX_DUMP_LEN {
        s.push_str(" ...");
    }
    s
}

// ============================================
// ESTRUTURAS DE REASSEMBLY
// ============================================

struct IncompletePacket {
    total_frags: u8,
    created_at: Instant,
    fragments: HashMap<u8, Vec<u8>>,
}

struct ReassemblyBuffer {
    packets: HashMap<(u8, u8), IncompletePacket>,
}

impl ReassemblyBuffer {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
        }
    }

    /// Limpa pacotes incompletos cujo timeout individual expirou e loga detalhes do descarte.
    fn check_timeout(&mut self, stats: &mut SessionStats) {
        let now = Instant::now();
        let timeout = Duration::from_secs(REASSEMBLY_TIMEOUT_SECS);

        // Identificar pacotes que já ultrapassaram o tempo limite de espera
        let expired_ids: Vec<(u8, u8)> = self
            .packets
            .iter()
            .filter(|(_, pkt)| now.duration_since(pkt.created_at) >= timeout)
            .map(|(&id, _)| id)
            .collect();

        for id in expired_ids {
            if let Some(pkt) = self.packets.remove(&id) {
                stats.reassembly_timeouts += 1;
                let missing_indices: Vec<u8> = (0..pkt.total_frags)
                    .filter(|i| !pkt.fragments.contains_key(i))
                    .map(|i| i + 1) // 1-indexed para log legível
                    .collect();

                println!(
                    "⚠️ [Reassembly Timeout] Pacote Sensor_ID={} ID={} descartado após {}s de inatividade! Recebidos: {}/{} (Faltaram fragmentos: {:?})",
                    id.0, id.1, REASSEMBLY_TIMEOUT_SECS, pkt.fragments.len(), pkt.total_frags, missing_indices
                );
            }
        }
    }

    // Adiciona fragmento e retorna Some(payload_completo) se terminar
    fn add_fragment(
        &mut self,
        sensor_id: u8,
        packet_id: u8,
        total_frags: u8,
        frag_idx: u8,
        payload: Vec<u8>,
        stats: &mut SessionStats,
    ) -> Option<Vec<u8>> {
        // 1. Limpar pacotes expirados individualmente antes de processar novo fragmento
        self.check_timeout(stats);

        // 2. Limite anti-flood: descartar NOVO pacote se o buffer já está cheio de pacotes recentes
        let key = (sensor_id, packet_id);
        if !self.packets.contains_key(&key) && self.packets.len() >= MAX_CONCURRENT_PACKETS {
            println!(
                "⚠️ [Reassembly] Limite de {} pacotes simultâneos atingido. Fragmento Sensor={} ID={} descartado (possível flood).",
                MAX_CONCURRENT_PACKETS, sensor_id, packet_id
            );
            return None;
        }

        let entry = self
            .packets
            .entry(key)
            .or_insert_with(|| IncompletePacket {
                total_frags,
                created_at: Instant::now(),
                fragments: HashMap::new(),
            });

        // Evitar duplicatas
        entry.fragments.entry(frag_idx).or_insert(payload);

        if entry.fragments.len() == entry.total_frags as usize {
            // Remontar payload completo ordenadamente
            let mut full_payload = Vec::new();
            for i in 0..entry.total_frags {
                if let Some(frag) = entry.fragments.get(&i) {
                    full_payload.extend_from_slice(frag);
                }
            }
            self.packets.remove(&key);
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
    println!("Chaves públicas carregadas: {} sensor(es)", key_store.len());
    for sensor_id in key_store.keys() {
        println!("   - {}", sensor_id);
    }

    // --- 2. Carregar acumulador serializado do disco ---
    let (acc_path, acc_bytes) = ACCUMULATOR_PATHS
        .iter()
        .find_map(|p| std::fs::read(p).ok().map(|b| (*p, b)))
        .with_context(|| {
            format!(
                "Arquivo accumulator.dat não encontrado em {:?}. \
                 Execute 'cd SnifferESP && cargo run --release --bin setup' primeiro.",
                ACCUMULATOR_PATHS
            )
        })?;
    let acc: Accumulator<Rsa2048, String> = serde_cbor::from_slice(&acc_bytes)
        .with_context(|| format!("Falha ao desserializar {}", acc_path))?;
    println!(
        "\nAcumulador carregado de '{}' ({} bytes).",
        acc_path,
        acc_bytes.len()
    );

    // --- 3. Inicializar monitor de processo e estatísticas ---
    let mut mon = ProcMonitor::new();
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
            println!("\nInterrupção recebida (Ctrl+C)... Encerrando controlador.");
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

    println!("\nAguardando dados de rádio em {}...\n", SERIAL_PORT);

    let mut reassembly = ReassemblyBuffer::new();
    let mut buf = [0u8; 1024];
    let mut stream_buffer = Vec::new();

    while running.load(Ordering::SeqCst) {
        match port.read(&mut buf) {
            Ok(t) if t > 0 => {
                stream_buffer.extend_from_slice(&buf[..t]);

                // Parse stream contínuo procurando delimitador 0x00
                while let Some(pos) = stream_buffer.iter().position(|&b| b == 0x00) {
                    let frame = stream_buffer.drain(..=pos).collect::<Vec<u8>>();
                    
                    if frame.len() <= 6 {
                        // Muito pequeno para ser um frame válido (precisa ter header 5 bytes + dados + 0x00 overhead).
                        // Inclui o frame vazio gerado pelo delimitador inicial que o ESP envia
                        // antes de cada fragmento e o preâmbulo de wake-up (FF FF FF FF 00).
                        continue;
                    }

                    if frame.len() > MAX_FRAME_LEN {
                        // Lixo grudado num fragmento (ex.: ruído sem 0x00): não pode ser válido
                        println!(
                            "[Radio] Frame de {} bytes excede o máximo ({}) — descartado. Início: {}",
                            frame.len(),
                            MAX_FRAME_LEN,
                            hex_prefix(&frame)
                        );
                        continue;
                    }
                    
                    // Decodificar COBS (tirando o 0x00 final)
                    match decode_vec(&frame[..frame.len() - 1]) {
                        Ok(decoded) => {
                            if decoded.len() < 5 {
                                println!("[Radio] Frame decodificado muito pequeno.");
                                continue;
                            }
                            
                            let sensor_id = decoded[0];
                            let packet_id = decoded[1];
                            let total_frags = decoded[2];
                            let frag_idx = decoded[3];
                            let payload_len = decoded[4] as usize;
                            
                            if total_frags == 0 || frag_idx >= total_frags || payload_len == 0 {
                                println!(
                                    "[Radio] Cabeçalho decodificado corrompido: Sensor={}, ID={}, Total={}, Frag={}, Len={}",
                                    sensor_id, packet_id, total_frags, frag_idx, payload_len
                                );
                                continue;
                            }
                            
                            if decoded.len() < 5 + payload_len {
                                println!("[Radio] Tamanho real ({}) menor que payload_len ({}).", decoded.len() - 5, payload_len);
                                continue;
                            }
                            
                            let payload = decoded[5..5 + payload_len].to_vec();
                            
                            println!(
                                "   [Radio] RX: Fragmento {}/{} (Sensor ID: {}, Pacote ID: {}) — {} bytes",
                                frag_idx + 1,
                                total_frags,
                                sensor_id,
                                packet_id,
                                payload_len
                            );

                            let mut stats = stats_arc.lock().unwrap();
                            if let Some(full_cb_raw) = reassembly.add_fragment(
                                sensor_id,
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
                                    &mut mon,
                                    &mut stats,
                                    &mut last_readings,
                                    &mut replay_seen,
                                ) {
                                    eprintln!("Erro ao processar pacote CBOR: {:#}", e);
                                }
                            }
                        }
                        Err(_) => {
                            println!(
                                "[Radio] Erro de decodificação COBS ({} bytes). Início: {}",
                                frame.len(),
                                hex_prefix(&frame)
                            );
                        }
                    }
                }

                // Sem 0x00 no que sobrou: é o início de um frame ainda em trânsito.
                // Se já passou do tamanho máximo de um frame válido, é ruído (ex.: outro
                // transmissor em 433 MHz) — descarta para o buffer não crescer sem limite.
                if stream_buffer.len() > MAX_FRAME_LEN {
                    println!(
                        "[Radio] {} bytes sem delimitador 0x00 — buffer descartado. Início: {}",
                        stream_buffer.len(),
                        hex_prefix(&stream_buffer)
                    );
                    stream_buffer.clear();
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
                eprintln!("Erro de leitura serial: {:?}", e);
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }

    Ok(())
}
