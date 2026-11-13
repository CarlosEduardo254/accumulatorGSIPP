// ═══════════════════════════════════════════════════════════════════════
// UDP Controller — Servidor de Verificação para ITS (Arquitetura TCC GSIPP)
// ═══════════════════════════════════════════════════════════════════════
//
// Fluxo de verificações para cada pacote recebido de um sensor ESP32 via UDP:
//   0. Camada 00: desserialização do mapa CBOR externo (descarte de lixo/D1/D2)
//   1. Timestamp (anti-replay): diferença máxima de 5s
//      1b. Anti-replay intra-janela (deduplicação dentro do Δt)
//   2. Assinatura RSA-2048: SHA-256 (com delimitador) + PKCS#1 v1.5
//   3. Acumulador criptográfico (Witness + PoE de Wesolowski):
//      3a. Sintática:  desserialização da MembershipProof (S1, S2, S3)
//      3b. Aritmética: acc.verify_membership(id, proof) == false (S5)
//
// Métricas de desempenho e resiliência:
//   - Tempo de verificação no controlador (ms), medido a partir do recebimento
//     do datagrama (inclui o decode CBOR externo; exclui I/O de log)
//   - RAM consumida pelo processo (MB)
//   - Rastreamento de gaps de sequência (pacotes UDP perdidos na rede)
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
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, System};

// ============================================
// CONFIGURAÇÕES
// ============================================

const BIND_ADDR: &str = "0.0.0.0:4242";
const MAX_PACKET_SIZE: usize = 4096;
/// Tolerância máxima de timestamp (em segundos) para proteção anti-replay
const REPLAY_WINDOW_SECS: u64 = 5;
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
    total_received: u64,
    accepted: Bucket,
    /// Verificação 01 — timestamp fora da janela Δt (R1)
    rejected_replay: Bucket,
    /// Verificação 01b — duplicata intra-janela (R2)
    rejected_replay_duplicate: Bucket,
    /// Verificação 02 — ID sem chave pública cadastrada
    rejected_unknown_sensor: Bucket,
    /// Verificação 02 — assinatura RSA inválida (S4)
    rejected_invalid_sig: Bucket,
    /// Verificação 03 sintática — MembershipProof não desserializa (S1, S2, S3)
    rejected_proof_syntax: Bucket,
    /// Verificação 03 aritmética — verify_membership == false (S5)
    rejected_invalid_proof: Bucket,
    /// Camada 00 — mapa CBOR externo malformado (D1, D2)
    corrupted_cbor: Bucket,
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
            if self.total_received > 0 {
                (n as f64 / self.total_received as f64) * 100.0
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
        println!("                 RESUMO DA SESSÃO — ITS GSIPP (UDP)");
        println!("═══════════════════════════════════════════════════════════════════════");
        println!(" Total de pacotes recebidos:        {}", self.total_received);
        line("Aceitos (3 etapas validadas):", &self.accepted);
        line("V01  Anti-Replay (timestamp):", &self.rejected_replay);
        line("V01b Anti-Replay (duplicata):", &self.rejected_replay_duplicate);
        line("V02  Sensor desconhecido:", &self.rejected_unknown_sensor);
        line("V02  Assinatura RSA inválida:", &self.rejected_invalid_sig);
        line("V03  Proof sintática (CBOR):", &self.rejected_proof_syntax);
        line("V03  Proof aritmética (PoE):", &self.rejected_invalid_proof);
        line("C00  CBOR externo malformado:", &self.corrupted_cbor);
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
    stats.total_received += 1;

    // ════════════════════════════════════════════════════
    // INÍCIO DA MEDIÇÃO — imediatamente após o recv_from
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
                "    Camada 00 FALHOU: mapa CBOR externo inválido ({} bytes) — {:#}\n",
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
    println!(" Pacote recebido de: {}", payload.id);
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
                "    ALERTA DE GAP: Sequência saltou de #{} para #{} ({} pacote(s) perdido(s) na rede UDP)",
                prev_reading, payload.reading, lost
            );
        } else if payload.reading <= prev_reading {
            println!(
                "    ALERTA DE SEQUÊNCIA: Leitura não-crescente (anterior: #{}, atual: #{})",
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
            "    Verificação 01 FALHOU: Diferença de timestamp = {}s (máx: {}s)",
            time_diff, REPLAY_WINDOW_SECS
        );
        println!(
            "    Pacote do sensor {} descartado como possível ataque de repetição.\n",
            payload.id
        );
        return Ok(());
    }
    println!(
        "    Verificação 01: Timestamp OK (Δ = {}s ≤ {}s)",
        time_diff, REPLAY_WINDOW_SECS
    );

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 01b: Anti-Replay Intra-Janela
    // Rejeita pacote com (id, timestamp, reading) já visto dentro do Δt.
    // ──────────────────────────────────────────────────
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
            "    Verificação 01b FALHOU: Pacote duplicado dentro da janela (id={}, ts={}, reading={})\n",
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
                "    Verificação 02 FALHOU: Chave pública não encontrada para '{}'\n",
                payload.id
            );
            return Ok(());
        }
    };

    // Recalcular o hash SHA-256 da concatenação delimitada: id | timestamp | reading
    // Delimitador '|' previne ambiguidade de colisão.
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
            println!("    Verificação 02: Assinatura RSA-2048 VÁLIDA");
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
            println!("    Verificação 02 FALHOU: Assinatura inválida — {}\n", e);
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
                    "    Verificação 03 (sintática) FALHOU em {:.3} ms ao desserializar MembershipProof ({} bytes): {:#}\n",
                    elapsed.as_secs_f64() * 1000.0,
                    payload.membership_proof.len(),
                    e
                );
                return Ok(());
            }
        };

    // 03b — Aritmética: witness + PoE de Wesolowski contra o acumulador.
    if acc.verify_membership(&payload.id, &proof) {
        println!("    Verificação 03: MembershipProof VÁLIDA (witness^hash(id) == acc)");
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
            "    Verificação 03 (aritmética) FALHOU em {:.3} ms: o sensor '{}' NÃO pertence ao acumulador com esta prova.\n",
            elapsed.as_secs_f64() * 1000.0,
            payload.id
        );
        return Ok(());
    }

    // ════════════════════════════════════════════════════
    // FIM DA MEDIÇÃO — PACOTE ACEITO
    // ════════════════════════════════════════════════════
    replay_seen.insert(replay_key);

    let elapsed = since_recv();
    stats.accepted.record(elapsed);

    print_metrics("ACEITO ", elapsed, raw.len(), mon, stats);
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
    println!(" Status: {}", status);
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
        "    Sessão: {} aceitos | {} rejeitados | {} perdidos",
        stats.accepted.count,
        stats.total_rejected(),
        stats.sequence_gaps
    );
    println!("────────────────────────────────────────────────────");
}

// ============================================
// MAIN — Servidor UDP
// ============================================

fn main() -> Result<()> {
    println!("═══════════════════════════════════════════════════════");
    println!("  UDP Controller — ITS (Arquitetura TCC GSIPP)");
    println!("═══════════════════════════════════════════════════════");
    println!("  Verificações: Timestamp + RSA-2048 + Acumulador");
    println!("  Porta UDP:    {}", BIND_ADDR);
    println!("  Anti-Replay:  Janela de {}s", REPLAY_WINDOW_SECS);
    println!("═══════════════════════════════════════════════════════\n");

    // --- 1. Construir dicionário de chaves públicas ---
    let key_store = build_key_store();
    println!(
        " Chaves públicas carregadas: {} sensor(es)",
        key_store.len()
    );
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
        "\n Acumulador carregado de '{}' ({} bytes).",
        acc_path,
        acc_bytes.len()
    );

    // --- 3. Inicializar monitor de processo e estatísticas ---
    let mut mon = ProcMonitor::new();
    let stats_arc = Arc::new(Mutex::new(SessionStats::default()));
    let mut last_readings = HashMap::new();
    let mut replay_seen = HashSet::new();

    // --- 4. Configurar handler para Ctrl+C (relatório final) ---
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        let stats_clone = stats_arc.clone();
        ctrlc::set_handler(move || {
            println!("\n Interrupção recebida (Ctrl+C)... Encerrando servidor UDP.");
            if let Ok(st) = stats_clone.lock() {
                st.print_summary();
            }
            r.store(false, Ordering::SeqCst);
            std::process::exit(0);
        })
        .expect("Erro ao configurar handler de Ctrl+C");
    }

    // --- 5. Abrir socket UDP ---
    let socket = UdpSocket::bind(BIND_ADDR).context("Falha ao fazer bind no socket UDP")?;
    println!("\n📡 Aguardando pacotes UDP em {}...\n", BIND_ADDR);

    let mut buf = [0u8; MAX_PACKET_SIZE];

    while running.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                println!("──── Pacote de {} ({} bytes) ────", src, size);
                let mut stats = stats_arc.lock().unwrap();
                if let Err(e) = process_packet(
                    &buf[..size],
                    &key_store,
                    &acc,
                    &mut mon,
                    &mut stats,
                    &mut last_readings,
                    &mut replay_seen,
                ) {
                    eprintln!(" Erro ao processar pacote: {:#}", e);
                }
            }
            Err(e) => {
                eprintln!(" Erro ao receber UDP: {}", e);
            }
        }
    }

    Ok(())
}
