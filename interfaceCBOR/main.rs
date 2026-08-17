// ═══════════════════════════════════════════════════════════════════════
// UDP Controller — Servidor de Verificação para ITS (Arquitetura TCC)
// ═══════════════════════════════════════════════════════════════════════
//
// Fluxo de 3 verificações para cada pacote recebido de um sensor ESP32:
//   1. Timestamp (anti-replay): diferença máxima de 5s
//   2. Assinatura RSA-2048: SHA-256 + PKCS#1 v1.5
//   3. Acumulador criptográfico: verify_membership (Witness + PoE)
//
// Métricas de desempenho:
//   - Tempo de verificação no controlador (ms)
//   - RAM consumida pelo processo (MB)
//
// Executar: cargo run --bin udp_controller --release

use accumulator::{group::Rsa2048, Accumulator, MembershipProof};
use anyhow::{Context, Result};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use sha2::Digest;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use sysinfo::System;

// ============================================
// CONFIGURAÇÕES
// ============================================

const BIND_ADDR: &str = "0.0.0.0:4242";
const MAX_PACKET_SIZE: usize = 4096;
/// Tolerância máxima de timestamp (em segundos) para proteção anti-replay
const REPLAY_WINDOW_SECS: u64 = 5;

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
) -> Result<()> {
    // --- Desserializar CBOR ---
    let payload: Payload =
        serde_cbor::from_slice(raw).context("Falha ao desserializar payload CBOR")?;

    println!("\n════════════════════════════════════════════════════");
    println!("📦 Pacote recebido de: {}", payload.id);
    println!("   Timestamp:  {}", payload.timestamp);
    println!("   Reading:    {}", payload.reading);
    println!("   Assinatura: {} bytes", payload.signature.len());
    println!("   Proof:      {} bytes", payload.membership_proof.len());
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
        print_metrics("REJEITADO (Replay Attack)", elapsed, raw.len(), sys);
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
    println!("   ✓ Verificação 01: Timestamp OK (Δ = {}s ≤ {}s)", time_diff, REPLAY_WINDOW_SECS);

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 02: Assinatura Digital RSA-2048
    // ──────────────────────────────────────────────────
    let pub_key = match key_store.get(&payload.id) {
        Some(key) => key,
        None => {
            let elapsed = t_start.elapsed();
            print_metrics("REJEITADO (Sensor Desconhecido)", elapsed, raw.len(), sys);
            println!(
                "   ✗ Verificação 02 FALHOU: Chave pública não encontrada para '{}'\n",
                payload.id
            );
            return Ok(());
        }
    };

    // Recalcular o hash SHA-256 da concatenação: id + timestamp + reading
    // (mesmo formato usado pelo ESP32: sprintf "%s%llu%llu")
    let data_to_hash = format!("{}{}{}", payload.id, payload.timestamp, payload.reading);
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
            print_metrics("REJEITADO (Assinatura Inválida)", elapsed, raw.len(), sys);
            println!("   ✗ Verificação 02 FALHOU: Assinatura inválida — {}\n", e);
            return Ok(());
        }
    }

    // ──────────────────────────────────────────────────
    // VERIFICAÇÃO 03: Acumulador Criptográfico
    // ──────────────────────────────────────────────────
    let proof: MembershipProof<Rsa2048, String> =
        serde_cbor::from_slice(&payload.membership_proof)
            .context("Falha ao desserializar MembershipProof (Witness + PoE)")?;

    if acc.verify_membership(&payload.id, &proof) {
        println!("   ✓ Verificação 03: MembershipProof VÁLIDA (witness^hash(id) == acc)");
    } else {
        let elapsed = t_start.elapsed();
        print_metrics("REJEITADO (Prova Inválida)", elapsed, raw.len(), sys);
        println!(
            "   ✗ Verificação 03 FALHOU: O sensor '{}' NÃO pertence ao acumulador.\n",
            payload.id
        );
        return Ok(());
    }

    // ════════════════════════════════════════════════════
    // FIM DA MEDIÇÃO — PACOTE ACEITO
    // ════════════════════════════════════════════════════
    let elapsed = t_start.elapsed();
    print_metrics("ACEITO ✓", elapsed, raw.len(), sys);
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
    println!("  Porta: {}", BIND_ADDR);
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
    // Este arquivo foi gerado pelo `setup.rs` e contém o estado do acumulador
    // após adicionar todos os sensores autorizados (ex: ESP-42).
    let acc_bytes = std::fs::read("accumulator.dat").expect(
        "❌ Arquivo 'accumulator.dat' não encontrado! Execute 'cargo run --bin setup' primeiro."
    );
    let acc: Accumulator<Rsa2048, String> = serde_cbor::from_slice(&acc_bytes)
        .context("Falha ao desserializar accumulator.dat")?;
    println!("\n🔐 Acumulador carregado com sucesso do disco.");

    // --- 3. Inicializar monitor de sistema ---
    let mut sys = System::new();

    // --- 4. Abrir socket UDP ---
    let socket = UdpSocket::bind(BIND_ADDR).context("Falha ao fazer bind no socket UDP")?;
    println!("\n📡 Aguardando pacotes em {}...\n", BIND_ADDR);

    let mut buf = [0u8; MAX_PACKET_SIZE];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                println!("──── Pacote de {} ({} bytes) ────", src, size);
                if let Err(e) = process_packet(&buf[..size], &key_store, &acc, &mut sys) {
                    eprintln!("❌ Erro ao processar pacote: {:#}", e);
                }
            }
            Err(e) => {
                eprintln!("❌ Erro ao receber UDP: {}", e);
            }
        }
    }
}
