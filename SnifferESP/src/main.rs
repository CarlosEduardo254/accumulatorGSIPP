use accumulator::{group::Rsa2048, Accumulator, MembershipProof};
use serde::Deserialize;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;

#[derive(Deserialize, Debug)]
struct Payload {
    #[serde(rename = "1")]
    id: String,
    #[serde(rename = "2")]
    timestamp: u64,
    #[serde(rename = "3")]
    reading: u64,
    #[serde(rename = "4", with = "serde_bytes")]
    membership_proof: Vec<u8>,
}

/// Estrutura de métricas thread-safe
struct Metrics {
    packets_received: AtomicU64,
    packets_valid: AtomicU64,
    packets_invalid: AtomicU64,
    total_verification_time_us: AtomicU64,
    start_time: Instant,
}

impl Metrics {
    fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_valid: AtomicU64::new(0),
            packets_invalid: AtomicU64::new(0),
            total_verification_time_us: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    fn print_stats(&self, system: &mut System) {
        let received = self.packets_received.load(Ordering::Relaxed);
        let valid = self.packets_valid.load(Ordering::Relaxed);
        let invalid = self.packets_invalid.load(Ordering::Relaxed);
        let total_time = self.total_verification_time_us.load(Ordering::Relaxed);
        let uptime = self.start_time.elapsed().as_secs();

        let avg_time = if received > 0 {
            total_time / received
        } else {
            0
        };
        let valid_pct = if received > 0 {
            (valid * 100) / received
        } else {
            0
        };

        // Atualizar informações do sistema
        system.refresh_all();
        let memory_mb = system.used_memory() / 1024 / 1024;
        let cpu_usage = system.global_cpu_info().cpu_usage();

        println!("\n═════════════════════════════════════════════════");
        println!("     Controlador de Sensores - Estatísticas");
        println!("═════════════════════════════════════════════════");
        println!(
            "Uptime: {}h {}m {}s",
            uptime / 3600,
            (uptime % 3600) / 60,
            uptime % 60
        );
        println!("Pacotes recebidos: {}", received);
        println!("  ✓ Válidos:   {} ({}%)", valid, valid_pct);
        println!("  ✗ Inválidos: {} ({}%)", invalid, 100 - valid_pct);
        println!();
        println!("Desempenho:");
        println!(
            "  Tempo médio de verificação: {} μs ({:.2} ms)",
            avg_time,
            avg_time as f64 / 1000.0
        );
        println!(
            "  Throughput: {:.2} pkt/s",
            if uptime > 0 {
                received as f64 / uptime as f64
            } else {
                0.0
            }
        );
        println!("  Uso de RAM: {} MB", memory_mb);
        println!("  CPU: {:.1}%", cpu_usage);
        println!("═════════════════════════════════════════════════\n");
    }
}

fn process_packet(data: &[u8], acc: &Accumulator<Rsa2048, String>, metrics: &Arc<Metrics>) {
    metrics.packets_received.fetch_add(1, Ordering::Relaxed);

    // 1. Deserializar CBOR → Payload
    let payload: Payload = match serde_cbor::from_slice(data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ Erro ao deserializar CBOR: {}", e);
            metrics.packets_invalid.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // 2. Deserializar MembershipProof
    let proof: MembershipProof<Rsa2048, String> =
        match serde_cbor::from_slice(&payload.membership_proof) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("✗ Erro ao deserializar MembershipProof: {}", e);
                metrics.packets_invalid.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

    // 3. Verificação criptográfica (MEDINDO TEMPO)
    let start = Instant::now();
    let is_valid = acc.verify_membership(&payload.id, &proof);
    let elapsed_us = start.elapsed().as_micros() as u64;

    metrics
        .total_verification_time_us
        .fetch_add(elapsed_us, Ordering::Relaxed);

    if is_valid {
        metrics.packets_valid.fetch_add(1, Ordering::Relaxed);
        println!(
            "✓ [{}] Reading: {} @ {} | Verificação: {} μs",
            payload.id, payload.reading, payload.timestamp, elapsed_us
        );
    } else {
        metrics.packets_invalid.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "✗ FRAUDE DETECTADA! Sensor: {} | Reading: {}",
            payload.id, payload.reading
        );
    }
}

fn main() -> anyhow::Result<()> {
    println!("═════════════════════════════════════════════════");
    println!("   Controlador de Sensores IoT - Inicializando");
    println!("═════════════════════════════════════════════════\n");

    // Carregar acumulador serializado
    println!("Carregando acumulador...");
    let acc_bytes = std::fs::read("accumulator.dat")
        .expect("Arquivo 'accumulator.dat' não encontrado! Execute o setup primeiro.");
    let acc: Accumulator<Rsa2048, String> = serde_cbor::from_slice(&acc_bytes)?;
    println!("✓ Acumulador carregado com sucesso\n");

    // Inicializar métricas
    let metrics = Arc::new(Metrics::new());
    let mut system = System::new_all();

    // Thread de monitoramento (imprime stats a cada 10s)
    let metrics_clone = Arc::clone(&metrics);
    std::thread::spawn(move || {
        let mut sys = System::new_all();
        loop {
            std::thread::sleep(Duration::from_secs(10));
            metrics_clone.print_stats(&mut sys);
        }
    });

    // Servidor UDP
    let socket = UdpSocket::bind("0.0.0.0:4242")?;
    println!("✓ Servidor UDP iniciado na porta 4242");
    println!("✓ Aguardando pacotes...\n");

    let mut buf = [0; 65535];
    loop {
        let (size, source) = socket.recv_from(&mut buf)?;
        println!("DEBUG: Recebido {} bytes de {}", size, source); // LOG DE DEBUG
        let packet = buf[..size].to_vec();
        let metrics_ref = Arc::clone(&metrics);
        let acc_clone = acc.clone();

        // Processar em thread separada (não bloquear recepção)
        std::thread::spawn(move || {
            process_packet(&packet, &acc_clone, &metrics_ref);
        });
    }
}
