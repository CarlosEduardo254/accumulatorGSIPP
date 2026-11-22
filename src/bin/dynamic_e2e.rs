// ═══════════════════════════════════════════════════════════════════════
// dynamic_e2e — Teste funcional fim-a-fim de revogação e adição via Wi-Fi/UDP
// ═══════════════════════════════════════════════════════════════════════
//
// Exercita o controlador REAL (udp_controller, porta UDP 4242) no ciclo de vida:
//
//   Fase 1  (controlador com A1 = {ESP-01, ESP-02, ESP-42})
//     F1-A  ESP-42, proof de A1                      → esperado 100% ACEITO
//     F1-B  ESP-02, proof de A1 (controle adicional) → esperado 100% ACEITO
//   Fase 2  (TMC offline — dynamic_tmc): revoga ESP-42 → A2 = {ESP-01, ESP-02} e
//           atualiza a witness de ESP-02 para A2
//   Fase 3  (controlador com A2; a chave pública do ESP-42 CONTINUA no HashMap)
//     F3-A  ESP-42 revogado, assinatura RSA legítima, proof antiga → 100% REJEITADO V03 aritmética
//     F3-B  ESP-02, witness DESATUALIZADA (A1)                     → 100% REJEITADO V03 aritmética
//     F3-C  ESP-02, witness ATUALIZADA (A2)                        → 100% ACEITO
//   Fase 4  (controlador com A3 = {ESP-01, ESP-02, ESP-99})
//     F4-A  ESP-99 (novo sensor), proof de A3                      → 100% ACEITO
//     F4-B  ESP-02, witness atualizada para A3                     → 100% ACEITO
//     F4-C  ESP-02, witness de A2 (controle adicional)             → 100% REJEITADO V03 aritmética
//     F4-D  ESP-42 revogado (controle adicional)                   → 100% REJEITADO V03 aritmética
//
// Modo local (--host 127.0.0.1, padrão): o próprio teste inicia o udp_controller a cada fase
// com --acc accumulator_A{k}.dat, captura o stdout em --controller-log e confere o desfecho
// de CADA pacote a partir da saída do controlador (fonte da verdade).
//
// Modo remoto (--host <IP do Raspberry Pi>): o teste apenas envia os pacotes pela rede Wi-Fi;
// antes de cada fase ele imprime o comando do controlador a ser executado no Pi e aguarda
// ENTER (desative com --no-pause). A conferência é feita no log do controlador no Pi.
//
// Pré-requisito: cargo run --release --bin dynamic_tmc   (gera os artefatos)
//
// Uso:
//   cargo run --release --bin dynamic_e2e -- [--host 127.0.0.1] [--port 4242] [--packets 50]
//       [--delay-ms 20] [--artifacts target/e2e_dinamicidade]
//       [--controller-log logs_dinamicidade/e2e_controller.log]
//       [--json logs_dinamicidade/resultados_e2e.json] [--no-spawn] [--no-pause]

use anyhow::{bail, Context, Result};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use serde::Serialize;
use sha2::Digest;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ============================================
// Chave privada LEGÍTIMA do ESP-42 (a mesma do firmware e do attack_tests.py).
// O controlador tem a chave pública correspondente embutida (ESP42_PUBLIC_KEY_PEM).
// ============================================
const ESP42_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDg8/gBUdLHnfPi
fpt4K/HH64ks9hTBgJrW0GP+6rMU3ndEzgr3tbKQEq9yhtQHO0iVTHmFKTHWkwdv
iBiyjPOkp7psfXk49QRH74si9WZRZFgsaFdCvtmgNtjy8JbfdivND7gkcjovp5o3
h5+obvigODWhquRduqrYbO7zs/AELw9pXlHu92G5k/3htsZf0X1NaQZx/KGApxV7
GQb5FvpEwDDTcDVeXTmgxXrabmt9vjMeHIlRZUlEk11MKqGOfMPJqFYzNVDa19/Q
GcjJsZOPxtY+DLwTBVQ7c3b4RnhNanBhBeo1+omeT8hzAdxGksSPAE12rEPnceUa
muRvI1Q9AgMBAAECggEACw/cOn5iUdgh2dm1ffmVPGpH9trMBv7yvk0Fmc/DSiut
bEgAkJFSDFUq5QQd0ZQ3+8WEtUhjD8TvqOuloUQeqBJqb7LU3vjngr0UF74/D5IS
Zu6jmd/mNkN0NDAiDy+RtFYJTVuDonvIsOHdt0vrtH9HHeHYNIa9J4Ll1jybOS1a
oalMPXiXZikxpvkEjX32Yi3I3L4YOF//yAR6iCQC/hsCRLwyh4T380IBSZV1/2tx
Ns6B+ybS73xLrV9X+lbZDTFzBYRKJgfGs/3iivnGvqxYVtlJDJm4E8bpINABF7dc
bEDIQdCftne1x5cL//6b8HL89YT1IRKbkhmzcp6iCQKBgQD7Hg4MzMHownTyDHBx
otx3oLJcPeQ+DkRktEZyBA761h3ihsAiJpPTy2653CwITLQwoLasIeE5i6+f1Exz
1DpcuH/ywSQKVK5RcvupnDO3Ccf2UqScL+XklyhsH6jmHipwB+KkLbPwiT3M6Vxn
sNUWJ5sFTcvJQx9AuCUEhnw+GQKBgQDlU64C8VRxVt+DSl5gxZMbtOv2cHgwutU5
SOq57L8lIn7EwgQyJAcAkzuBBVlbji6E+3GtUC3jGEDOMiRU9D25f2nx+Zla1YYt
zwprSapyYc5CYk+55sFpDIh0D29oJVMD2qkZ8CMMakA2z/DAvX1YDZmOvMCS8llh
+uUesl9DxQKBgBQQDqdPJJ7oClfcTo+Fp3+XQyjDeRzMHwK8tHQfhuLbgH+8rFUO
J/lf43TN9majWjIYZP/TpR7n3hwy5fjLF+6YfwByFeMNaO/w89JVPHx/N46ig6xG
12MwAHbDAMeB2Xoh5yWe0SWCkYFxk4RlSGEAwQ3nbUSjLDgLfkmiRQLhAoGAdz/H
SdJyRamV+rCOWSYENDElTnX3meddfzdSj7HzR30jjG8TPXuMhJkLJTFB4SETQaV6
3FPIOMHg2Rgr2l1TR4Vg8yoGu7wy1NlHorigwG/pkI2Mxa+fvV9+CVQJa4+VFnj6
2/kKUKdjkt0YZTFj34ja4+V1AjSxlAiiYg8BCL0CgYEAmwmyXqo1ZzbnuMmRu5Bl
Z3ift7jxvrMf7r93rLFkvS95D7xqYx+q1SvkK/+QtriEFGTUzFbC8mXJugZfmy/G
2rmLH8AwARYqwY6NIPHKl8k4mY6f5c1LYKDMskUGPiPeEnawMSSm64cu3MVjxi+a
dbhl6UebIeL+HnjKQ7xODw0=
-----END PRIVATE KEY-----
";

// ============================================
// CLI
// ============================================

struct Cli {
    host: String,
    port: u16,
    packets: usize,
    delay_ms: u64,
    artifacts: PathBuf,
    controller_log: PathBuf,
    json: PathBuf,
    spawn: bool,
    pause: bool,
    controller_bin: Option<PathBuf>,
    /// Se definido, só envia os cenários destes sensores (ex.: no teste com o
    /// ESP32 físico, o PC simula apenas o ESP-02).
    sensors: Option<Vec<String>>,
}

fn parse_cli() -> Result<Cli> {
    let mut c = Cli {
        host: "127.0.0.1".into(),
        port: 4242,
        packets: 50,
        delay_ms: 20,
        artifacts: "target/e2e_dinamicidade".into(),
        controller_log: "logs_dinamicidade/e2e_controller.log".into(),
        json: "logs_dinamicidade/resultados_e2e.json".into(),
        spawn: true,
        pause: true,
        controller_bin: None,
        sensors: None,
    };
    let mut no_spawn = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut v = |f: &str| args.next().with_context(|| format!("faltou o valor de {}", f));
        match a.as_str() {
            "--host" => c.host = v("--host")?,
            "--port" => c.port = v("--port")?.parse().context("--port inválido")?,
            "--packets" => c.packets = v("--packets")?.parse().context("--packets inválido")?,
            "--delay-ms" => c.delay_ms = v("--delay-ms")?.parse().context("--delay-ms inválido")?,
            "--artifacts" => c.artifacts = v("--artifacts")?.into(),
            "--controller-log" => c.controller_log = v("--controller-log")?.into(),
            "--json" => c.json = v("--json")?.into(),
            "--controller-bin" => c.controller_bin = Some(v("--controller-bin")?.into()),
            "--sensors" => {
                c.sensors = Some(v("--sensors")?.split(',').map(|s| s.trim().to_string()).collect())
            }
            "--no-spawn" => no_spawn = true,
            "--no-pause" => c.pause = false,
            "-h" | "--help" => {
                println!(
                    "uso: dynamic_e2e [--host 127.0.0.1] [--port 4242] [--packets 50] [--delay-ms 20] \
                     [--artifacts dir] [--controller-log arq] [--json arq] [--controller-bin exe] \
                     [--sensors ESP-02,...] [--no-spawn] [--no-pause]"
                );
                std::process::exit(0);
            }
            o => bail!("flag desconhecida: {}", o),
        }
    }
    if c.packets == 0 {
        bail!("--packets precisa ser > 0");
    }
    let loopback = c
        .host
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(c.host == "localhost");
    // Só é possível iniciar o controlador quando ele roda nesta mesma máquina.
    c.spawn = loopback && !no_spawn;
    Ok(c)
}

// ============================================
// CENÁRIOS
// ============================================

#[derive(Clone, Copy, PartialEq, Debug, Serialize)]
enum Expect {
    Aceito,
    RejeitadoV03Aritmetica,
}

struct Scenario {
    code: &'static str,
    desc: &'static str,
    sensor: &'static str,
    proof: &'static str, // nome do arquivo em <artifacts>/proofs/<proof>.proof
    expect: Expect,
    extra: bool, // controle adicional (além do roteiro mínimo)
}

struct Phase {
    num: u8,
    title: &'static str,
    acc: &'static str, // A1 | A2 | A3
    scenarios: Vec<Scenario>,
}

fn plan() -> Vec<Phase> {
    use Expect::*;
    vec![
        Phase {
            num: 1,
            title: "Fase 1 — Controlador com A1 = {ESP-01, ESP-02, ESP-42}",
            acc: "A1",
            scenarios: vec![
                Scenario { code: "F1-A", desc: "ESP-42 legítimo, proof de A1", sensor: "ESP-42", proof: "ESP_42_A1", expect: Aceito, extra: false },
                Scenario { code: "F1-B", desc: "ESP-02 legítimo, proof de A1 (controle)", sensor: "ESP-02", proof: "ESP_02_A1", expect: Aceito, extra: true },
            ],
        },
        Phase {
            num: 3,
            title: "Fase 3 — Controlador com A2 = {ESP-01, ESP-02} (chave do ESP-42 mantida no HashMap)",
            acc: "A2",
            scenarios: vec![
                Scenario { code: "F3-A", desc: "ESP-42 REVOGADO, assinatura RSA legítima + proof antiga (A1)", sensor: "ESP-42", proof: "ESP_42_A1", expect: RejeitadoV03Aritmetica, extra: false },
                Scenario { code: "F3-B", desc: "ESP-02 com witness DESATUALIZADA (A1)", sensor: "ESP-02", proof: "ESP_02_A1", expect: RejeitadoV03Aritmetica, extra: false },
                Scenario { code: "F3-C", desc: "ESP-02 com witness ATUALIZADA (A2)", sensor: "ESP-02", proof: "ESP_02_A2", expect: Aceito, extra: false },
            ],
        },
        Phase {
            num: 4,
            title: "Fase 4 — Controlador com A3 = {ESP-01, ESP-02, ESP-99}",
            acc: "A3",
            scenarios: vec![
                Scenario { code: "F4-A", desc: "ESP-99 NOVO sensor, proof de A3", sensor: "ESP-99", proof: "ESP_99_A3", expect: Aceito, extra: false },
                Scenario { code: "F4-B", desc: "ESP-02 com witness atualizada para A3", sensor: "ESP-02", proof: "ESP_02_A3", expect: Aceito, extra: false },
                Scenario { code: "F4-C", desc: "ESP-02 com witness de A2 (controle)", sensor: "ESP-02", proof: "ESP_02_A2", expect: RejeitadoV03Aritmetica, extra: true },
                Scenario { code: "F4-D", desc: "ESP-42 revogado, proof de A1 (controle)", sensor: "ESP-42", proof: "ESP_42_A1", expect: RejeitadoV03Aritmetica, extra: true },
            ],
        },
    ]
}

// ============================================
// PACOTE (formato idêntico ao ESP32 / attack_tests.py)
// ============================================

#[derive(Serialize)]
struct Payload<'a> {
    #[serde(rename = "1")]
    id: &'a str,
    #[serde(rename = "2")]
    timestamp: u64,
    #[serde(rename = "3")]
    reading: u64,
    #[serde(rename = "4", with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(rename = "5", with = "serde_bytes")]
    membership_proof: &'a [u8],
}

fn build_packet(key: &RsaPrivateKey, id: &str, reading: u64, proof: &[u8]) -> Result<Vec<u8>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let digest = Sha256::digest(format!("{}|{}|{}", id, timestamp, reading).as_bytes());
    let signature = key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)?;
    Ok(serde_cbor::to_vec(&Payload {
        id,
        timestamp,
        reading,
        signature,
        membership_proof: proof,
    })?)
}

// ============================================
// CONTROLADOR (processo filho) — modo local
// ============================================

struct Controller {
    child: Child,
    lines: mpsc::Receiver<String>,
    captured: Vec<String>,
}

fn controller_bin(cli: &Cli) -> Result<PathBuf> {
    if let Some(p) = &cli.controller_bin {
        return Ok(p.clone());
    }
    let exe = std::env::current_exe()?;
    let name = if cfg!(windows) { "udp_controller.exe" } else { "udp_controller" };
    let p = exe.parent().context("sem diretório do executável")?.join(name);
    if !p.exists() {
        bail!(
            "udp_controller não encontrado em {} — compile com `cargo build --release --bin udp_controller`",
            p.display()
        );
    }
    Ok(p)
}

fn controller_args(cli: &Cli, acc: &str, max_packets: Option<usize>, local: bool) -> Vec<String> {
    let art = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let mut args = vec![
        "--acc".to_string(),
        art(&cli.artifacts.join(format!("accumulator_{}.dat", acc))),
        "--pubkey".to_string(),
        format!("ESP-02={}", art(&cli.artifacts.join("keys/ESP_02.pub.pem"))),
        "--pubkey".to_string(),
        format!("ESP-99={}", art(&cli.artifacts.join("keys/ESP_99.pub.pem"))),
    ];
    if let Some(max) = max_packets {
        args.push("--max-packets".to_string());
        args.push(max.to_string());
    }
    if local {
        args.push("--bind".to_string());
        args.push(format!("127.0.0.1:{}", cli.port));
    }
    args
}

fn spawn_controller(bin: &Path, args: &[String]) -> Result<Controller> {
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("falha ao iniciar {}", bin.display()))?;
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let tx2 = tx.clone();
    std::thread::spawn(move || {
        for l in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    std::thread::spawn(move || {
        for l in BufReader::new(err).lines().map_while(Result::ok) {
            if tx2.send(format!("[stderr] {}", l)).is_err() {
                break;
            }
        }
    });
    let mut c = Controller {
        child,
        lines: rx,
        captured: Vec::new(),
    };
    // Aguarda o socket estar pronto.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match c.lines.recv_timeout(left) {
            Ok(l) => {
                let ready = l.contains("Aguardando pacotes UDP");
                c.captured.push(l);
                if ready {
                    return Ok(c);
                }
            }
            Err(_) => {
                let _ = c.child.kill();
                bail!(
                    "controlador não ficou pronto em 30 s. Saída:\n{}",
                    c.captured.join("\n")
                );
            }
        }
    }
}

fn finish_controller(mut c: Controller) -> (Vec<String>, bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut exited = false;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = c.child.try_wait() {
            exited = true;
            break;
        }
        while let Ok(l) = c.lines.try_recv() {
            c.captured.push(l);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !exited {
        let _ = c.child.kill();
        let _ = c.child.wait();
    }
    // Drena o restante (as threads terminam quando os pipes fecham).
    while let Ok(l) = c.lines.recv_timeout(Duration::from_millis(500)) {
        c.captured.push(l);
    }
    (c.captured, exited)
}

/// Desfecho de cada pacote, na ordem em que o controlador os processou.
#[derive(Debug, Clone)]
struct Outcome {
    layer: String,
    ms: Option<f64>,
}

fn classify(status: &str) -> String {
    let s = status.trim();
    if s.starts_with("ACEITO") {
        "ACEITO"
    } else if s.contains("V03 Aritmética") {
        "REJEITADO_V03_ARITMETICA"
    } else if s.contains("V03 Sintática") {
        "REJEITADO_V03_SINTATICA"
    } else if s.contains("Assinatura Inválida") {
        "REJEITADO_V02_ASSINATURA"
    } else if s.contains("Sensor Desconhecido") {
        "REJEITADO_V02_SENSOR_DESCONHECIDO"
    } else if s.contains("Replay Intra-Janela") {
        "REJEITADO_V01b_DUPLICATA"
    } else if s.contains("Replay Attack") {
        "REJEITADO_V01_TIMESTAMP"
    } else if s.contains("CBOR Externo") {
        "REJEITADO_C00_CBOR"
    } else {
        "DESCONHECIDO"
    }
    .to_string()
}

fn parse_outcomes(lines: &[String]) -> Vec<Outcome> {
    let mut out: Vec<Outcome> = Vec::new();
    for l in lines {
        if let Some(rest) = l.trim_start().strip_prefix("Status:") {
            out.push(Outcome {
                layer: classify(rest),
                ms: None,
            });
        } else if let Some(rest) = l
            .trim_start()
            .strip_prefix("Tempo de verificação no controlador (ms):")
        {
            if let Some(last) = out.last_mut() {
                last.ms = rest.trim().parse().ok();
            }
        }
    }
    out
}

// ============================================
// RESULTADOS
// ============================================

#[derive(Serialize)]
struct ScenarioResult {
    phase: u8,
    accumulator: &'static str,
    code: &'static str,
    description: &'static str,
    sensor: &'static str,
    proof_file: String,
    proof_bytes: usize,
    additional_control: bool,
    expected: Expect,
    sent: usize,
    observed_by_layer: BTreeMap<String, usize>,
    accepted: usize,
    rejected: usize,
    acceptance_rate_pct: f64,
    controller_verify_ms_mean: Option<f64>,
    controller_verify_ms_median: Option<f64>,
    verified_from_controller_log: bool,
    pass: bool,
}

fn mean_median(v: &[f64]) -> (Option<f64>, Option<f64>) {
    if v.is_empty() {
        return (None, None);
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    let med = if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 };
    (Some(s.iter().sum::<f64>() / n as f64), Some(med))
}

fn expected_layer(e: Expect) -> &'static str {
    match e {
        Expect::Aceito => "ACEITO",
        Expect::RejeitadoV03Aritmetica => "REJEITADO_V03_ARITMETICA",
    }
}

// ============================================
// MAIN
// ============================================

fn main() -> Result<()> {
    let cli = parse_cli()?;
    let target = format!("{}:{}", cli.host, cli.port);

    println!("═══════════════════════════════════════════════════════════════════════");
    println!("  dynamic_e2e — Revogação e adição fim-a-fim via UDP (porta {})", cli.port);
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("  Destino:        {}", target);
    println!("  Pacotes/cenário: {} (intervalo {} ms)", cli.packets, cli.delay_ms);
    println!("  Artefatos TMC:  {}", cli.artifacts.display());
    println!(
        "  Modo:           {}",
        if cli.spawn {
            "LOCAL — o teste inicia o udp_controller em cada fase e confere a saída dele"
        } else {
            "REMOTO — o udp_controller roda no Raspberry Pi; conferir o log de lá"
        }
    );

    // ── Material: chaves e proofs ─────────────────────────────────────
    let mut keys: HashMap<&str, RsaPrivateKey> = HashMap::new();
    keys.insert("ESP-42", RsaPrivateKey::from_pkcs8_pem(ESP42_PRIVATE_KEY_PEM)?);
    for (id, f) in [("ESP-02", "ESP_02.key.pem"), ("ESP-99", "ESP_99.key.pem")] {
        let p = cli.artifacts.join("keys").join(f);
        let pem = fs::read_to_string(&p).with_context(|| {
            format!(
                "chave {} não encontrada em {} — rode `cargo run --release --bin dynamic_tmc` antes",
                id,
                p.display()
            )
        })?;
        keys.insert(id, RsaPrivateKey::from_pkcs8_pem(&pem)?);
    }
    let load_proof = |name: &str| -> Result<Vec<u8>> {
        let p = cli.artifacts.join("proofs").join(format!("{}.proof", name));
        fs::read(&p).with_context(|| format!("proof não encontrada: {}", p.display()))
    };

    let bin = if cli.spawn { Some(controller_bin(&cli)?) } else { None };
    if let Some(dir) = cli.controller_log.parent() {
        fs::create_dir_all(dir)?;
    }
    if let Some(dir) = cli.json.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut ctrl_log = if cli.spawn {
        Some(fs::File::create(&cli.controller_log)?)
    } else {
        None
    };

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut readings: HashMap<&str, u64> = HashMap::new();
    let mut results: Vec<ScenarioResult> = Vec::new();
    let mut all_pass = true;

    for phase in plan() {
        // A Fase 2 acontece no TMC (offline); é registrada antes da Fase 3.
        if phase.num == 3 {
            println!("\n───────────────────────────────────────────────────────────────────────");
            println!(" Fase 2 — TMC (offline): revogação do ESP-42 e atualização da witness do ESP-02");
            println!("───────────────────────────────────────────────────────────────────────");
            let manifest = cli.artifacts.join("tmc_manifest.json");
            match fs::read_to_string(&manifest)
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            {
                Some(m) => {
                    for k in [
                        "A2_revoke_delete_ESP42",
                        "A2_witness_update_ESP02",
                        "A2_proof_regen_ESP02",
                    ] {
                        println!("   {:<28} {:>9.4} ms", k, m["timings_ms"][k].as_f64().unwrap_or(f64::NAN));
                    }
                    println!("   Novo acumulador: accumulator_A2.dat | nova proof: proofs/ESP_02_A2.proof");
                }
                None => println!("   (tmc_manifest.json não encontrado em {})", manifest.display()),
            }
            if let Some(f) = ctrl_log.as_mut() {
                writeln!(f, "\n##### FASE 2 — TMC offline (dynamic_tmc): sem controlador em execução #####\n")?;
            }
        }

        let mut phase = phase;
        if let Some(only) = &cli.sensors {
            phase.scenarios.retain(|sc| only.iter().any(|s| s == sc.sensor));
        }
        let total: usize = phase.scenarios.len() * cli.packets;
        println!("\n───────────────────────────────────────────────────────────────────────");
        println!(" {}", phase.title);
        println!("───────────────────────────────────────────────────────────────────────");
        // Modo remoto (ESP32 físico enviando sem parar): sem --max-packets; a fase
        // termina com Ctrl+C no Raspberry Pi, que imprime o resumo da sessão.
        let max = if cli.spawn { Some(total) } else { None };
        let args = controller_args(&cli, phase.acc, max, cli.spawn);

        let controller = match &bin {
            Some(b) => {
                println!("   Iniciando: udp_controller {}", args.join(" "));
                Some(spawn_controller(b, &args)?)
            }
            None => {
                println!("   No Raspberry Pi (pasta do pacote dist/rpi-aarch64), execute:");
                println!("     ./rodar_fase.sh {}        (equivale a: ./udp_controller {})", phase.acc, args.join(" "));
                println!("   Encerre a fase com Ctrl+C no Pi depois que os pacotes do PC/ESP32 chegarem.");
                if cli.pause {
                    print!("   Pressione ENTER quando o controlador estiver aguardando pacotes... ");
                    std::io::stdout().flush()?;
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s)?;
                }
                None
            }
        };

        // ── Envio ────────────────────────────────────────────────────
        let mut sent_meta: Vec<(usize, usize)> = Vec::new(); // (idx cenário, bytes proof)
        for (si, sc) in phase.scenarios.iter().enumerate() {
            let proof = load_proof(sc.proof)?;
            let key = &keys[sc.sensor];
            print!("   {} [{}] enviando {} pacotes... ", sc.code, sc.sensor, cli.packets);
            std::io::stdout().flush()?;
            for _ in 0..cli.packets {
                let r = readings.entry(sc.sensor).or_insert(0);
                *r += 1;
                let pkt = build_packet(key, sc.sensor, *r, &proof)?;
                sock.send_to(&pkt, &target)?;
                std::thread::sleep(Duration::from_millis(cli.delay_ms));
            }
            println!("ok");
            sent_meta.push((si, proof.len()));
        }

        // ── Coleta da saída do controlador ──────────────────────────
        let outcomes = match controller {
            Some(c) => {
                let (lines, exited) = finish_controller(c);
                if let Some(f) = ctrl_log.as_mut() {
                    writeln!(f, "\n##### FASE {} — udp_controller {} #####\n", phase.num, args.join(" "))?;
                    for l in &lines {
                        writeln!(f, "{}", l)?;
                    }
                }
                if !exited {
                    println!("   ⚠  controlador não encerrou sozinho (pacotes perdidos?) — processo finalizado");
                }
                Some(parse_outcomes(&lines))
            }
            None => None,
        };

        // ── Avaliação por cenário ───────────────────────────────────
        for (si, proof_len) in sent_meta {
            let sc = &phase.scenarios[si];
            let mut by_layer: BTreeMap<String, usize> = BTreeMap::new();
            let mut times = Vec::new();
            let verified = outcomes.is_some();
            if let Some(outs) = &outcomes {
                let start = si * cli.packets;
                for o in outs.iter().skip(start).take(cli.packets) {
                    *by_layer.entry(o.layer.clone()).or_insert(0) += 1;
                    if let Some(ms) = o.ms {
                        times.push(ms);
                    }
                }
                let seen: usize = by_layer.values().sum();
                if seen < cli.packets {
                    by_layer.insert("NAO_PROCESSADO".into(), cli.packets - seen);
                }
            }
            let accepted = *by_layer.get("ACEITO").unwrap_or(&0);
            let observed: usize = by_layer.values().sum();
            let rejected = observed - accepted - by_layer.get("NAO_PROCESSADO").copied().unwrap_or(0);
            let pass = verified
                && by_layer.get(expected_layer(sc.expect)).copied().unwrap_or(0) == cli.packets;
            if verified {
                all_pass &= pass;
            }
            let (mean, med) = mean_median(&times);
            results.push(ScenarioResult {
                phase: phase.num,
                accumulator: phase.acc,
                code: sc.code,
                description: sc.desc,
                sensor: sc.sensor,
                proof_file: format!("proofs/{}.proof", sc.proof),
                proof_bytes: proof_len,
                additional_control: sc.extra,
                expected: sc.expect,
                sent: cli.packets,
                observed_by_layer: by_layer,
                accepted,
                rejected,
                acceptance_rate_pct: if verified { 100.0 * accepted as f64 / cli.packets as f64 } else { f64::NAN },
                controller_verify_ms_mean: mean,
                controller_verify_ms_median: med,
                verified_from_controller_log: verified,
                pass,
            });
        }
    }

    // ── Relatório ────────────────────────────────────────────────────
    println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════");
    println!("  RESULTADO FIM-A-FIM (desfecho de cada pacote extraído do stdout do udp_controller)");
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════");
    println!(
        "  {:<5} {:<3} {:<7} {:>6} {:>8} {:>9} {:>8}  {:<26} {:<26} {}",
        "Cen.", "Acc", "Sensor", "Envio", "Aceitos", "Rejeit.", "t̄ (ms)", "Esperado", "Camada observada", "OK?"
    );
    for r in &results {
        let observed = r
            .observed_by_layer
            .iter()
            .map(|(k, v)| format!("{}×{}", k, v))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {:<5} {:<3} {:<7} {:>6} {:>8} {:>9} {:>8}  {:<26} {:<26} {}{}",
            r.code,
            r.accumulator,
            r.sensor,
            r.sent,
            if r.verified_from_controller_log { r.accepted.to_string() } else { "?".into() },
            if r.verified_from_controller_log { r.rejected.to_string() } else { "?".into() },
            r.controller_verify_ms_mean.map(|v| format!("{:.3}", v)).unwrap_or("-".into()),
            expected_layer(r.expected),
            if observed.is_empty() { "(ver log do controlador)".into() } else { observed },
            if !r.verified_from_controller_log { "—" } else if r.pass { "PASSOU" } else { "FALHOU" },
            if r.additional_control { "  (controle adicional)" } else { "" },
        );
    }
    for r in &results {
        println!("    {}: {}", r.code, r.description);
    }

    fs::write(&cli.json, serde_json::to_string_pretty(&results)?)?;
    println!("\n✓ Resultados JSON: {}", cli.json.display());
    if cli.spawn {
        println!("✓ Log do controlador: {}", cli.controller_log.display());
        if all_pass {
            println!("\n✅ TODOS OS CENÁRIOS SE COMPORTARAM COMO ESPERADO.");
        } else {
            println!("\n❌ HÁ CENÁRIOS COM DESFECHO DIFERENTE DO ESPERADO.");
            std::process::exit(1);
        }
    }
    Ok(())
}
