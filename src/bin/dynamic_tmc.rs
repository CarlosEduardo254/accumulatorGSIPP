// ═══════════════════════════════════════════════════════════════════════
// dynamic_tmc — TMC (offline) do experimento de dinamicidade fim-a-fim
// ═══════════════════════════════════════════════════════════════════════
//
// Gera, usando SOMENTE a API dinâmica da biblioteca Cambrian modificada,
// os três estados do acumulador usados no teste fim-a-fim (dynamic_e2e):
//
//   A1 = {ESP-01, ESP-02, ESP-42}            (setup inicial, idêntico ao SnifferESP/setup)
//   A2 = A1.delete([(ESP-42, w42)])          (revogação SEM trapdoor — Shamir trick)
//        w02' = A2.update_membership_witness(w02, [ESP-02], [], [ESP-42])
//   A3 = A2.add([ESP-99])                    (join de um novo sensor)
//        proof99 = A3.prove_membership([(ESP-99, Witness(A2))])
//        w02'' = A3.update_membership_witness(w02', [ESP-02], [ESP-99], [])
//
// Artefatos gravados em <out-dir> (padrão target/e2e_dinamicidade):
//   accumulator_A1.dat, accumulator_A2.dat, accumulator_A3.dat   (CBOR, formato do accumulator.dat)
//   proofs/ESP_42_A1.proof  proofs/ESP_02_A1.proof               (proofs de A1)
//   proofs/ESP_02_A2.proof                                        (witness atualizada p/ A2)
//   proofs/ESP_99_A3.proof  proofs/ESP_02_A3.proof               (proofs de A3)
//   keys/ESP_02.{key,pub}.pem  keys/ESP_99.{key,pub}.pem         (chaves RSA-2048 de TESTE)
//   tmc_manifest.json                                             (tempos, tamanhos, checagens)
//
// O SnifferESP/accumulator.dat e as proofs do firmware NÃO são alterados.
//
// Uso: cargo run --release --bin dynamic_tmc -- [--out-dir target/e2e_dinamicidade]

use accumulator::group::Rsa2048;
use accumulator::{Accumulator, MembershipProof, Witness};
use anyhow::{Context, Result};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

type Acc = Accumulator<Rsa2048, String>;
type Wit = Witness<Rsa2048, String>;
type Proof = MembershipProof<Rsa2048, String>;

#[derive(Serialize)]
struct Manifest {
    a1: Vec<&'static str>,
    a2: Vec<&'static str>,
    a3: Vec<&'static str>,
    accumulator_files: BTreeMap<String, String>,
    proof_files: BTreeMap<String, String>,
    public_key_files: BTreeMap<String, String>,
    private_key_files: BTreeMap<String, String>,
    timings_ms: BTreeMap<String, f64>,
    sizes_bytes: BTreeMap<String, usize>,
    checks: BTreeMap<String, bool>,
}

fn timed<R>(f: impl FnOnce() -> R) -> (R, f64) {
    let t = Instant::now();
    let r = f();
    (r, t.elapsed().as_secs_f64() * 1000.0)
}

fn s(x: &str) -> String {
    x.to_string()
}

fn write(path: &Path, bytes: &[u8]) -> Result<String> {
    fs::write(path, bytes).with_context(|| format!("Falha ao gravar {}", path.display()))?;
    Ok(path.to_string_lossy().replace('\\', "/"))
}

fn main() -> Result<()> {
    let mut out_dir = PathBuf::from("target/e2e_dinamicidade");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out-dir" => out_dir = PathBuf::from(args.next().context("faltou --out-dir <dir>")?),
            "-h" | "--help" => {
                println!("uso: dynamic_tmc [--out-dir target/e2e_dinamicidade]");
                return Ok(());
            }
            other => anyhow::bail!("flag desconhecida: {}", other),
        }
    }
    fs::create_dir_all(out_dir.join("proofs"))?;
    fs::create_dir_all(out_dir.join("keys"))?;

    println!("═══════════════════════════════════════════════════════════");
    println!("  dynamic_tmc — TMC offline: A1 → (revoga ESP-42) A2 → (join ESP-99) A3");
    println!("═══════════════════════════════════════════════════════════");
    if cfg!(debug_assertions) {
        println!("  ⚠  Build de DEBUG: tempos e geração de chaves RSA serão lentos.");
    }

    let mut m = Manifest {
        a1: vec!["ESP-01", "ESP-02", "ESP-42"],
        a2: vec!["ESP-01", "ESP-02"],
        a3: vec!["ESP-01", "ESP-02", "ESP-99"],
        accumulator_files: BTreeMap::new(),
        proof_files: BTreeMap::new(),
        public_key_files: BTreeMap::new(),
        private_key_files: BTreeMap::new(),
        timings_ms: BTreeMap::new(),
        sizes_bytes: BTreeMap::new(),
        checks: BTreeMap::new(),
    };

    // ── Setup: A1 ────────────────────────────────────────────────────
    let ids_a1: Vec<String> = m.a1.iter().map(|x| s(x)).collect();
    let (a1, t) = timed(|| Acc::empty().add(&ids_a1));
    m.timings_ms.insert(s("A1_setup_add_3"), t);
    let (wits_a1, t) = timed(|| Witness(Acc::empty()).compute_individual_witnesses(&ids_a1));
    m.timings_ms.insert(s("A1_setup_witnesses_3"), t);
    let wit = |id: &str| -> Wit {
        wits_a1
            .iter()
            .find(|(x, _)| x == id)
            .map(|(_, w)| w.clone())
            .unwrap()
    };
    let w42_a1 = wit("ESP-42");
    let w02_a1 = wit("ESP-02");
    let acc_err = |e: accumulator::AccError| anyhow::anyhow!("erro do acumulador: {:?}", e);
    let p42_a1: Proof = a1
        .prove_membership(&[(s("ESP-42"), w42_a1.clone())])
        .map_err(acc_err)?;
    let p02_a1: Proof = a1
        .prove_membership(&[(s("ESP-02"), w02_a1.clone())])
        .map_err(acc_err)?;
    assert!(a1.verify_membership(&s("ESP-42"), &p42_a1));
    assert!(a1.verify_membership(&s("ESP-02"), &p02_a1));
    println!("\n[Setup] A1 = {{ESP-01, ESP-02, ESP-42}} — proofs de ESP-42 e ESP-02 geradas");

    // Consistência com o setup original do firmware (se os arquivos existirem).
    if let Ok(orig) = fs::read("SnifferESP/accumulator.dat") {
        let same = orig == serde_cbor::to_vec(&a1)?;
        m.checks.insert(s("A1_igual_SnifferESP_accumulator_dat"), same);
        println!("        A1 == SnifferESP/accumulator.dat ? {}", same);
    }
    if let Ok(orig) = fs::read("SnifferESP/proofs/ESP_42.proof") {
        let same = orig == serde_cbor::to_vec(&p42_a1)?;
        m.checks.insert(s("proof_ESP42_A1_igual_firmware"), same);
        println!("        proof ESP-42 (A1) == SnifferESP/proofs/ESP_42.proof ? {}", same);
    }

    // ── Fase 2: revogação do ESP-42 → A2 ─────────────────────────────
    let del_in = [(s("ESP-42"), w42_a1.clone())];
    let a1_in = a1.clone();
    let (a2, t) = timed(|| a1_in.delete(&del_in));
    let a2 = a2.map_err(|e| anyhow::anyhow!("delete falhou: {:?}", e))?;
    m.timings_ms.insert(s("A2_revoke_delete_ESP42"), t);

    let (w02_a2, t) = timed(|| {
        a2.update_membership_witness(w02_a1.clone(), &[s("ESP-02")], &[], &[s("ESP-42")])
    });
    let w02_a2 = w02_a2.map_err(|e| anyhow::anyhow!("update witness falhou: {:?}", e))?;
    m.timings_ms.insert(s("A2_witness_update_ESP02"), t);
    let (p02_a2, t) = timed(|| a2.prove_membership(&[(s("ESP-02"), w02_a2.clone())]));
    let p02_a2 = p02_a2.map_err(|e| anyhow::anyhow!("prove falhou: {:?}", e))?;
    m.timings_ms.insert(s("A2_proof_regen_ESP02"), t);

    let ids_a2: Vec<String> = m.a2.iter().map(|x| s(x)).collect();
    m.checks.insert(s("A2_igual_reconstrucao_do_zero"), a2 == Acc::empty().add(&ids_a2));
    m.checks.insert(s("A2_ESP42_proof_antiga_rejeitada"), !a2.verify_membership(&s("ESP-42"), &p42_a1));
    m.checks.insert(s("A2_ESP02_proof_A1_rejeitada"), !a2.verify_membership(&s("ESP-02"), &p02_a1));
    m.checks.insert(s("A2_ESP02_proof_A2_aceita"), a2.verify_membership(&s("ESP-02"), &p02_a2));
    println!("\n[Fase 2] Revogação: A2 = A1.delete([(ESP-42, w42)])  →  A2 = {{ESP-01, ESP-02}}");
    println!("         witness de ESP-02 atualizada (LLX) e nova PoE gerada");

    // ── Fase 4: join do ESP-99 → A3 ──────────────────────────────────
    let a2_in = a2.clone();
    let (a3, t) = timed(|| a2_in.add(&[s("ESP-99")]));
    m.timings_ms.insert(s("A3_join_add_ESP99"), t);
    let (p99_a3, t) = timed(|| a3.prove_membership(&[(s("ESP-99"), Witness(a2.clone()))]));
    let p99_a3 = p99_a3.map_err(|e| anyhow::anyhow!("prove ESP-99 falhou: {:?}", e))?;
    m.timings_ms.insert(s("A3_proof_new_ESP99"), t);
    let (w02_a3, t) = timed(|| {
        a3.update_membership_witness(w02_a2.clone(), &[s("ESP-02")], &[s("ESP-99")], &[])
    });
    let w02_a3 = w02_a3.map_err(|e| anyhow::anyhow!("update witness falhou: {:?}", e))?;
    m.timings_ms.insert(s("A3_witness_update_ESP02"), t);
    let (p02_a3, t) = timed(|| a3.prove_membership(&[(s("ESP-02"), w02_a3.clone())]));
    let p02_a3 = p02_a3.map_err(|e| anyhow::anyhow!("prove falhou: {:?}", e))?;
    m.timings_ms.insert(s("A3_proof_regen_ESP02"), t);

    let ids_a3: Vec<String> = m.a3.iter().map(|x| s(x)).collect();
    m.checks.insert(s("A3_igual_reconstrucao_do_zero"), a3 == Acc::empty().add(&ids_a3));
    m.checks.insert(s("A3_ESP99_proof_aceita"), a3.verify_membership(&s("ESP-99"), &p99_a3));
    m.checks.insert(s("A3_ESP02_proof_A3_aceita"), a3.verify_membership(&s("ESP-02"), &p02_a3));
    m.checks.insert(s("A3_ESP02_proof_A2_rejeitada"), !a3.verify_membership(&s("ESP-02"), &p02_a2));
    m.checks.insert(s("A3_ESP42_proof_antiga_rejeitada"), !a3.verify_membership(&s("ESP-42"), &p42_a1));
    println!("\n[Fase 4] Join: A3 = A2.add([ESP-99])  →  A3 = {{ESP-01, ESP-02, ESP-99}}");
    println!("         proof do ESP-99 gerada (witness = A2); witness de ESP-02 atualizada");

    // ── Gravação dos artefatos ───────────────────────────────────────
    for (name, acc) in [("A1", &a1), ("A2", &a2), ("A3", &a3)] {
        let bytes = serde_cbor::to_vec(acc)?;
        m.sizes_bytes.insert(format!("accumulator_{}", name), bytes.len());
        let p = write(&out_dir.join(format!("accumulator_{}.dat", name)), &bytes)?;
        m.accumulator_files.insert(s(name), p);
    }
    for (name, proof) in [
        ("ESP_42_A1", &p42_a1),
        ("ESP_02_A1", &p02_a1),
        ("ESP_02_A2", &p02_a2),
        ("ESP_02_A3", &p02_a3),
        ("ESP_99_A3", &p99_a3),
    ] {
        let bytes = serde_cbor::to_vec(proof)?;
        m.sizes_bytes.insert(format!("proof_{}", name), bytes.len());
        let p = write(&out_dir.join("proofs").join(format!("{}.proof", name)), &bytes)?;
        m.proof_files.insert(s(name), p);
    }

    // Chaves RSA-2048 de TESTE para ESP-02 e ESP-99 (o ESP-42 usa a chave do firmware).
    // Chaves já existentes são REAPROVEITADAS: o ESP32 gravado e o controlador no
    // Raspberry Pi continuam consistentes mesmo que o TMC seja executado de novo.
    println!("\n[Chaves] Pares RSA-2048 de teste para ESP-02 e ESP-99:");
    for id in ["ESP-02", "ESP-99"] {
        let stem = id.replace('-', "_");
        let sk_path = out_dir.join("keys").join(format!("{}.key.pem", stem));
        let sk = match fs::read_to_string(&sk_path) {
            Ok(pem) => {
                println!("   {} — reaproveitando {}", id, sk_path.display());
                RsaPrivateKey::from_pkcs8_pem(&pem)
                    .with_context(|| format!("chave inválida em {}", sk_path.display()))?
            }
            Err(_) => {
                println!("   {} — gerando novo par", id);
                RsaPrivateKey::new(&mut OsRng, 2048).context("geração de chave RSA falhou")?
            }
        };
        let pk = RsaPublicKey::from(&sk);
        let sk_pem = sk.to_pkcs8_pem(LineEnding::LF)?;
        let pk_pem = pk.to_public_key_pem(LineEnding::LF)?;
        let p = write(&out_dir.join("keys").join(format!("{}.key.pem", stem)), sk_pem.as_bytes())?;
        m.private_key_files.insert(s(id), p);
        let p = write(&out_dir.join("keys").join(format!("{}.pub.pem", stem)), pk_pem.as_bytes())?;
        m.public_key_files.insert(s(id), p);
    }

    let manifest_path = out_dir.join("tmc_manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&m)?)?;

    println!("\n  Tempos no TMC (ms):");
    for (k, v) in &m.timings_ms {
        println!("    {:<32} {:>10.4}", k, v);
    }
    println!("\n  Tamanhos (bytes):");
    for (k, v) in &m.sizes_bytes {
        println!("    {:<32} {:>10}", k, v);
    }
    println!("\n  Checagens matemáticas:");
    let mut all_ok = true;
    for (k, v) in &m.checks {
        println!("    [{}] {}", if *v { "OK" } else { "FALHOU" }, k);
        all_ok &= *v;
    }
    println!("\n✓ Artefatos gravados em '{}'", out_dir.display());
    println!("✓ Manifesto: '{}'", manifest_path.display());
    if !all_ok {
        anyhow::bail!("alguma checagem matemática falhou — veja acima");
    }
    Ok(())
}
