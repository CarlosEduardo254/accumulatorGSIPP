// ═══════════════════════════════════════════════════════════════════════
// dynamic_bench — Escalabilidade e operações dinâmicas do Acumulador RSA-2048
// (Arquitetura TCC GSIPP — experimento de dinamicidade)
// ═══════════════════════════════════════════════════════════════════════
//
// Mede, para cada tamanho de rede N (padrão: 10, 50, 100, 500, 1000):
//
//   1. Acumulação inicial (TMC, offline)
//        - Accumulator::empty().add(&ids)                          → A = g^(∏ H(id))
//        - Witness(empty).compute_individual_witnesses(&ids)       → N witnesses (RootFactor)
//        - tamanho do acumulador serializado (CBOR, igual ao accumulator.dat)
//   2. Adição dinâmica (Node Join)
//        - acc.add(&[novo])                                         → A' = A^H(novo)
//        - acc'.prove_membership(&[(novo, Witness(A))])             → MembershipProof do novo
//        - acc'.update_membership_witness(w_i, [id_i], [novo], [])  → witness de 1 sensor
//        - acc'.prove_membership(&[(id_i, w_i')])                   → nova PoE desse sensor
//        - update_membership_witness em lote para as N witnesses
//   3. Revogação dinâmica (Node Revocation)
//        - acc.delete(&[(id_j, w_j)])   — deleção SEM trapdoor (Shamir trick): exige a
//                                         witness do elemento removido; A' = w_j
//        - acc'.update_membership_witness(w_i, [id_i], [], [id_j])  → witness de 1 legítimo
//        - acc'.prove_membership(&[(id_i, w_i')])                   → nova PoE
//        - update_membership_witness em lote para as N-1 witnesses remanescentes
//   4. Verificação no controlador
//        - acc.verify_membership(id, proof)          (somente aritmética)
//        - serde_cbor::from_slice + verify_membership (como no udp_controller, V03a+V03b)
//        - tamanho da MembershipProof serializada
//
// Todas as amostras são registradas (JSON) e resumidas por média, mediana,
// desvio-padrão amostral, p95 (nearest-rank), mínimo e máximo.
//
// Uso (da raiz do repositório):
//   cargo run --release --bin dynamic_bench
//   cargo run --release --bin dynamic_bench -- --ns 10,50,100,500,1000 --reps 20 \
//       --heavy-reps 5 --verify-reps 200 --out resultados_dinamicidade.json
//
// Flags:
//   --ns <lista>         valores de N separados por vírgula (padrão 10,50,100,500,1000)
//   --reps <k>           repetições das operações unitárias (join/revogação)   (padrão 20)
//   --heavy-reps <k>     repetições das operações O(N)/O(N log N): setup e lotes (padrão 5)
//   --verify-reps <k>    repetições da verificação no controlador               (padrão 200)
//   --skip-batch         não mede as atualizações em lote (útil no Raspberry Pi)
//   --out <arquivo>      JSON de saída (padrão resultados_dinamicidade.json)

use accumulator::group::{Group, Rsa2048, UnknownOrderGroup};
use accumulator::hash::hash_to_prime;
use accumulator::{Accumulator, MembershipProof, Witness};
use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type Acc = Accumulator<Rsa2048, String>;
type Wit = Witness<Rsa2048, String>;
type Proof = MembershipProof<Rsa2048, String>;

// ============================================
// CLI
// ============================================

#[derive(Debug, Serialize)]
struct Config {
    ns: Vec<usize>,
    reps: usize,
    heavy_reps: usize,
    verify_reps: usize,
    skip_batch: bool,
    out: String,
}

fn parse_args() -> Config {
    let mut cfg = Config {
        ns: vec![10, 50, 100, 500, 1000],
        reps: 20,
        heavy_reps: 5,
        verify_reps: 200,
        skip_batch: false,
        out: "resultados_dinamicidade.json".to_string(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let value = |i: usize, flag: &str| -> String {
        args.get(i + 1)
            .cloned()
            .unwrap_or_else(|| usage_exit(&format!("faltou o valor de {}", flag)))
    };
    let num = |s: String, flag: &str| -> usize {
        s.trim()
            .parse::<usize>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or_else(|| usage_exit(&format!("valor inválido para {}: {}", flag, s)))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--ns" => {
                cfg.ns = value(i, "--ns")
                    .split(',')
                    .map(|s| num(s.to_string(), "--ns"))
                    .collect();
                i += 1;
            }
            "--reps" => {
                cfg.reps = num(value(i, "--reps"), "--reps");
                i += 1;
            }
            "--heavy-reps" => {
                cfg.heavy_reps = num(value(i, "--heavy-reps"), "--heavy-reps");
                i += 1;
            }
            "--verify-reps" => {
                cfg.verify_reps = num(value(i, "--verify-reps"), "--verify-reps");
                i += 1;
            }
            "--out" => {
                cfg.out = value(i, "--out");
                i += 1;
            }
            "--skip-batch" => cfg.skip_batch = true,
            "-h" | "--help" => usage_exit(""),
            other => usage_exit(&format!("flag desconhecida: {}", other)),
        }
        i += 1;
    }
    if cfg.ns.iter().any(|n| *n < 2) {
        usage_exit("todo N precisa ser >= 2 (a revogação precisa de um sensor remanescente)");
    }
    cfg
}

fn usage_exit(msg: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("erro: {}\n", msg);
    }
    eprintln!(
        "uso: dynamic_bench [--ns 10,50,100,500,1000] [--reps 20] [--heavy-reps 5] \
         [--verify-reps 200] [--skip-batch] [--out resultados_dinamicidade.json]"
    );
    std::process::exit(if msg.is_empty() { 0 } else { 2 })
}

// ============================================
// ESTATÍSTICAS
// ============================================

#[derive(Debug, Clone, Serialize)]
struct Stats {
    n: usize,
    mean: f64,
    median: f64,
    std: f64,
    p95: f64,
    min: f64,
    max: f64,
}

fn stats(samples: &[f64]) -> Stats {
    let n = samples.len();
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = s.iter().sum::<f64>() / n as f64;
    let median = if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    };
    // Desvio-padrão amostral (n-1)
    let std = if n > 1 {
        (s.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt()
    } else {
        0.0
    };
    // p95 pelo método nearest-rank
    let rank = ((0.95 * n as f64).ceil() as usize).clamp(1, n);
    Stats {
        n,
        mean,
        median,
        std,
        p95: s[rank - 1],
        min: s[0],
        max: s[n - 1],
    }
}

#[derive(Debug, Serialize)]
struct Metric {
    key: &'static str,
    label: &'static str,
    unit: &'static str,
    stats: Stats,
    samples: Vec<f64>,
}

fn metric(key: &'static str, label: &'static str, samples: Vec<f64>) -> Metric {
    Metric {
        key,
        label,
        unit: "ms",
        stats: stats(&samples),
        samples,
    }
}

/// Executa `f` e devolve (resultado, tempo em ms).
fn timed<R>(f: impl FnOnce() -> R) -> (R, f64) {
    let t = Instant::now();
    let r = f();
    (r, t.elapsed().as_secs_f64() * 1000.0)
}

// ============================================
// AMBIENTE (máquina)
// ============================================

#[derive(Debug, Serialize)]
struct Machine {
    cpu_brand: String,
    cpu_arch: String,
    logical_cpus: usize,
    physical_cores: Option<usize>,
    cpu_freq_mhz: u64,
    total_ram_gib: f64,
    os: String,
    os_version: String,
    kernel_version: String,
    build_profile: &'static str,
    unix_timestamp: u64,
}

fn machine_info() -> Machine {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    let cpus = sys.cpus();
    Machine {
        cpu_brand: cpus
            .first()
            .map(|c| c.brand().trim().to_string())
            .unwrap_or_default(),
        cpu_arch: System::cpu_arch().unwrap_or_default(),
        logical_cpus: cpus.len(),
        physical_cores: sys.physical_core_count(),
        cpu_freq_mhz: cpus.first().map(|c| c.frequency()).unwrap_or(0),
        total_ram_gib: sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0),
        os: System::name().unwrap_or_default(),
        os_version: System::os_version().unwrap_or_default(),
        kernel_version: System::kernel_version().unwrap_or_default(),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        unix_timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

// ============================================
// RESULTADOS
// ============================================

#[derive(Debug, Serialize)]
struct SizeStats {
    min: usize,
    max: usize,
    mean: f64,
}

#[derive(Debug, Serialize)]
struct NResult {
    n: usize,
    accumulator_size_bytes: usize,
    membership_proof_size_bytes: SizeStats,
    witness_value_size_bytes: SizeStats,
    metrics: Vec<Metric>,
}

#[derive(Debug, Serialize)]
struct Report {
    experiment: &'static str,
    group: &'static str,
    deletion_method: &'static str,
    witness_update_method: &'static str,
    config: Config,
    machine: Machine,
    primitives: Vec<Metric>,
    results: Vec<NResult>,
}

fn sensor_ids(n: usize) -> Vec<String> {
    (1..=n).map(|i| format!("ESP-{:04}", i)).collect()
}

fn size_stats(sizes: &[usize]) -> SizeStats {
    SizeStats {
        min: *sizes.iter().min().unwrap(),
        max: *sizes.iter().max().unwrap(),
        mean: sizes.iter().sum::<usize>() as f64 / sizes.len() as f64,
    }
}

/// Confere (fora da medição) que `w` é witness de `id` em `acc`: w^H(id) == acc.
fn assert_witness(acc: &Acc, id: &str, w: &Wit, ctx: &str) {
    assert!(
        w.0.clone().add(&[id.to_string()]) == *acc,
        "witness inválida ({}) para {}",
        ctx,
        id
    );
}

// ============================================
// BENCHMARK POR N
// ============================================

fn bench_n(n: usize, cfg: &Config) -> NResult {
    let ids = sensor_ids(n);
    println!("\n▶ N = {} sensores", n);

    // ── 1. Acumulação inicial ─────────────────────────────────────────
    let mut t_acc = Vec::new();
    let mut t_wits = Vec::new();
    let mut acc_opt: Option<Acc> = None;
    let mut wits_opt: Option<Vec<(String, Wit)>> = None;
    for _ in 0..cfg.heavy_reps {
        let (acc, t) = timed(|| Acc::empty().add(&ids));
        t_acc.push(t);
        let (wits, t) =
            timed(|| Witness(Acc::empty()).compute_individual_witnesses(&ids));
        t_wits.push(t);
        acc_opt = Some(acc);
        wits_opt = Some(wits);
    }
    let acc = acc_opt.unwrap();
    let wits = wits_opt.unwrap();
    for (id, w) in wits.iter().step_by((n / 10).max(1)) {
        assert_witness(&acc, id, w, "setup");
    }
    let acc_bytes = serde_cbor::to_vec(&acc).unwrap();
    println!(
        "   setup: add(N) média {:.3} ms | N witnesses média {:.3} ms | acumulador {} bytes",
        stats(&t_acc).mean,
        stats(&t_wits).mean,
        acc_bytes.len()
    );

    // Índice "espalhado" e determinístico para escolher sensores por repetição.
    let pick = |r: usize, salt: usize| (r * 7919 + salt * 104_729) % n;

    // ── 2. Adição dinâmica (Join) ────────────────────────────────────
    let mut t_join_add = Vec::new();
    let mut t_join_proof_new = Vec::new();
    let mut t_join_wupd = Vec::new();
    let mut t_join_regen = Vec::new();
    let mut t_join_batch = Vec::new();
    for r in 0..cfg.reps {
        let new_id = format!("NEW-{:04}-{:03}", n, r);
        let acc_in = acc.clone();
        let (acc_new, t) = timed(|| acc_in.add(&[new_id.clone()]));
        t_join_add.push(t);

        let wit_new = Witness(acc.clone());
        let (proof_new, t) =
            timed(|| acc_new.prove_membership(&[(new_id.clone(), wit_new)]).unwrap());
        t_join_proof_new.push(t);

        let i = pick(r, 1);
        let (id_i, w_i) = &wits[i];
        let w_i_in = w_i.clone();
        let tracked = [id_i.clone()];
        let adds = [new_id.clone()];
        let (w_i_new, t) = timed(|| {
            acc_new
                .update_membership_witness(w_i_in, &tracked, &adds, &[])
                .unwrap()
        });
        t_join_wupd.push(t);

        let w_i_new_in = w_i_new.clone();
        let (proof_i_new, t) =
            timed(|| acc_new.prove_membership(&[(id_i.clone(), w_i_new_in)]).unwrap());
        t_join_regen.push(t);

        // Conferências (fora da medição)
        assert!(acc_new.verify_membership(&new_id, &proof_new));
        assert!(acc_new.verify_membership(id_i, &proof_i_new));
        let stale = acc.prove_membership(&[(id_i.clone(), w_i.clone())]).unwrap();
        assert!(acc.verify_membership(id_i, &stale));
        assert!(!acc_new.verify_membership(id_i, &stale), "witness antiga não deveria valer");

        if !cfg.skip_batch && r < cfg.heavy_reps {
            let inputs: Vec<Wit> = wits.iter().map(|(_, w)| w.clone()).collect();
            let (updated, t) = timed(|| {
                wits.iter()
                    .zip(inputs)
                    .map(|((id, _), w)| {
                        acc_new
                            .update_membership_witness(w, std::slice::from_ref(id), &adds, &[])
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            });
            t_join_batch.push(t);
            for k in (0..n).step_by((n / 10).max(1)) {
                assert_witness(&acc_new, &wits[k].0, &updated[k], "join-lote");
            }
        }
    }
    println!(
        "   join : add {:.3} ms | proof novo {:.3} ms | upd witness {:.3} ms | nova PoE {:.3} ms{}",
        stats(&t_join_add).mean,
        stats(&t_join_proof_new).mean,
        stats(&t_join_wupd).mean,
        stats(&t_join_regen).mean,
        if t_join_batch.is_empty() {
            String::new()
        } else {
            format!(" | lote N {:.3} ms", stats(&t_join_batch).mean)
        }
    );

    // ── 3. Revogação dinâmica (Delete) ───────────────────────────────
    let mut t_rev_del = Vec::new();
    let mut t_rev_wupd = Vec::new();
    let mut t_rev_regen = Vec::new();
    let mut t_rev_batch = Vec::new();
    for r in 0..cfg.reps {
        let j = pick(r, 2);
        let mut i = pick(r, 3);
        if i == j {
            i = (i + 1) % n;
        }
        let (id_j, w_j) = &wits[j];
        let (id_i, w_i) = &wits[i];

        let acc_in = acc.clone();
        let del_in = [(id_j.clone(), w_j.clone())];
        let (acc_del, t) = timed(|| acc_in.delete(&del_in).unwrap());
        t_rev_del.push(t);

        let w_i_in = w_i.clone();
        let tracked = [id_i.clone()];
        let dels = [id_j.clone()];
        let (w_i_new, t) = timed(|| {
            acc_del
                .update_membership_witness(w_i_in, &tracked, &[], &dels)
                .unwrap()
        });
        t_rev_wupd.push(t);

        let w_i_new_in = w_i_new.clone();
        let (proof_i_new, t) =
            timed(|| acc_del.prove_membership(&[(id_i.clone(), w_i_new_in)]).unwrap());
        t_rev_regen.push(t);

        // Conferências (fora da medição)
        let remaining: Vec<String> = ids.iter().filter(|x| *x != id_j).cloned().collect();
        if r == 0 {
            assert!(acc_del == Acc::empty().add(&remaining), "delete divergente da reconstrução");
        }
        let proof_j_old = acc.prove_membership(&[(id_j.clone(), w_j.clone())]).unwrap();
        assert!(!acc_del.verify_membership(id_j, &proof_j_old), "revogado não pode verificar");
        assert!(acc_del.verify_membership(id_i, &proof_i_new));
        let stale = acc.prove_membership(&[(id_i.clone(), w_i.clone())]).unwrap();
        assert!(!acc_del.verify_membership(id_i, &stale));

        if !cfg.skip_batch && r < cfg.heavy_reps {
            let inputs: Vec<(String, Wit)> = wits
                .iter()
                .filter(|(id, _)| id != id_j)
                .map(|(id, w)| (id.clone(), w.clone()))
                .collect();
            let (updated, t) = timed(|| {
                inputs
                    .into_iter()
                    .map(|(id, w)| {
                        let nw = acc_del
                            .update_membership_witness(w, std::slice::from_ref(&id), &[], &dels)
                            .unwrap();
                        (id, nw)
                    })
                    .collect::<Vec<_>>()
            });
            t_rev_batch.push(t);
            for (id, w) in updated.iter().step_by((n / 10).max(1)) {
                assert_witness(&acc_del, id, w, "revogação-lote");
            }
        }
    }
    println!(
        "   revog: delete {:.3} ms | upd witness {:.3} ms | nova PoE {:.3} ms{}",
        stats(&t_rev_del).mean,
        stats(&t_rev_wupd).mean,
        stats(&t_rev_regen).mean,
        if t_rev_batch.is_empty() {
            String::new()
        } else {
            format!(" | lote N-1 {:.3} ms", stats(&t_rev_batch).mean)
        }
    );

    // ── 4. Verificação no controlador ────────────────────────────────
    let k = n.min(10);
    let members: Vec<(String, Proof, Vec<u8>)> = (0..k)
        .map(|m| {
            let (id, w) = &wits[m * n / k];
            let p = acc.prove_membership(&[(id.clone(), w.clone())]).unwrap();
            let bytes = serde_cbor::to_vec(&p).unwrap();
            (id.clone(), p, bytes)
        })
        .collect();
    let proof_sizes: Vec<usize> = members.iter().map(|(_, _, b)| b.len()).collect();
    let witness_sizes: Vec<usize> = members
        .iter()
        .map(|(_, p, _)| serde_cbor::to_vec(&p.witness).unwrap().len())
        .collect();

    let mut t_verify = Vec::new();
    let mut t_decode_verify = Vec::new();
    for r in 0..cfg.verify_reps {
        let (id, proof, bytes) = &members[r % k];
        let (ok, t) = timed(|| acc.verify_membership(id, proof));
        assert!(ok);
        t_verify.push(t);
        let (ok, t) = timed(|| {
            let p: Proof = serde_cbor::from_slice(bytes).unwrap();
            acc.verify_membership(id, &p)
        });
        assert!(ok);
        t_decode_verify.push(t);
    }
    println!(
        "   verif: verify_membership {:.3} ms | decode+verify {:.3} ms | proof {} bytes",
        stats(&t_verify).mean,
        stats(&t_decode_verify).mean,
        size_stats(&proof_sizes).max
    );

    let mut metrics = vec![
        metric("setup_acc_build", "Acumulação inicial: add(N)", t_acc),
        metric(
            "setup_all_witnesses",
            "Geração das N witnesses (RootFactor)",
            t_wits,
        ),
        metric("join_add", "Join: add de 1 sensor", t_join_add),
        metric(
            "join_new_proof",
            "Join: MembershipProof do novo sensor",
            t_join_proof_new,
        ),
        metric(
            "join_witness_update_1",
            "Join: update witness (1 sensor)",
            t_join_wupd,
        ),
        metric(
            "join_proof_regen_1",
            "Join: nova PoE (1 sensor)",
            t_join_regen,
        ),
    ];
    if !t_join_batch.is_empty() {
        metrics.push(metric(
            "join_batch_update_all",
            "Join: update em lote (N witnesses)",
            t_join_batch,
        ));
    }
    metrics.extend(vec![
        metric("revoke_delete", "Revogação: delete de 1 sensor", t_rev_del),
        metric(
            "revoke_witness_update_1",
            "Revogação: update witness (1 sensor)",
            t_rev_wupd,
        ),
        metric(
            "revoke_proof_regen_1",
            "Revogação: nova PoE (1 sensor)",
            t_rev_regen,
        ),
    ]);
    if !t_rev_batch.is_empty() {
        metrics.push(metric(
            "revoke_batch_update_all",
            "Revogação: update em lote (N-1)",
            t_rev_batch,
        ));
    }
    metrics.extend(vec![
        metric(
            "verify_membership",
            "Verificação: verify_membership",
            t_verify,
        ),
        metric(
            "verify_decode_and_verify",
            "Verificação: decode CBOR + verify",
            t_decode_verify,
        ),
    ]);

    NResult {
        n,
        accumulator_size_bytes: acc_bytes.len(),
        membership_proof_size_bytes: size_stats(&proof_sizes),
        witness_value_size_bytes: size_stats(&witness_sizes),
        metrics,
    }
}

// ============================================
// PRIMITIVAS (contexto para a análise de custo)
// ============================================

fn bench_primitives(reps: usize) -> Vec<Metric> {
    let mut t_h2p = Vec::new();
    let mut t_exp = Vec::new();
    let g = Rsa2048::unknown_order_elem();
    for r in 0..reps {
        let id = format!("PRIM-{:05}", r);
        let (p, t) = timed(|| hash_to_prime(&id));
        t_h2p.push(t);
        let (_e, t) = timed(|| Rsa2048::exp(&g, &p));
        t_exp.push(t);
    }
    vec![
        metric(
            "hash_to_prime",
            "hash_to_prime(id) → primo de 256 bits",
            t_h2p,
        ),
        metric(
            "modexp_256",
            "g^p mod n (n de 2048 bits, p de 256 bits)",
            t_exp,
        ),
    ]
}

// ============================================
// SAÍDA EM TABELA
// ============================================

fn print_tables(report: &Report) {
    let line = "═".repeat(92);
    println!("\n{}", line);
    println!("  RESULTADOS — DINAMICIDADE DO ACUMULADOR RSA-2048 (tempos em ms)");
    println!("{}", line);
    println!(
        "  Máquina: {} | {} CPUs lógicas | {:.1} GiB RAM | {} {} | build {}",
        report.machine.cpu_brand,
        report.machine.logical_cpus,
        report.machine.total_ram_gib,
        report.machine.os,
        report.machine.os_version,
        report.machine.build_profile
    );
    println!(
        "  Repetições: unitárias={} | pesadas={} | verificação={}",
        report.config.reps, report.config.heavy_reps, report.config.verify_reps
    );

    println!("\n  Primitivas (independentes de N):");
    for m in &report.primitives {
        println!(
            "    {:<44} média {:>9.4} | mediana {:>9.4} | dp {:>8.4} | p95 {:>9.4}",
            m.label, m.stats.mean, m.stats.median, m.stats.std, m.stats.p95
        );
    }

    let keys: Vec<(&str, &str)> = report.results[0]
        .metrics
        .iter()
        .map(|m| (m.key, m.label))
        .collect();
    for (key, label) in keys {
        println!("\n  {}  [{}]", label, key);
        println!(
            "    {:>6} │ {:>5} │ {:>11} │ {:>11} │ {:>10} │ {:>11} │ {:>11}",
            "N", "amost", "média", "mediana", "desv.pad", "p95", "máx"
        );
        println!("    {}", "─".repeat(84));
        for res in &report.results {
            if let Some(m) = res.metrics.iter().find(|m| m.key == key) {
                println!(
                    "    {:>6} │ {:>5} │ {:>11.4} │ {:>11.4} │ {:>10.4} │ {:>11.4} │ {:>11.4}",
                    res.n,
                    m.stats.n,
                    m.stats.mean,
                    m.stats.median,
                    m.stats.std,
                    m.stats.p95,
                    m.stats.max
                );
            }
        }
    }

    println!("\n  Tamanhos serializados (CBOR)");
    println!(
        "    {:>6} │ {:>18} │ {:>26} │ {:>22}",
        "N", "acumulador (bytes)", "MembershipProof (min–máx)", "witness (min–máx)"
    );
    println!("    {}", "─".repeat(84));
    for res in &report.results {
        println!(
            "    {:>6} │ {:>18} │ {:>26} │ {:>22}",
            res.n,
            res.accumulator_size_bytes,
            format!(
                "{}–{}",
                res.membership_proof_size_bytes.min, res.membership_proof_size_bytes.max
            ),
            format!(
                "{}–{}",
                res.witness_value_size_bytes.min, res.witness_value_size_bytes.max
            ),
        );
    }

    // Razão de escala da verificação (maior N / menor N)
    let first = report.results.first().unwrap();
    let last = report.results.last().unwrap();
    let v = |r: &NResult, key: &str| {
        r.metrics
            .iter()
            .find(|m| m.key == key)
            .map(|m| m.stats.median)
            .unwrap_or(f64::NAN)
    };
    println!(
        "\n  Escala N={} → N={} ({}×): verify_membership mediana {:.4} → {:.4} ms (razão {:.3}×); \
         add(N) mediana {:.3} → {:.3} ms (razão {:.1}×)",
        first.n,
        last.n,
        last.n / first.n,
        v(first, "verify_membership"),
        v(last, "verify_membership"),
        v(last, "verify_membership") / v(first, "verify_membership"),
        v(first, "setup_acc_build"),
        v(last, "setup_acc_build"),
        v(last, "setup_acc_build") / v(first, "setup_acc_build"),
    );
    println!("{}\n", line);
}

// ============================================
// MAIN
// ============================================

fn main() -> anyhow::Result<()> {
    let cfg = parse_args();
    let machine = machine_info();

    println!("═══════════════════════════════════════════════════════════════════");
    println!("  dynamic_bench — Dinamicidade do Acumulador RSA-2048 (TCC GSIPP)");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  CPU:   {} ({} lógicas, {:?} físicas, {} MHz)",
        machine.cpu_brand, machine.logical_cpus, machine.physical_cores, machine.cpu_freq_mhz);
    println!("  RAM:   {:.1} GiB | SO: {} {} ({})",
        machine.total_ram_gib, machine.os, machine.os_version, machine.cpu_arch);
    println!("  Build: {}", machine.build_profile);
    if cfg!(debug_assertions) {
        println!("  ⚠  Build de DEBUG — use `cargo run --release --bin dynamic_bench`.");
    }
    println!("  N = {:?} | reps={} heavy-reps={} verify-reps={} skip-batch={}",
        cfg.ns, cfg.reps, cfg.heavy_reps, cfg.verify_reps, cfg.skip_batch);
    println!("  Deleção: Accumulator::delete(&[(elem, witness)]) — Shamir trick, sem trapdoor");
    println!("  Witness: Accumulator::update_membership_witness (LLX, Seção 4.2)");

    // Aquecimento: inicializa lazy_statics (módulo RSA) e caches.
    let warm = Acc::empty().add(&sensor_ids(8));
    let w = Witness(Acc::empty()).compute_individual_witnesses(&sensor_ids(8));
    let p = warm.prove_membership(&[w[0].clone()]).unwrap();
    assert!(warm.verify_membership(&w[0].0, &p));

    let primitives = bench_primitives(cfg.verify_reps);
    let results: Vec<NResult> = cfg.ns.iter().map(|&n| bench_n(n, &cfg)).collect();

    let report = Report {
        experiment: "dinamicidade-acumulador-rsa2048",
        group: "Rsa2048 (módulo RSA-2048 do desafio RSA, g = 2)",
        deletion_method: "Accumulator::delete(&[(elem, witness)]): Shamir trick sem trapdoor; \
                          exige a witness do elemento removido e o novo acumulador é a própria witness",
        witness_update_method: "Accumulator::update_membership_witness (LLX 2007, Seção 4.2): \
                                adição w' = w^H(x); deleção w' = w^b · A'^a com a·H(id) + b·H(x) = 1",
        config: cfg,
        machine,
        primitives,
        results,
    };

    print_tables(&report);

    if let Some(dir) = std::path::Path::new(&report.config.out).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    std::fs::write(&report.config.out, serde_json::to_string_pretty(&report)?)?;
    println!("✓ Resultados (amostras brutas + estatísticas) salvos em '{}'", report.config.out);
    Ok(())
}
