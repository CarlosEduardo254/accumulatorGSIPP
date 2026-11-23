#!/usr/bin/env python3
"""
analisar_por_cenario.py — Análise por pacote e por cenário dos logs do
udp_controller nas fases de dinamicidade (complementa o analisar_log.py).

O ESP32 físico é identificado pelo ID (ESP-42 ou ESP-99). O ESP-02 simulado pelo
PC (dynamic_e2e) chega em rajadas de --packets pacotes por cenário, na ordem em
que o cliente envia; os pacotes do ESP-02 são cortados em blocos consecutivos e
rotulados com a lista de cenários informada.

Uso:
  python3 analisar_por_cenario.py [--json saida.json] [--bloco 20] \
      A1=logs/controller_A1_X.log A2=logs/controller_A2_Y.log A3=logs/controller_A3_Z.log
  Rótulos padrão dos blocos do ESP-02:  A1: F1-B | A2: F3-B, F3-C | A3: F4-B, F4-C
  Para outra sequência (ex.: Fase 1 do cliente repetida contra o controlador A2):
      A2=logs/controller_A2_Y.log:F1-B*,F3-B,F3-C

Saída: por cenário, desfecho por camada, tempos no controlador (média, mediana,
dp, p95, mín., máx.), Δ de timestamp, tamanhos, IP de origem e lacunas de
sequência (Reading), além da separação dos tempos em dois regimes ("rápido" e
"lento"), que no Raspberry Pi 3B+ correspondem ao clock da CPU (DVFS).
"""
import json
import re
import statistics as st
import sys

PADRAO = {"A1": ["F1-B"], "A2": ["F3-B", "F3-C"], "A3": ["F4-B", "F4-C"]}
# Limiares (ms) entre os regimes rápido/lento no Pi 3B+, por tamanho de proof.
LIMIARES = {False: (17.0, 24.0), True: (22.0, 30.0)}  # chave: proof grande (1064 B)?

CAMPOS = [(r"Pacote recebido de: (.+)$", "sensor", str),
          (r"Timestamp:\s+(\d+)", "ts", int),
          (r"Reading:\s+(\d+)", "reading", int),
          (r"Proof:\s+(\d+) bytes", "proof", int),
          (r"Timestamp OK \(Δ = (-?\d+)s", "delta", int),
          (r"Status: (.+)$", "status", str),
          (r"Tempo de verificação no controlador \(ms\): ([0-9.]+)", "ms", float),
          (r"RAM consumida pelo processo \(MB\): ([0-9.]+)", "ram", float)]


def ler(path):
    pkts, cur = [], None
    for raw in open(path, encoding="utf-8", errors="replace"):
        l = raw.strip()
        m = re.match(r"──── Pacote de ([0-9.]+):(\d+) \((\d+) bytes\)", l)
        if m:
            cur = {"ip": m[1], "bytes": int(m[3])}
            pkts.append(cur)
            continue
        if cur is None:
            continue
        for pat, chave, conv in CAMPOS:
            m = re.search(pat, l)
            if m and chave not in cur:
                cur[chave] = conv(m[1])
        if "Assinatura RSA-2048 VÁLIDA" in l:
            cur["v02_ok"] = True
    return [p for p in pkts if "status" in p and "ms" in p]


def camada(s):
    if s.startswith("ACEITO"):
        return "ACEITO"
    for chave, nome in [("Aritmética", "V03_ARITMETICA"), ("Sintática", "V03_SINTATICA"),
                        ("Assinatura Inválida", "V02_ASSINATURA"), ("Sensor Desconhecido", "V02_DESCONHECIDO"),
                        ("Replay Intra-Janela", "V01b_DUPLICATA"), ("Replay Attack", "V01_TIMESTAMP"),
                        ("CBOR Externo", "C00_CBOR")]:
        if chave in s:
            return nome
    return "OUTRO"


def estat(v):
    v = sorted(v)
    n = len(v)
    if n == 0:
        return None
    return {"n": n, "media": round(st.mean(v), 3), "mediana": round(st.median(v), 3),
            "dp": round(st.stdev(v), 3) if n > 1 else 0.0, "p95": v[min(n - 1, round(0.95 * (n - 1)))],
            "min": v[0], "max": v[-1]}


def regimes(ps):
    r = {"rapido": [], "lento": [], "transicao": []}
    for p in ps:
        lo, hi = LIMIARES[p["proof"] >= 1000]
        r["rapido" if p["ms"] < lo else "lento" if p["ms"] > hi else "transicao"].append(p["ms"])
    return {k: estat(v) for k, v in r.items()}


def resumo(ps):
    lay = {}
    for p in ps:
        c = camada(p["status"])
        lay[c] = lay.get(c, 0) + 1
    rd = [p["reading"] for p in ps]
    return {"camadas": lay, "v02_assinatura_valida": sum(1 for p in ps if p.get("v02_ok")),
            "ms": estat([p["ms"] for p in ps]), "regimes_ms": regimes(ps),
            "delta_timestamp_s": sorted({p["delta"] for p in ps if "delta" in p}),
            "bytes_udp": sorted({p["bytes"] for p in ps}), "proof_bytes": sorted({p["proof"] for p in ps}),
            "ip_origem": sorted({p["ip"] for p in ps}), "reading_ini_fim": [rd[0], rd[-1]],
            "lacunas_sequencia": sum(1 for a, b in zip(rd, rd[1:]) if b != a + 1),
            "duracao_s": ps[-1]["ts"] - ps[0]["ts"]}


def main(argv):
    out_json, bloco, fases = None, 20, []
    i = 0
    while i < len(argv):
        if argv[i] == "--json":
            out_json, i = argv[i + 1], i + 2
        elif argv[i] == "--bloco":
            bloco, i = int(argv[i + 1]), i + 2
        else:
            acc, resto = argv[i].split("=", 1)
            path, _, rot = resto.partition(":")
            fases.append((acc, path, rot.split(",") if rot else PADRAO.get(acc, [])))
            i += 1
    if not fases:
        print(__doc__)
        return 2
    rel = {}
    for acc, path, rotulos in fases:
        pk = ler(path)
        grupos = {}
        for sid in sorted({p["sensor"] for p in pk} - {"ESP-02"}):
            grupos[f"{sid} (ESP32)"] = [p for p in pk if p["sensor"] == sid]
        pc = [p for p in pk if p["sensor"] == "ESP-02"]
        for k, rot in enumerate(rotulos):
            if pc[bloco * k:bloco * (k + 1)]:
                grupos[f"{rot} (ESP-02, PC)"] = pc[bloco * k:bloco * (k + 1)]
        if len(pc) > bloco * len(rotulos):
            grupos["ESP-02 (sem rótulo)"] = pc[bloco * len(rotulos):]
        rams = [p["ram"] for p in pk if "ram" in p]
        rel[acc] = {"arquivo": path, "pacotes": len(pk),
                    "ram_mb_min_max": [min(rams), max(rams)] if rams else None,
                    "cenarios": {g: resumo(ps) for g, ps in grupos.items()}}
        print(f"\n═══ {acc}: {path} — {len(pk)} pacotes, RAM {rel[acc]['ram_mb_min_max']} MB")
        for g, r in rel[acc]["cenarios"].items():
            s, rg = r["ms"], r["regimes_ms"]
            reg = " | ".join(f"{k} n={v['n']} med={v['mediana']}" for k, v in rg.items() if v)
            print(f"  {g:28s} n={s['n']:3d} {r['camadas']}  V02ok={r['v02_assinatura_valida']}")
            print(f"  {'':28s} ms: média {s['media']} mediana {s['mediana']} dp {s['dp']} "
                  f"p95 {s['p95']} [{s['min']}–{s['max']}]  ({reg})")
            print(f"  {'':28s} Δts {r['delta_timestamp_s']} s | UDP {r['bytes_udp']} B | proof "
                  f"{r['proof_bytes']} B | origem {r['ip_origem']} | lacunas {r['lacunas_sequencia']}")
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(rel, f, ensure_ascii=False, indent=1)
        print(f"\n✓ JSON: {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
