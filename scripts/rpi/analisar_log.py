#!/usr/bin/env python3
"""
analisar_log.py — Resume um ou mais logs do udp_controller por sensor e por
camada de verificação (aceito / V01 / V01b / V02 / V03 sintática / V03 aritmética / C00).

Uso:  python3 analisar_log.py logs/controller_A1_*.log logs/controller_A2_*.log ...
      python3 analisar_log.py --json resumo.json logs/*.log
"""
import json
import re
import statistics
import sys
from collections import OrderedDict

LAYERS = [
    ("ACEITO", lambda s: s.startswith("ACEITO")),
    ("V03_ARITMETICA", lambda s: "V03 Aritmética" in s),
    ("V03_SINTATICA", lambda s: "V03 Sintática" in s),
    ("V02_ASSINATURA", lambda s: "Assinatura Inválida" in s),
    ("V02_DESCONHECIDO", lambda s: "Sensor Desconhecido" in s),
    ("V01b_DUPLICATA", lambda s: "Replay Intra-Janela" in s),
    ("V01_TIMESTAMP", lambda s: "Replay Attack" in s),
    ("C00_CBOR", lambda s: "CBOR Externo" in s),
]


def classify(status: str) -> str:
    for name, pred in LAYERS:
        if pred(status):
            return name
    return "OUTRO"


def analyze(path: str):
    acc = "?"
    sensor = None
    pending = None  # (sensor, camada)
    per = OrderedDict()
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            m = re.match(r"Acumulador carregado de '([^']+)'", line)
            if m:
                acc = m.group(1)
            m = re.match(r"Pacote recebido de: (.+)$", line)
            if m:
                sensor = m.group(1).strip()
                continue
            if line.startswith("Status:"):
                layer = classify(line[len("Status:"):].strip())
                who = sensor if layer != "C00_CBOR" else "(CBOR inválido)"
                d = per.setdefault(who, {"total": 0, "camadas": {}, "ms": []})
                d["total"] += 1
                d["camadas"][layer] = d["camadas"].get(layer, 0) + 1
                pending = d
                sensor = None
                continue
            m = re.match(r"Tempo de verificação no controlador \(ms\): ([0-9.]+)", line)
            if m and pending is not None:
                pending["ms"].append(float(m.group(1)))
                pending = None
    return acc, per


def main(argv):
    out_json = None
    if len(argv) >= 2 and argv[0] == "--json":
        out_json, argv = argv[1], argv[2:]
    if not argv:
        print(__doc__)
        return 2
    report = []
    for path in argv:
        acc, per = analyze(path)
        print(f"\n═══ {path}\n    acumulador: {acc}")
        print(f"    {'sensor':<16} {'total':>6} {'aceitos':>8} {'%aceito':>8}  "
              f"{'média ms':>9} {'mediana':>8}  camadas")
        for who, d in per.items():
            ok = d["camadas"].get("ACEITO", 0)
            ms = d["ms"]
            mean = f"{statistics.mean(ms):.3f}" if ms else "-"
            med = f"{statistics.median(ms):.3f}" if ms else "-"
            layers = ", ".join(f"{k}×{v}" for k, v in d["camadas"].items())
            print(f"    {who:<16} {d['total']:>6} {ok:>8} {100.0 * ok / d['total']:>7.1f}%  "
                  f"{mean:>9} {med:>8}  {layers}")
            report.append({"log": path, "accumulator": acc, "sensor": who, "total": d["total"],
                           "accepted": ok, "layers": d["camadas"],
                           "verify_ms_mean": statistics.mean(ms) if ms else None,
                           "verify_ms_median": statistics.median(ms) if ms else None})
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n✓ JSON: {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
