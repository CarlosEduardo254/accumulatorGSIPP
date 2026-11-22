#!/usr/bin/env python3
"""
gen_sensor_identity.py — Gera esp32_sensor/sensor_identity.h para regravar o
ESP32 com outra identidade (ID + chave privada RSA-2048 + MembershipProof),
a partir dos artefatos do TMC do experimento de dinamicidade (dynamic_tmc).

O firmware (esp32_sensor.ino) inclui sensor_identity.h quando ele existe; sem
ele, volta à identidade padrão embutida (ESP-42 com a proof do setup original,
que é a mesma proof de A1).

Exemplos (da raiz do repositório):
  # Fase 4 — ESP32 vira o novo sensor ESP-99 (acumulador A3)
  python SnifferESP/gen_sensor_identity.py --sensor ESP-99 --acc A3

  # ESP32 como ESP-02 com a witness de A1 / A2 / A3
  python SnifferESP/gen_sensor_identity.py --sensor ESP-02 --acc A2

  # Voltar ao firmware padrão (ESP-42, proof de A1)
  python SnifferESP/gen_sensor_identity.py --restore-default

Depois: cd SnifferESP/esp32_sensor && pio run --target upload
(ou abrir o .ino no Arduino IDE e fazer o upload).

O header contém CHAVE PRIVADA e é ignorado pelo Git (.gitignore).
"""

import argparse
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEFAULT_ARTIFACTS = os.path.join(REPO, "target", "e2e_dinamicidade")
HEADER = os.path.join(HERE, "esp32_sensor", "sensor_identity.h")

# Combinações produzidas pelo dynamic_tmc
AVAILABLE = {
    ("ESP-02", "A1"), ("ESP-02", "A2"), ("ESP-02", "A3"),
    ("ESP-99", "A3"),
}


def c_string_pem(pem: str) -> str:
    lines = [l for l in pem.strip().splitlines() if l.strip()]
    return "\n".join(f'    "{l}\\n"' for l in lines)


def c_byte_array(data: bytes) -> str:
    rows = []
    for i in range(0, len(data), 12):
        rows.append("    " + ", ".join(f"0x{b:02X}" for b in data[i:i + 12]))
    return ",\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sensor", help="ID do sensor (ESP-02 ou ESP-99)")
    ap.add_argument("--acc", help="estado do acumulador da proof (A1, A2 ou A3)")
    ap.add_argument("--artifacts", default=DEFAULT_ARTIFACTS, help="diretório gerado pelo dynamic_tmc")
    ap.add_argument("--key", help="(opcional) caminho da chave privada PKCS#8 PEM")
    ap.add_argument("--proof", help="(opcional) caminho do arquivo .proof")
    ap.add_argument("--restore-default", action="store_true",
                    help="remove sensor_identity.h (firmware volta a ser ESP-42 / A1)")
    a = ap.parse_args()

    if a.restore_default:
        if os.path.exists(HEADER):
            os.remove(HEADER)
            print(f"✓ Removido {HEADER} — o firmware volta à identidade padrão ESP-42 (proof de A1).")
        else:
            print("✓ sensor_identity.h não existe — o firmware já usa a identidade padrão ESP-42.")
        return 0

    if not a.sensor or not a.acc:
        ap.error("informe --sensor e --acc (ou --restore-default)")
    acc = a.acc.upper()
    stem = a.sensor.replace("-", "_")
    key_path = a.key or os.path.join(a.artifacts, "keys", f"{stem}.key.pem")
    proof_path = a.proof or os.path.join(a.artifacts, "proofs", f"{stem}_{acc}.proof")
    if not (a.key and a.proof) and (a.sensor, acc) not in AVAILABLE:
        print(f"⚠  Combinação {a.sensor}/{acc} não é gerada pelo dynamic_tmc. "
              f"Disponíveis: {sorted(AVAILABLE)}", file=sys.stderr)
    for p in (key_path, proof_path):
        if not os.path.exists(p):
            print(f"✗ Arquivo não encontrado: {p}\n  Rode antes: cargo run --release --bin dynamic_tmc",
                  file=sys.stderr)
            return 1

    with open(key_path, encoding="ascii") as f:
        pem = f.read()
    if "BEGIN PRIVATE KEY" not in pem and "BEGIN RSA PRIVATE KEY" not in pem:
        print(f"✗ {key_path} não parece uma chave privada PEM", file=sys.stderr)
        return 1
    with open(proof_path, "rb") as f:
        proof = f.read()

    header = f"""// ═══════════════════════════════════════════════════════════════════
// sensor_identity.h — GERADO por SnifferESP/gen_sensor_identity.py
// NÃO versionar (contém chave privada). Remova com --restore-default.
// ═══════════════════════════════════════════════════════════════════
// Sensor:     {a.sensor}
// Acumulador: {acc}
// Chave:      {os.path.relpath(key_path, REPO)}
// Proof:      {os.path.relpath(proof_path, REPO)} ({len(proof)} bytes, sha256 {hashlib.sha256(proof).hexdigest()[:16]}…)
#pragma once

const char *SENSOR_ID = "{a.sensor}";

const char *PRIVATE_KEY_PEM =
{c_string_pem(pem)};

const uint8_t MEMBERSHIP_PROOF[] = {{
{c_byte_array(proof)}}};
"""
    with open(HEADER, "w", encoding="utf-8", newline="\n") as f:
        f.write(header)
    print(f"✓ {HEADER}")
    print(f"  SENSOR_ID = {a.sensor} | proof de {acc} ({len(proof)} bytes)")
    print("  Agora faça o upload do firmware (pio run --target upload, ou Arduino IDE).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
