#!/usr/bin/env python3
"""
Converte o arquivo .proof (MembershipProof em CBOR gerada pelo setup) para o
array C embutido no firmware ESP32 (esp32_sensor/esp32_sensor.ino).

O bloco gerado é idêntico ao usado no .ino:

    const uint8_t MEMBERSHIP_PROOF[] = { ... };
    const size_t PROOF_SIZE = sizeof(MEMBERSHIP_PROOF);

Uso (de qualquer diretório):
    python3 SnifferESP/convert_proof_to_array.py            # ESP-42, imprime o bloco
    python3 SnifferESP/convert_proof_to_array.py ESP-42 --write
        → substitui o bloco diretamente em esp32_sensor/esp32_sensor.ino

Lembrete: se a proof do ESP-42 mudar, atualize também ESP42_PROOF_BYTES em
attack_tests.py (o script avisa na inicialização se houver divergência).
"""

import argparse
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INO_PATH = os.path.join(SCRIPT_DIR, "esp32_sensor", "esp32_sensor.ino")
BYTES_PER_LINE = 12

# Bloco no .ino: do banner "MEMBERSHIP PROOF" até a linha do PROOF_SIZE.
INO_BLOCK_RE = re.compile(
    r"// =+\n// MEMBERSHIP PROOF.*?const size_t PROOF_SIZE = sizeof\(MEMBERSHIP_PROOF\);",
    re.S,
)


def proof_path_for(esp_id: str) -> str:
    return os.path.join(SCRIPT_DIR, "proofs", f"{esp_id.replace('-', '_')}.proof")


def build_c_block(esp_id: str, data: bytes) -> str:
    """Gera o bloco C completo (banner + array + PROOF_SIZE)."""
    lines = [
        "// ============================================",
        f"// MEMBERSHIP PROOF — {esp_id} (Witness + PoE de Wesolowski)",
        "// ============================================",
        "// Gerado por SnifferESP/convert_proof_to_array.py a partir de",
        f"// SnifferESP/proofs/{esp_id.replace('-', '_')}.proof ({len(data)} bytes).",
        "// Deve corresponder ao accumulator.dat carregado pelo controlador.",
        "",
        "const uint8_t MEMBERSHIP_PROOF[] = {",
    ]
    rows = [
        ", ".join(f"0x{b:02X}" for b in data[i:i + BYTES_PER_LINE])
        for i in range(0, len(data), BYTES_PER_LINE)
    ]
    lines += [f"    {row}," for row in rows[:-1]]
    lines.append(f"    {rows[-1]}}};")
    lines.append("const size_t PROOF_SIZE = sizeof(MEMBERSHIP_PROOF);")
    return "\n".join(lines)


def write_into_ino(block: str) -> bool:
    with open(INO_PATH, encoding="utf-8") as f:
        ino = f.read()
    new_ino, n = INO_BLOCK_RE.subn(lambda _: block, ino, count=1)
    if n != 1:
        print(f"❌ Bloco MEMBERSHIP PROOF não encontrado em {INO_PATH}")
        return False
    if new_ino == ino:
        print(f"✅ {os.path.relpath(INO_PATH)} já está atualizado.")
        return True
    with open(INO_PATH, "w", encoding="utf-8") as f:
        f.write(new_ino)
    print(f"✅ Bloco MEMBERSHIP_PROOF atualizado em {os.path.relpath(INO_PATH)}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("esp_id", nargs="?", default="ESP-42",
                        help="ID do sensor (default: ESP-42)")
    parser.add_argument("--write", action="store_true",
                        help="Substitui o bloco diretamente no esp32_sensor.ino")
    args = parser.parse_args()

    proof_file = proof_path_for(args.esp_id)
    if not os.path.exists(proof_file):
        print(f"❌ Erro: Arquivo não encontrado: {proof_file}")
        print("\nExecute primeiro: cd SnifferESP && cargo run --release --bin setup")
        return 1

    with open(proof_file, "rb") as f:
        data = f.read()

    block = build_c_block(args.esp_id, data)

    if args.write:
        return 0 if write_into_ino(block) else 1

    print(block)
    print(f"\n// ✅ {len(data)} bytes — cole no lugar do bloco MEMBERSHIP PROOF do .ino")
    print("//    ou rode novamente com --write para atualizar o arquivo automaticamente.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
