#!/usr/bin/env python3
"""
Converte o arquivo .proof para um array C que pode ser incluído no código ESP32
Elimina a necessidade de usar SPIFFS
"""

import sys
import os

def convert_proof_to_c_array(proof_file):
    """Converte o arquivo .proof para array C"""

    if not os.path.exists(proof_file):
        print(f"❌ Erro: Arquivo não encontrado: {proof_file}")
        print(f"\nExecute primeiro: cargo run --bin setup")
        return False

    # Ler arquivo binário
    with open(proof_file, "rb") as f:
        data = f.read()

    file_size = len(data)

    print("=" * 60)
    print("  ARRAY C GERADO - Cole no código ESP32")
    print("=" * 60)
    print()
    print("// MembershipProof em array C (gerado automaticamente)")
    print(f"// Tamanho: {file_size} bytes")
    print()
    print("const uint8_t MEMBERSHIP_PROOF[] PROGMEM = {")

    # Gerar linhas com 12 bytes cada
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        hex_values = ", ".join(f"0x{b:02X}" for b in chunk)

        # Adicionar vírgula no final exceto na última linha
        if i + 12 < len(data):
            print(f"  {hex_values},")
        else:
            print(f"  {hex_values}")

    print("};")
    print(f"const size_t PROOF_SIZE = {file_size};")
    print()
    print("=" * 60)
    print(f"✅ Conversão concluída: {file_size} bytes")
    print("=" * 60)
    print()
    print("📋 PRÓXIMO PASSO:")
    print("   1. Copie TODO o código acima (desde 'const uint8_t...' até '};')")
    print("   2. Cole no arquivo esp32_sensor.ino (por volta da linha 50)")
    print("   3. Remova/comente o código que usa SPIFFS")
    print()

    return True

if __name__ == "__main__":
    # Arquivo padrão: ESP-42
    esp_id = "ESP-42"

    if len(sys.argv) > 1:
        esp_id = sys.argv[1]

    proof_file = f"proofs/{esp_id.replace('-', '_')}.proof"

    print()
    print(f"📂 Convertendo prova para: {esp_id}")
    print(f"   Arquivo: {proof_file}")
    print()

    convert_proof_to_c_array(proof_file)
