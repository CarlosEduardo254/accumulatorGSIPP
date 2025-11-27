#!/usr/bin/env python3
"""
Script para gravar o arquivo .proof no ESP32 via SPIFFS

Uso:
    python upload_proof_to_esp.py --port COM3 --esp-id ESP-42

Requisitos:
    pip install esptool mkspiffs-prebuilt
"""

import argparse
import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path


def check_dependencies():
    """Verifica se as ferramentas necessárias estão instaladas"""
    print("🔍 Verificando dependências...\n")

    required_tools = {
        'esptool.py': 'pip install esptool',
        'mkspiffs': 'pip install mkspiffs-prebuilt'
    }

    missing = []
    for tool, install_cmd in required_tools.items():
        if shutil.which(tool) is None:
            print(f"❌ {tool} não encontrado")
            print(f"   Instale com: {install_cmd}\n")
            missing.append(tool)
        else:
            print(f"✅ {tool} encontrado")

    if missing:
        print(f"\n❌ Instale as dependências faltantes e tente novamente")
        return False

    print()
    return True


def find_proof_file(esp_id):
    """Localiza o arquivo .proof para o ESP especificado"""
    # Formato: proofs/ESP_42.proof (ESP-42 → ESP_42)
    proof_filename = f"proofs/{esp_id.replace('-', '_')}.proof"

    if not os.path.exists(proof_filename):
        print(f"❌ Arquivo de prova não encontrado: {proof_filename}")
        print(f"\nExecute primeiro: cargo run --bin setup")
        return None

    file_size = os.path.getsize(proof_filename)
    print(f"✅ Arquivo .proof encontrado: {proof_filename} ({file_size} bytes)")
    return proof_filename


def create_spiffs_image(proof_file, output_image):
    """Cria uma imagem SPIFFS com o arquivo .proof"""
    print(f"\n📦 Criando imagem SPIFFS...\n")

    # Criar diretório temporário para os arquivos do SPIFFS
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copiar .proof para o diretório temporário como "sensor.proof"
        dest_file = os.path.join(tmpdir, "sensor.proof")
        shutil.copy(proof_file, dest_file)
        print(f"   Copiado: {proof_file} → {dest_file}")

        # Criar imagem SPIFFS
        # Tamanho típico da partição SPIFFS no ESP32: 1.5MB (0x170000)
        spiffs_size = 0x170000  # 1.5MB
        spiffs_page = 256
        spiffs_block = 4096

        cmd = [
            'mkspiffs',
            '-c', tmpdir,           # Diretório com os arquivos
            '-b', str(spiffs_block),
            '-p', str(spiffs_page),
            '-s', hex(spiffs_size),
            output_image
        ]

        print(f"   Executando: {' '.join(cmd)}\n")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✅ Imagem SPIFFS criada: {output_image}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Erro ao criar imagem SPIFFS:")
            print(e.stderr)
            return False


def flash_spiffs_to_esp(port, spiffs_image):
    """Grava a imagem SPIFFS no ESP32"""
    print(f"\n📤 Gravando no ESP32 (porta {port})...\n")

    # Offset da partição SPIFFS (tipicamente 0x290000 para ESP32 padrão)
    # Verifique na tabela de partições se estiver usando uma customizada
    spiffs_offset = 0x290000

    cmd = [
        'esptool.py',
        '--chip', 'esp32',
        '--port', port,
        '--baud', '921600',
        'write_flash',
        '-z',
        hex(spiffs_offset),
        spiffs_image
    ]

    print(f"   Executando: {' '.join(cmd)}\n")

    try:
        subprocess.run(cmd, check=True)
        print(f"\n✅ Prova gravada com sucesso no ESP32!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Erro ao gravar no ESP32")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Grava o arquivo .proof de um ESP no filesystem SPIFFS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python upload_proof_to_esp.py --port COM3 --esp-id ESP-42
  python upload_proof_to_esp.py --port /dev/ttyUSB0 --esp-id ESP-01

Notas:
  - Execute 'cargo run --bin setup' primeiro para gerar as provas
  - O ESP32 deve estar conectado via USB
  - No Windows, use COMx (ex: COM3)
  - No Linux, use /dev/ttyUSBx (ex: /dev/ttyUSB0)
        """
    )

    parser.add_argument(
        '--port',
        required=True,
        help='Porta serial do ESP32 (ex: COM3 ou /dev/ttyUSB0)'
    )

    parser.add_argument(
        '--esp-id',
        required=True,
        help='ID do ESP (ex: ESP-42)'
    )

    args = parser.parse_args()

    print("═" * 60)
    print("  Upload de MembershipProof para ESP32")
    print("═" * 60)
    print()

    # 1. Verificar dependências
    if not check_dependencies():
        sys.exit(1)

    # 2. Localizar arquivo .proof
    proof_file = find_proof_file(args.esp_id)
    if not proof_file:
        sys.exit(1)

    # 3. Criar imagem SPIFFS
    spiffs_image = f"spiffs_{args.esp_id}.bin"
    if not create_spiffs_image(proof_file, spiffs_image):
        sys.exit(1)

    # 4. Gravar no ESP32
    if not flash_spiffs_to_esp(args.port, spiffs_image):
        sys.exit(1)

    # 5. Limpar arquivo temporário
    os.remove(spiffs_image)
    print(f"\n🗑️  Arquivo temporário removido: {spiffs_image}")

    print("\n" + "═" * 60)
    print("✅ PROCESSO COMPLETO!")
    print("═" * 60)
    print(f"""
Próximos passos:
  1. Programe o código ESP32 (esp32_sensor.ino)
  2. Reinicie o ESP32
  3. Verifique os logs seriais (115200 baud)
  4. Execute o controlador: cd SnifferESP && cargo run --release
""")


if __name__ == '__main__':
    main()
