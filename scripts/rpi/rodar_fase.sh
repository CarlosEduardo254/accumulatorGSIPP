#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# rodar_fase.sh — Sobe o udp_controller no Raspberry Pi para uma fase do
# experimento de dinamicidade (hardware real: ESP32 + PC via Wi-Fi).
#
#   ./rodar_fase.sh A1    # Fase 1: A1 = {ESP-01, ESP-02, ESP-42}
#   ./rodar_fase.sh A2    # Fase 3: A2 = {ESP-01, ESP-02}          (ESP-42 revogado)
#   ./rodar_fase.sh A3    # Fase 4: A3 = {ESP-01, ESP-02, ESP-99}  (ESP-99 adicionado)
#
# A chave pública do ESP-42 (embutida no controlador) fica cadastrada em TODAS
# as fases; ESP-02 e ESP-99 são cadastrados via --pubkey. Ctrl+C encerra a fase
# e o controlador imprime o resumo da sessão (gravado também no log).
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"

acc="${1:-}"
case "$acc" in
    A1|A2|A3) ;;
    *) echo "uso: ./rodar_fase.sh A1|A2|A3"; exit 2 ;;
esac

art=target/e2e_dinamicidade
mkdir -p logs
log="logs/controller_${acc}_$(date +%Y%m%d_%H%M%S).log"
echo "▶ Fase com ${acc} — log em ${log}"
echo "  Ctrl+C encerra a fase (o resumo da sessão é impresso e gravado)."
echo

# tee -i: ignora o Ctrl+C para não perder o resumo que o controlador imprime ao sair.
./udp_controller \
    --acc "${art}/accumulator_${acc}.dat" \
    --pubkey "ESP-02=${art}/keys/ESP_02.pub.pem" \
    --pubkey "ESP-99=${art}/keys/ESP_99.pub.pem" \
    2>&1 | tee -i "${log}"

echo
echo "✓ Fase ${acc} encerrada. Analise com: python3 analisar_log.py ${log}"
