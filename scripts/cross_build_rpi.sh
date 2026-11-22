#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# cross_build_rpi.sh — Compila (release) os binários para o Raspberry Pi 3B+
# (aarch64-unknown-linux-gnu) dentro do WSL2 e copia para dist/rpi-aarch64/.
#
# Pré-requisito: scripts/setup_wsl_cross.sh (uma vez).
# Uso (dentro do WSL, a partir da raiz do repositório em /mnt/c/...):
#   bash scripts/cross_build_rpi.sh
#
# O diretório de build fica no sistema de arquivos Linux ($HOME), que é muito
# mais rápido que /mnt/c para o configure/make da GMP.
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# shellcheck disable=SC1091
source "$HOME/.cargo/env"

TARGET=aarch64-unknown-linux-gnu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/accumulatorGSIPP-target}"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar

BINS=(udp_controller dynamic_bench dynamic_tmc dynamic_e2e interface_cbor)

cd "$REPO"
args=()
for b in "${BINS[@]}"; do args+=(--bin "$b"); done
cargo build --release --target "$TARGET" "${args[@]}"

OUT="$REPO/dist/rpi-aarch64"
mkdir -p "$OUT"
for b in "${BINS[@]}"; do
    cp "$CARGO_TARGET_DIR/$TARGET/release/$b" "$OUT/"
    # O perfil release do projeto tem debug=true (flamegraph); remove os símbolos
    # só da cópia do pacote para a transferência ao Pi ficar leve.
    aarch64-linux-gnu-strip "$OUT/$b"
done

# Scripts de execução no Pi
cp "$REPO"/scripts/rpi/rodar_fase.sh "$REPO"/scripts/rpi/rodar_bench.sh "$REPO"/scripts/rpi/analisar_log.py "$OUT/"
cp "$REPO"/SnifferESP/ROTEIRO_DINAMICIDADE_HARDWARE.md "$OUT/LEIA-ME.md"
chmod +x "$OUT"/*.sh "$OUT"/analisar_log.py

# Artefatos do TMC que o CONTROLADOR precisa (somente dados públicos:
# acumuladores e chaves públicas — chaves privadas e proofs ficam no PC/ESP32).
ART="$REPO/target/e2e_dinamicidade"
if [ -f "$ART/accumulator_A1.dat" ]; then
    mkdir -p "$OUT/target/e2e_dinamicidade/keys"
    cp "$ART"/accumulator_A{1,2,3}.dat "$ART/tmc_manifest.json" "$OUT/target/e2e_dinamicidade/"
    cp "$ART"/keys/*.pub.pem "$OUT/target/e2e_dinamicidade/keys/"
else
    echo "⚠  $ART não encontrado — rode o dynamic_tmc no PC antes de montar o pacote."
fi

# Checksums para conferir a cópia no Pi:  cd <pacote> && md5sum -c CHECKSUMS.md5
(cd "$OUT" && find . -type f ! -name CHECKSUMS.md5 | sort | sed 's|^\./||' | xargs md5sum > CHECKSUMS.md5)

echo
echo "✓ Binários aarch64 em $OUT:"
for b in "${BINS[@]}"; do
    need=$(aarch64-linux-gnu-objdump -T "$OUT/$b" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)
    printf "   %-16s %8s KiB   requer até %s\n" "$b" "$(( $(stat -c %s "$OUT/$b") / 1024 ))" "$need"
done
echo
echo "Confira no Raspberry Pi com 'ldd --version' que a glibc dele é >= à versão acima."
