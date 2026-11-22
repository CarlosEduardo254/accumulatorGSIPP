#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# setup_wsl_cross.sh — Prepara o WSL2 (Ubuntu) para cross-compilar o projeto
# para o Raspberry Pi 3B+ (aarch64-unknown-linux-gnu, Raspberry Pi OS 64 bits).
#
# Executar UMA vez dentro do WSL, como root:
#   wsl -d <distro> -u root -- bash /mnt/c/.../accumulatorGSIPP/scripts/setup_wsl_cross.sh
#
# Instala: build-essential, m4 (exigido pela GMP), gcc/g++ aarch64, rustup +
# alvo aarch64, e os mesmos symlinks <triplo-rust>-gcc usados no Cross.toml
# (o configure da GMP procura "aarch64-unknown-linux-gnu-gcc").
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential m4 curl ca-certificates pkg-config file \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu

# Mesmos symlinks do Cross.toml
for t in gcc g++ ar ranlib strip nm objdump; do
    ln -sf "/usr/bin/aarch64-linux-gnu-$t" "/usr/local/bin/aarch64-unknown-linux-gnu-$t"
done

# Rust (toolchain estável) + alvo do Raspberry Pi
if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
    curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup target add aarch64-unknown-linux-gnu

echo
echo "✓ Ambiente de cross-compilação pronto:"
aarch64-linux-gnu-gcc --version | head -1
rustc --version
echo "  glibc do sysroot aarch64: $(ls /usr/aarch64-linux-gnu/lib/libc.so.6 >/dev/null 2>&1 && \
    strings /usr/aarch64-linux-gnu/lib/libc.so.6 | grep -m1 'GNU C Library' || echo '?')"
