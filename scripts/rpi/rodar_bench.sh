#!/usr/bin/env bash
# rodar_bench.sh — Parte A (dynamic_bench) no Raspberry Pi 3B+.
# Uso: ./rodar_bench.sh [flags extras do dynamic_bench, ex.: --heavy-reps 3]
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p logs
stamp=$(date +%Y%m%d_%H%M%S)
./dynamic_bench --ns 10,50,100,500,1000 --reps 20 --heavy-reps 5 --verify-reps 200 \
    --out "logs/resultados_dinamicidade_rpi_${stamp}.json" "$@" \
    2>&1 | tee "logs/dynamic_bench_rpi_${stamp}.log"
