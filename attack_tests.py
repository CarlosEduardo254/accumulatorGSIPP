#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
  attack_tests.py — Avaliação Automatizada de Segurança
  TCC: Autenticação para ITS com Acumuladores Criptográficos RSA
═══════════════════════════════════════════════════════════════════

Metodologia (conforme artigo):
  A avaliação de segurança testa a resiliência contra dois modelos
  de ameaça — Spoofing e Replay Attack — simulados em lotes de 10
  repetições para quantificar a taxa de rejeição.

Testes implementados:
  SPOOFING (4 variantes, 10 repetições cada):
    S1: Proof forjada  — bytes aleatórios no lugar da witness + PoE
    S2: Proof nula      — campo membershipproof vazio (0 bytes)
    S3: Proof corrompida — proof legítima com 16 bytes invertidos
    S4: Chave do atacante — ID clonado, assinatura com chave RSA própria

  REPLAY (2 variantes, 10 repetições cada):
    R1: Timestamp expirado — pacote válido com ts 30s no passado (fora de Δt)
    R2: Pacote duplicado   — reenvio idêntico dentro da janela Δt

  BASELINE (controle):
    B1: Pacote legítimo — 10 pacotes válidos como referência de aceitação

Métricas coletadas:
  - Latência de construção + envio por pacote (ms)
  - Taxa de rejeição esperada por variante (verificada no controlador)
  - Tamanho do pacote por variante (bytes)

Uso:
  python3 attack_tests.py --target <IP_RASPBERRY> [--port 4242] [--test all]
  python3 attack_tests.py --target <IP_RASPBERRY> --test spoofing
  python3 attack_tests.py --target <IP_RASPBERRY> --test replay
  python3 attack_tests.py --target <IP_RASPBERRY> --test baseline

Pré-requisitos:
  - Python 3.8+ com cbor2 e cryptography
  - Controlador UDP rodando no Raspberry Pi (./udp_controller)
  - Ambos na mesma rede Wi-Fi
"""

import argparse
import hashlib
import json
import os
import socket
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


# ═══════════════════════════════════════════════════════════════
# CONSTANTES DE CONFIGURAÇÃO
# ═══════════════════════════════════════════════════════════════

DEFAULT_PORT = 4242
SENSOR_ID = "ESP-42"
BATCH_SIZE = 100
REPLAY_WINDOW_SECS = 5

# ═══════════════════════════════════════════════════════════════
# MATERIAL CRIPTOGRÁFICO — Chave privada legítima do ESP-42
# ═══════════════════════════════════════════════════════════════
# Extraída do firmware para possibilitar a construção de pacotes
# válidos (baseline) e ataques que exigem assinatura correta (S3, R1, R2).

ESP42_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDg8/gBUdLHnfPi
fpt4K/HH64ks9hTBgJrW0GP+6rMU3ndEzgr3tbKQEq9yhtQHO0iVTHmFKTHWkwdv
iBiyjPOkp7psfXk49QRH74si9WZRZFgsaFdCvtmgNtjy8JbfdivND7gkcjovp5o3
h5+obvigODWhquRduqrYbO7zs/AELw9pXlHu92G5k/3htsZf0X1NaQZx/KGApxV7
GQb5FvpEwDDTcDVeXTmgxXrabmt9vjMeHIlRZUlEk11MKqGOfMPJqFYzNVDa19/Q
GcjJsZOPxtY+DLwTBVQ7c3b4RnhNanBhBeo1+omeT8hzAdxGksSPAE12rEPnceUa
muRvI1Q9AgMBAAECggEACw/cOn5iUdgh2dm1ffmVPGpH9trMBv7yvk0Fmc/DSiut
bEgAkJFSDFUq5QQd0ZQ3+8WEtUhjD8TvqOuloUQeqBJqb7LU3vjngr0UF74/D5IS
Zu6jmd/mNkN0NDAiDy+RtFYJTVuDonvIsOHdt0vrtH9HHeHYNIa9J4Ll1jybOS1a
oalMPXiXZikxpvkEjX32Yi3I3L4YOF//yAR6iCQC/hsCRLwyh4T380IBSZV1/2tx
Ns6B+ybS73xLrV9X+lbZDTFzBYRKJgfGs/3iivnGvqxYVtlJDJm4E8bpINABF7dc
bEDIQdCftne1x5cL//6b8HL89YT1IRKbkhmzcp6iCQKBgQD7Hg4MzMHownTyDHBx
otx3oLJcPeQ+DkRktEZyBA761h3ihsAiJpPTy2653CwITLQwoLasIeE5i6+f1Exz
1DpcuH/ywSQKVK5RcvupnDO3Ccf2UqScL+XklyhsH6jmHipwB+KkLbPwiT3M6Vxn
sNUWJ5sFTcvJQx9AuCUEhnw+GQKBgQDlU64C8VRxVt+DSl5gxZMbtOv2cHgwutU5
SOq57L8lIn7EwgQyJAcAkzuBBVlbji6E+3GtUC3jGEDOMiRU9D25f2nx+Zla1YYt
zwprSapyYc5CYk+55sFpDIh0D29oJVMD2qkZ8CMMakA2z/DAvX1YDZmOvMCS8llh
+uUesl9DxQKBgBQQDqdPJJ7oClfcTo+Fp3+XQyjDeRzMHwK8tHQfhuLbgH+8rFUO
J/lf43TN9majWjIYZP/TpR7n3hwy5fjLF+6YfwByFeMNaO/w89JVPHx/N46ig6xG
12MwAHbDAMeB2Xoh5yWe0SWCkYFxk4RlSGEAwQ3nbUSjLDgLfkmiRQLhAoGAdz/H
SdJyRamV+rCOWSYENDElTnX3meddfzdSj7HzR30jjG8TPXuMhJkLJTFB4SETQaV6
3FPIOMHg2Rgr2l1TR4Vg8yoGu7wy1NlHorigwG/pkI2Mxa+fvV9+CVQJa4+VFnj6
2/kKUKdjkt0YZTFj34ja4+V1AjSxlAiiYg8BCL0CgYEAmwmyXqo1ZzbnuMmRu5Bl
Z3ift7jxvrMf7r93rLFkvS95D7xqYx+q1SvkK/+QtriEFGTUzFbC8mXJugZfmy/G
2rmLH8AwARYqwY6NIPHKl8k4mY6f5c1LYKDMskUGPiPeEnawMSSm64cu3MVjxi+a
dbhl6UebIeL+HnjKQ7xODw0=
-----END PRIVATE KEY-----
"""

# ═══════════════════════════════════════════════════════════════
# MEMBERSHIP PROOF LEGÍTIMA DO ESP-42 (1064 bytes)
# ═══════════════════════════════════════════════════════════════
# Contém a witness w_i e a Proof of Exponentiation (PoE) geradas
# pelo setup do acumulador (cargo run --bin setup).

ESP42_PROOF_BYTES = bytes([
    0xA2, 0x67, 0x77, 0x69, 0x74, 0x6E, 0x65, 0x73, 0x73, 0xA2, 0x67, 0x70,
    0x68, 0x61, 0x6E, 0x74, 0x6F, 0x6D, 0xF6, 0x65, 0x76, 0x61, 0x6C, 0x75,
    0x65, 0x79, 0x02, 0x00, 0x35, 0x33, 0x37, 0x66, 0x34, 0x62, 0x35, 0x37,
    0x33, 0x33, 0x36, 0x36, 0x64, 0x33, 0x38, 0x31, 0x62, 0x62, 0x39, 0x33,
    0x37, 0x38, 0x63, 0x38, 0x61, 0x62, 0x37, 0x64, 0x66, 0x66, 0x35, 0x33,
    0x63, 0x30, 0x35, 0x38, 0x33, 0x34, 0x37, 0x32, 0x34, 0x36, 0x32, 0x37,
    0x34, 0x65, 0x62, 0x64, 0x36, 0x66, 0x30, 0x38, 0x31, 0x62, 0x62, 0x34,
    0x30, 0x32, 0x66, 0x35, 0x31, 0x39, 0x63, 0x30, 0x32, 0x38, 0x38, 0x31,
    0x31, 0x64, 0x37, 0x62, 0x64, 0x64, 0x66, 0x38, 0x33, 0x39, 0x36, 0x33,
    0x66, 0x30, 0x34, 0x65, 0x63, 0x39, 0x34, 0x66, 0x32, 0x61, 0x66, 0x31,
    0x63, 0x64, 0x63, 0x63, 0x66, 0x38, 0x37, 0x36, 0x35, 0x36, 0x36, 0x33,
    0x66, 0x34, 0x31, 0x61, 0x39, 0x32, 0x36, 0x38, 0x32, 0x64, 0x37, 0x34,
    0x66, 0x65, 0x34, 0x62, 0x32, 0x38, 0x37, 0x32, 0x36, 0x34, 0x66, 0x37,
    0x66, 0x32, 0x30, 0x34, 0x62, 0x63, 0x39, 0x35, 0x35, 0x36, 0x66, 0x61,
    0x31, 0x30, 0x34, 0x33, 0x33, 0x39, 0x37, 0x31, 0x38, 0x37, 0x30, 0x66,
    0x38, 0x36, 0x36, 0x66, 0x37, 0x39, 0x62, 0x65, 0x64, 0x61, 0x62, 0x39,
    0x37, 0x36, 0x63, 0x36, 0x65, 0x38, 0x37, 0x35, 0x65, 0x61, 0x66, 0x65,
    0x61, 0x37, 0x31, 0x33, 0x39, 0x61, 0x61, 0x38, 0x64, 0x64, 0x32, 0x32,
    0x64, 0x38, 0x37, 0x62, 0x32, 0x35, 0x38, 0x36, 0x63, 0x30, 0x66, 0x36,
    0x36, 0x62, 0x34, 0x33, 0x32, 0x31, 0x62, 0x36, 0x65, 0x35, 0x66, 0x34,
    0x32, 0x34, 0x31, 0x66, 0x38, 0x38, 0x30, 0x33, 0x31, 0x30, 0x31, 0x65,
    0x38, 0x34, 0x34, 0x62, 0x31, 0x34, 0x30, 0x39, 0x62, 0x33, 0x64, 0x64,
    0x63, 0x36, 0x31, 0x37, 0x30, 0x37, 0x33, 0x63, 0x32, 0x63, 0x65, 0x61,
    0x33, 0x33, 0x30, 0x34, 0x32, 0x39, 0x36, 0x62, 0x64, 0x32, 0x38, 0x39,
    0x30, 0x62, 0x61, 0x31, 0x32, 0x62, 0x66, 0x32, 0x37, 0x38, 0x34, 0x34,
    0x66, 0x35, 0x33, 0x31, 0x31, 0x34, 0x33, 0x39, 0x32, 0x39, 0x32, 0x35,
    0x65, 0x63, 0x66, 0x32, 0x32, 0x61, 0x32, 0x63, 0x33, 0x38, 0x35, 0x38,
    0x31, 0x39, 0x35, 0x37, 0x65, 0x63, 0x33, 0x33, 0x64, 0x62, 0x31, 0x39,
    0x34, 0x63, 0x37, 0x65, 0x63, 0x33, 0x64, 0x61, 0x32, 0x36, 0x63, 0x63,
    0x32, 0x66, 0x64, 0x38, 0x30, 0x35, 0x39, 0x33, 0x37, 0x38, 0x61, 0x33,
    0x35, 0x39, 0x37, 0x36, 0x65, 0x35, 0x63, 0x61, 0x37, 0x35, 0x65, 0x35,
    0x30, 0x38, 0x32, 0x64, 0x36, 0x61, 0x36, 0x65, 0x32, 0x36, 0x64, 0x33,
    0x64, 0x33, 0x33, 0x31, 0x64, 0x32, 0x38, 0x38, 0x39, 0x65, 0x39, 0x64,
    0x66, 0x30, 0x66, 0x66, 0x64, 0x31, 0x39, 0x32, 0x61, 0x62, 0x65, 0x66,
    0x36, 0x36, 0x31, 0x64, 0x35, 0x38, 0x64, 0x34, 0x37, 0x34, 0x37, 0x61,
    0x38, 0x35, 0x36, 0x66, 0x65, 0x31, 0x62, 0x61, 0x37, 0x34, 0x64, 0x39,
    0x36, 0x38, 0x61, 0x36, 0x33, 0x63, 0x31, 0x66, 0x64, 0x39, 0x65, 0x64,
    0x35, 0x33, 0x31, 0x39, 0x62, 0x33, 0x39, 0x37, 0x62, 0x38, 0x65, 0x64,
    0x39, 0x38, 0x37, 0x30, 0x30, 0x36, 0x30, 0x31, 0x66, 0x34, 0x38, 0x36,
    0x31, 0x31, 0x39, 0x38, 0x62, 0x34, 0x64, 0x39, 0x32, 0x34, 0x39, 0x33,
    0x30, 0x35, 0x66, 0x30, 0x61, 0x61, 0x31, 0x30, 0x31, 0x63, 0x39, 0x31,
    0x33, 0x61, 0x33, 0x64, 0x34, 0x31, 0x32, 0x62, 0x33, 0x32, 0x39, 0x34,
    0x37, 0x61, 0x61, 0x34, 0x38, 0x36, 0x36, 0x66, 0x35, 0x38, 0x66, 0x65,
    0x38, 0x64, 0x34, 0x61, 0x33, 0x63, 0x39, 0x30, 0x37, 0x65, 0x62, 0x37,
    0x61, 0x63, 0x34, 0x31, 0x37, 0x62, 0x65, 0x38, 0x38, 0x63, 0x37, 0x64,
    0x65, 0x70, 0x72, 0x6F, 0x6F, 0x66, 0xA1, 0x61, 0x51, 0x79, 0x02, 0x00,
    0x35, 0x33, 0x37, 0x66, 0x34, 0x62, 0x35, 0x37, 0x33, 0x33, 0x36, 0x36,
    0x64, 0x33, 0x38, 0x31, 0x62, 0x62, 0x39, 0x33, 0x37, 0x38, 0x63, 0x38,
    0x61, 0x62, 0x37, 0x64, 0x66, 0x66, 0x35, 0x33, 0x63, 0x30, 0x35, 0x38,
    0x33, 0x34, 0x37, 0x32, 0x34, 0x36, 0x32, 0x37, 0x34, 0x65, 0x62, 0x64,
    0x36, 0x66, 0x30, 0x38, 0x31, 0x62, 0x62, 0x34, 0x30, 0x32, 0x66, 0x35,
    0x31, 0x39, 0x63, 0x30, 0x32, 0x38, 0x38, 0x31, 0x31, 0x64, 0x37, 0x62,
    0x64, 0x64, 0x66, 0x38, 0x33, 0x39, 0x36, 0x33, 0x66, 0x30, 0x34, 0x65,
    0x63, 0x39, 0x34, 0x66, 0x32, 0x61, 0x66, 0x31, 0x63, 0x64, 0x63, 0x63,
    0x66, 0x38, 0x37, 0x36, 0x35, 0x36, 0x36, 0x33, 0x66, 0x34, 0x31, 0x61,
    0x39, 0x32, 0x36, 0x38, 0x32, 0x64, 0x37, 0x34, 0x66, 0x65, 0x34, 0x62,
    0x32, 0x38, 0x37, 0x32, 0x36, 0x34, 0x66, 0x37, 0x66, 0x32, 0x30, 0x34,
    0x62, 0x63, 0x39, 0x35, 0x35, 0x36, 0x66, 0x61, 0x31, 0x30, 0x34, 0x33,
    0x33, 0x39, 0x37, 0x31, 0x38, 0x37, 0x30, 0x66, 0x38, 0x36, 0x36, 0x66,
    0x37, 0x39, 0x62, 0x65, 0x64, 0x61, 0x62, 0x39, 0x37, 0x36, 0x63, 0x36,
    0x65, 0x38, 0x37, 0x35, 0x65, 0x61, 0x66, 0x65, 0x61, 0x37, 0x31, 0x33,
    0x39, 0x61, 0x61, 0x38, 0x64, 0x64, 0x32, 0x32, 0x64, 0x38, 0x37, 0x62,
    0x32, 0x35, 0x38, 0x36, 0x63, 0x30, 0x66, 0x36, 0x36, 0x62, 0x34, 0x33,
    0x32, 0x31, 0x62, 0x36, 0x65, 0x35, 0x66, 0x34, 0x32, 0x34, 0x31, 0x66,
    0x38, 0x38, 0x30, 0x33, 0x31, 0x30, 0x31, 0x65, 0x38, 0x34, 0x34, 0x62,
    0x31, 0x34, 0x30, 0x39, 0x62, 0x33, 0x64, 0x64, 0x63, 0x36, 0x31, 0x37,
    0x30, 0x37, 0x33, 0x63, 0x32, 0x63, 0x65, 0x61, 0x33, 0x33, 0x30, 0x34,
    0x32, 0x39, 0x36, 0x62, 0x64, 0x32, 0x38, 0x39, 0x30, 0x62, 0x61, 0x31,
    0x32, 0x62, 0x66, 0x32, 0x37, 0x38, 0x34, 0x34, 0x66, 0x35, 0x33, 0x31,
    0x31, 0x34, 0x33, 0x39, 0x32, 0x39, 0x32, 0x35, 0x65, 0x63, 0x66, 0x32,
    0x32, 0x61, 0x32, 0x63, 0x33, 0x38, 0x35, 0x38, 0x31, 0x39, 0x35, 0x37,
    0x65, 0x63, 0x33, 0x33, 0x64, 0x62, 0x31, 0x39, 0x34, 0x63, 0x37, 0x65,
    0x63, 0x33, 0x64, 0x61, 0x32, 0x36, 0x63, 0x63, 0x32, 0x66, 0x64, 0x38,
    0x30, 0x35, 0x39, 0x33, 0x37, 0x38, 0x61, 0x33, 0x35, 0x39, 0x37, 0x36,
    0x65, 0x35, 0x63, 0x61, 0x37, 0x35, 0x65, 0x35, 0x30, 0x38, 0x32, 0x64,
    0x36, 0x61, 0x36, 0x65, 0x32, 0x36, 0x64, 0x33, 0x64, 0x33, 0x33, 0x31,
    0x64, 0x32, 0x38, 0x38, 0x39, 0x65, 0x39, 0x64, 0x66, 0x30, 0x66, 0x66,
    0x64, 0x31, 0x39, 0x32, 0x61, 0x62, 0x65, 0x66, 0x36, 0x36, 0x31, 0x64,
    0x35, 0x38, 0x64, 0x34, 0x37, 0x34, 0x37, 0x61, 0x38, 0x35, 0x36, 0x66,
    0x65, 0x31, 0x62, 0x61, 0x37, 0x34, 0x64, 0x39, 0x36, 0x38, 0x61, 0x36,
    0x33, 0x63, 0x31, 0x66, 0x64, 0x39, 0x65, 0x64, 0x35, 0x33, 0x31, 0x39,
    0x62, 0x33, 0x39, 0x37, 0x62, 0x38, 0x65, 0x64, 0x39, 0x38, 0x37, 0x30,
    0x30, 0x36, 0x30, 0x31, 0x66, 0x34, 0x38, 0x36, 0x31, 0x31, 0x39, 0x38,
    0x62, 0x34, 0x64, 0x39, 0x32, 0x34, 0x39, 0x33, 0x30, 0x35, 0x66, 0x30,
    0x61, 0x61, 0x31, 0x30, 0x31, 0x63, 0x39, 0x31, 0x33, 0x61, 0x33, 0x64,
    0x34, 0x31, 0x32, 0x62, 0x33, 0x32, 0x39, 0x34, 0x37, 0x61, 0x61, 0x34,
    0x38, 0x36, 0x36, 0x66, 0x35, 0x38, 0x66, 0x65, 0x38, 0x64, 0x34, 0x61,
    0x33, 0x63, 0x39, 0x30, 0x37, 0x65, 0x62, 0x37, 0x61, 0x63, 0x34, 0x31,
    0x37, 0x62, 0x65, 0x38, 0x38, 0x63, 0x37, 0x64,
])


# ═══════════════════════════════════════════════════════════════
# ESTRUTURAS DE DADOS PARA MÉTRICAS
# ═══════════════════════════════════════════════════════════════

@dataclass
class PacketResult:
    """Resultado de um único envio de pacote."""
    iteration: int
    packet_size: int
    latency_ms: float
    sent: bool


@dataclass
class BatchResult:
    """Resultado agregado de um lote de N repetições."""
    test_id: str
    test_name: str
    category: str           # "Spoofing", "Replay" ou "Baseline"
    expected_result: str    # "REJEITADO" ou "ACEITO"
    blocked_by: str         # Qual verificação deve bloquear (ex: "Verificação 03")
    results: List[PacketResult] = field(default_factory=list)

    @property
    def total_sent(self) -> int:
        return sum(1 for r in self.results if r.sent)

    @property
    def latencies(self) -> List[float]:
        return [r.latency_ms for r in self.results if r.sent]

    @property
    def avg_latency(self) -> float:
        return statistics.mean(self.latencies) if self.latencies else 0.0

    @property
    def min_latency(self) -> float:
        return min(self.latencies) if self.latencies else 0.0

    @property
    def max_latency(self) -> float:
        return max(self.latencies) if self.latencies else 0.0

    @property
    def stdev_latency(self) -> float:
        return statistics.stdev(self.latencies) if len(self.latencies) > 1 else 0.0

    @property
    def avg_size(self) -> float:
        sizes = [r.packet_size for r in self.results if r.sent]
        return statistics.mean(sizes) if sizes else 0.0


# ═══════════════════════════════════════════════════════════════
# FUNÇÕES AUXILIARES — Criptografia e Rede
# ═══════════════════════════════════════════════════════════════

def load_esp42_private_key():
    """Carrega a chave privada RSA-2048 legítima do ESP-42."""
    return serialization.load_pem_private_key(ESP42_PRIVATE_KEY_PEM, password=None)


def generate_attacker_key():
    """Gera um par RSA-2048 exclusivo do atacante."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_data(private_key, sensor_id: str, timestamp: int, reading: int) -> bytes:
    """
    Assina os dados exatamente como o ESP32:
    SHA-256("sensor_id|timestamp|reading") → PKCS#1 v1.5 (prehashed).
    """
    data_str = f"{sensor_id}|{timestamp}|{reading}"
    digest = hashlib.sha256(data_str.encode("utf-8")).digest()
    return private_key.sign(
        digest,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )


def build_cbor_packet(sensor_id, timestamp, reading, signature, proof) -> bytes:
    """
    Monta o payload CBOR com 5 campos (formato idêntico ao ESP32):
      "1" → sensor_id, "2" → timestamp, "3" → reading,
      "4" → signature, "5" → membershipproof
    """
    return cbor2.dumps({
        "1": sensor_id,
        "2": timestamp,
        "3": reading,
        "4": signature,
        "5": proof,
    })


def send_udp(target_ip: str, port: int, data: bytes) -> Tuple[bool, float]:
    """Envia pacote UDP e retorna (sucesso, latência_ms)."""
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, (target_ip, port))
        sock.close()
        return True, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, (time.perf_counter() - t0) * 1000


# ═══════════════════════════════════════════════════════════════
# CLASSE PRINCIPAL — Suite de Testes de Segurança
# ═══════════════════════════════════════════════════════════════

class SecurityTestSuite:
    """Orquestra os testes de spoofing e replay conforme a metodologia do artigo."""

    def __init__(self, target_ip: str, port: int = DEFAULT_PORT):
        self.target_ip = target_ip
        self.port = port
        self.esp42_key = load_esp42_private_key()
        self.attacker_key = generate_attacker_key()
        self.all_batches: List[BatchResult] = []
        self._next_reading = 1  # Contador sequencial global (1, 2, 3, ...)

    def _get_reading(self) -> int:
        """Retorna o próximo reading sequencial."""
        r = self._next_reading
        self._next_reading += 1
        return r

    # ──────────────────────────────────────────────────────
    # RUNNER GENÉRICO — executa N repetições de um builder
    # ──────────────────────────────────────────────────────

    def _run_batch(
        self,
        test_id: str,
        test_name: str,
        category: str,
        expected: str,
        blocked_by: str,
        packet_builder: Callable[[int], bytes],
        reps: int = BATCH_SIZE,
    ) -> BatchResult:
        """Executa `reps` repetições de `packet_builder`, mede latência e coleta resultados."""
        batch = BatchResult(test_id, test_name, category, expected, blocked_by)
        self._print_header(batch, reps)

        for i in range(reps):
            # Medir tempo total: construção + envio
            t0 = time.perf_counter()
            pkt = packet_builder(i)
            sent, _ = send_udp(self.target_ip, self.port, pkt)
            latency = (time.perf_counter() - t0) * 1000

            result = PacketResult(i + 1, len(pkt), latency, sent)
            batch.results.append(result)
            self._print_row(result)

            time.sleep(0.2)  # 200ms entre pacotes para o controlador processar

        self._print_footer(batch)
        self.all_batches.append(batch)
        return batch

    # ──────────────────────────────────────────────────────
    # SPOOFING — 4 variantes (Teste 1 do artigo)
    # ──────────────────────────────────────────────────────

    def spoofing_forged_proof(self) -> BatchResult:
        """
        S1 — Proof forjada: bytes aleatórios no campo membershipproof.
        Assinatura RSA válida (passa na Verif. 02), mas witness+PoE são lixo.
        Esperado: REJEITADO pela Verificação 03 (deserialização ou verify_membership).
        """
        def builder(i: int) -> bytes:
            ts = int(time.time())
            reading = self._get_reading()
            sig = sign_data(self.esp42_key, SENSOR_ID, ts, reading)
            fake_proof = os.urandom(len(ESP42_PROOF_BYTES))
            return build_cbor_packet(SENSOR_ID, ts, reading, sig, fake_proof)

        return self._run_batch(
            "S1", "Proof Forjada (bytes aleatórios)", "Spoofing",
            "REJEITADO", "Verificação 03", builder,
        )

    def spoofing_null_proof(self) -> BatchResult:
        """
        S2 — Proof nula: campo membershipproof com 0 bytes.
        Assinatura RSA válida. Simula nó espúrio sem witness provisionada.
        Esperado: REJEITADO pela Verificação 03 (proof vazia não desserializa).
        """
        def builder(i: int) -> bytes:
            ts = int(time.time())
            reading = self._get_reading()
            sig = sign_data(self.esp42_key, SENSOR_ID, ts, reading)
            return build_cbor_packet(SENSOR_ID, ts, reading, sig, b"")

        return self._run_batch(
            "S2", "Proof Nula (0 bytes)", "Spoofing",
            "REJEITADO", "Verificação 03", builder,
        )

    def spoofing_corrupted_proof(self) -> BatchResult:
        """
        S3 — Proof corrompida: proof legítima com 16 bytes invertidos (bit flip).
        Assinatura RSA válida. Simula adulteração da witness em trânsito.
        Esperado: REJEITADO pela Verificação 03 (witness^hash(id) ≠ acumulador).
        """
        def builder(i: int) -> bytes:
            ts = int(time.time())
            reading = self._get_reading()
            sig = sign_data(self.esp42_key, SENSOR_ID, ts, reading)
            corrupted = bytearray(ESP42_PROOF_BYTES)
            for j in range(50, 66):
                corrupted[j] ^= 0xFF
            return build_cbor_packet(SENSOR_ID, ts, reading, sig, bytes(corrupted))

        return self._run_batch(
            "S3", "Proof Corrompida (bit flip)", "Spoofing",
            "REJEITADO", "Verificação 03", builder,
        )

    def spoofing_wrong_key(self) -> BatchResult:
        """
        S4 — Chave do atacante: ID legítimo (ESP-42) mas assinado com chave RSA
        própria do atacante. Proof legítima (capturada do ar).
        Esperado: REJEITADO pela Verificação 02 (assinatura não bate com pub key).
        """
        def builder(i: int) -> bytes:
            ts = int(time.time())
            reading = self._get_reading()
            sig = sign_data(self.attacker_key, SENSOR_ID, ts, reading)
            return build_cbor_packet(SENSOR_ID, ts, reading, sig, ESP42_PROOF_BYTES)

        return self._run_batch(
            "S4", "Chave do Atacante (ID clonado)", "Spoofing",
            "REJEITADO", "Verificação 02", builder,
        )

    # ──────────────────────────────────────────────────────
    # REPLAY — 2 variantes (Teste 2 do artigo)
    # ──────────────────────────────────────────────────────

    def replay_stale_timestamp(self) -> BatchResult:
        """
        R1 — Timestamp expirado: pacote com assinatura e proof válidas,
        mas timestamp 30s no passado (fora da janela Δt = 5s).
        Simula reenvio de pacote capturado após a janela expirar.
        Esperado: REJEITADO pela Verificação 01 (|now - ts| > 5s).
        """
        def builder(i: int) -> bytes:
            ts = int(time.time()) - 30  # 30 segundos no passado
            reading = self._get_reading()
            sig = sign_data(self.esp42_key, SENSOR_ID, ts, reading)
            return build_cbor_packet(SENSOR_ID, ts, reading, sig, ESP42_PROOF_BYTES)

        return self._run_batch(
            "R1", "Timestamp Expirado (Δt > 5s)", "Replay",
            "REJEITADO", "Verificação 01", builder,
        )

    def replay_duplicate(self) -> BatchResult:
        """
        R2 — Pacote duplicado: envia pacote legítimo e imediatamente reenvia
        o mesmo pacote (replay dentro da janela Δt).
        Para cada iteração: 1 legítimo (aceito) + 1 réplica (rejeitada).
        Esperado: Réplica REJEITADA pela Verificação 01b (cache de deduplicação).
        """
        batch = BatchResult(
            "R2", "Pacote Duplicado (replay intra-janela)", "Replay",
            "REJEITADO", "Verificação 01b",
        )
        self._print_header(batch, BATCH_SIZE)
        print("  ℹ  Cada iteração: 1 pacote legítimo (aceito) + 1 réplica (medida)\n")

        for i in range(BATCH_SIZE):
            ts = int(time.time())
            reading = self._get_reading()
            sig = sign_data(self.esp42_key, SENSOR_ID, ts, reading)
            pkt = build_cbor_packet(SENSOR_ID, ts, reading, sig, ESP42_PROOF_BYTES)

            # 1. Enviar pacote legítimo (deve ser ACEITO pelo controlador)
            send_udp(self.target_ip, self.port, pkt)
            time.sleep(0.1)  # 100ms para o controlador processar e cachear

            # 2. Reenviar o MESMO pacote (deve ser REJEITADO — replay)
            t0 = time.perf_counter()
            sent, _ = send_udp(self.target_ip, self.port, pkt)
            latency = (time.perf_counter() - t0) * 1000

            result = PacketResult(i + 1, len(pkt), latency, sent)
            batch.results.append(result)
            self._print_row(result)
            time.sleep(0.2)  # 200ms entre iterações

        self._print_footer(batch)
        self.all_batches.append(batch)
        return batch

    # ──────────────────────────────────────────────────────
    # BASELINE — pacotes legítimos para referência
    # ──────────────────────────────────────────────────────

    def baseline_legitimate(self) -> BatchResult:
        """
        B1 — Pacote legítimo: 10 pacotes 100% válidos como grupo de controle.
        Assinatura, timestamp e proof corretos.
        Esperado: ACEITO (todas as 3 verificações passam).
        """
        def builder(i: int) -> bytes:
            ts = int(time.time())
            reading = self._get_reading()
            sig = sign_data(self.esp42_key, SENSOR_ID, ts, reading)
            return build_cbor_packet(SENSOR_ID, ts, reading, sig, ESP42_PROOF_BYTES)

        return self._run_batch(
            "B1", "Pacote Legítimo (controle)", "Baseline",
            "ACEITO", "Todas passam", builder,
        )

    # ──────────────────────────────────────────────────────
    # FORMATAÇÃO DO OUTPUT
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _print_header(batch: BatchResult, reps: int):
        print(f"\n{'═' * 70}")
        print(f"  [{batch.test_id}] {batch.test_name}")
        print(f"  Categoria: {batch.category} | Repetições: {reps}")
        print(f"  Esperado: {batch.expected_result} — {batch.blocked_by}")
        print(f"{'═' * 70}")
        print(f"  {'#':>3} │ {'Tamanho':>9} │ {'Latência':>12} │ {'Status'}")
        print(f"  {'─' * 3}─┼─{'─' * 9}─┼─{'─' * 12}─┼─{'─' * 12}")

    @staticmethod
    def _print_row(r: PacketResult):
        status = "✓ Enviado" if r.sent else "✗ Falha"
        print(f"  {r.iteration:>3} │ {r.packet_size:>7} B │ {r.latency_ms:>9.3f} ms │ {status}")

    @staticmethod
    def _print_footer(batch: BatchResult):
        n = len(batch.results)
        print(f"  {'─' * 3}─┴─{'─' * 9}─┴─{'─' * 12}─┴─{'─' * 12}")
        print(f"  Pacotes enviados:  {batch.total_sent}/{n}")
        if batch.total_sent > 0:
            print(f"  Tamanho médio:     {batch.avg_size:.0f} bytes")
            print(f"  Latência média:    {batch.avg_latency:.3f} ms")
            print(f"  Latência min/máx:  {batch.min_latency:.3f} / {batch.max_latency:.3f} ms")
            if batch.stdev_latency > 0:
                print(f"  Desvio padrão:     {batch.stdev_latency:.3f} ms")
        print(f"  Resultado esperado: {batch.expected_result} ({batch.blocked_by})")

    # ──────────────────────────────────────────────────────
    # RELATÓRIO FINAL CONSOLIDADO
    # ──────────────────────────────────────────────────────

    def print_final_report(self):
        """Imprime tabela consolidada com todas as baterias executadas."""
        W = 86  # largura total da tabela

        print(f"\n\n{'═' * W}")
        print(f"{'RELATÓRIO CONSOLIDADO — Avaliação de Segurança':^{W}}")
        print(f"{'═' * W}")

        # Cabeçalho da tabela
        print(
            f"  {'Categoria':<10} │ {'ID':>3} │ {'Variante':<35} │ "
            f"{'Enviados':>8} │ {'Esperado':>10} │ {'Lat.(ms)':>9}"
        )
        print(
            f"  {'─' * 10}─┼─{'─' * 3}─┼─{'─' * 35}─┼─"
            f"{'─' * 8}─┼─{'─' * 10}─┼─{'─' * 9}"
        )

        # Linhas de dados
        prev_cat = None
        for b in self.all_batches:
            if prev_cat and b.category != prev_cat:
                print(
                    f"  {'─' * 10}─┼─{'─' * 3}─┼─{'─' * 35}─┼─"
                    f"{'─' * 8}─┼─{'─' * 10}─┼─{'─' * 9}"
                )
            prev_cat = b.category

            n = len(b.results)
            print(
                f"  {b.category:<10} │ {b.test_id:>3} │ {b.test_name:<35} │ "
                f"{b.total_sent:>4}/{n:<3} │ {b.expected_result:>10} │ "
                f"{b.avg_latency:>6.3f} ms"
            )

        print(f"  {'═' * 10}═╧═{'═' * 3}═╧═{'═' * 35}═╧═{'═' * 8}═╧═{'═' * 10}═╧═{'═' * 9}")

        # Resumo numérico
        attack_batches = [b for b in self.all_batches if b.expected_result == "REJEITADO"]
        baseline_batches = [b for b in self.all_batches if b.expected_result == "ACEITO"]

        total_attack = sum(b.total_sent for b in attack_batches)
        total_baseline = sum(b.total_sent for b in baseline_batches)
        all_latencies = []
        for b in attack_batches:
            all_latencies.extend(b.latencies)

        print(f"\n  Pacotes de ataque transmitidos:    {total_attack}")
        print(f"  Pacotes legítimos transmitidos:    {total_baseline}")
        print(f"  Taxa de rejeição esperada:         100% ({total_attack}/{total_attack})")
        if all_latencies:
            print(f"  Latência média dos ataques:        {statistics.mean(all_latencies):.3f} ms")
        print()
        print(f"  ℹ  Confirme a taxa de rejeição real no terminal do controlador.")
        print(f"     Use Ctrl+C no controlador para exibir o resumo da sessão.")
        print(f"{'═' * W}\n")

    def export_json(self, filepath: str = "resultados_teste.json"):
        """Exporta todos os resultados em JSON estruturado para análise posterior."""
        from datetime import datetime

        attack_batches = [b for b in self.all_batches if b.expected_result == "REJEITADO"]
        baseline_batches = [b for b in self.all_batches if b.expected_result == "ACEITO"]
        total_attack = sum(b.total_sent for b in attack_batches)
        total_baseline = sum(b.total_sent for b in baseline_batches)

        all_attack_latencies = []
        for b in attack_batches:
            all_attack_latencies.extend(b.latencies)

        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "target": self.target_ip,
                "port": self.port,
                "batch_size": BATCH_SIZE,
                "replay_window_secs": REPLAY_WINDOW_SECS,
                "inter_packet_delay_ms": 200,
            },
            "summary": {
                "total_attack_packets": total_attack,
                "total_baseline_packets": total_baseline,
                "expected_rejection_rate": "100%",
                "avg_attack_latency_ms": round(statistics.mean(all_attack_latencies), 3) if all_attack_latencies else 0,
            },
            "tests": [],
        }

        for b in self.all_batches:
            test_data = {
                "id": b.test_id,
                "name": b.test_name,
                "category": b.category,
                "expected_result": b.expected_result,
                "blocked_by": b.blocked_by,
                "packets_sent": b.total_sent,
                "packets_total": len(b.results),
                "latency": {
                    "avg_ms": round(b.avg_latency, 3),
                    "min_ms": round(b.min_latency, 3),
                    "max_ms": round(b.max_latency, 3),
                    "stdev_ms": round(b.stdev_latency, 3),
                },
                "avg_packet_size_bytes": round(b.avg_size),
                "per_packet": [
                    {
                        "iteration": r.iteration,
                        "size_bytes": r.packet_size,
                        "latency_ms": round(r.latency_ms, 3),
                        "sent": r.sent,
                    }
                    for r in b.results
                ],
            }
            report["tests"].append(test_data)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n  📄 Resultados exportados para: {filepath}")


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Avaliação Automatizada de Segurança — TCC GSIPP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 attack_tests.py --target 172.16.0.72 --test all
  python3 attack_tests.py --target 172.16.0.72 --test spoofing
  python3 attack_tests.py --target 172.16.0.72 --test replay
  python3 attack_tests.py --target 172.16.0.72 --test baseline
        """,
    )
    parser.add_argument(
        "--target", required=True,
        help="IP do Raspberry Pi (controlador)",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Porta UDP (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--test", default="all",
        choices=["all", "spoofing", "replay", "baseline"],
        help="Bateria de testes: all, spoofing, replay ou baseline (default: all)",
    )
    parser.add_argument(
        "--no-pause", action="store_true",
        help="Não aguardar ENTER entre testes diferentes",
    )

    args = parser.parse_args()
    suite = SecurityTestSuite(args.target, args.port)

    # Cabeçalho
    print(f"\n{'═' * 70}")
    print(f"  🔒 Avaliação Automatizada de Segurança — TCC GSIPP")
    print(f"{'═' * 70}")
    print(f"  Alvo:        {args.target}:{args.port}")
    print(f"  Bateria:     {args.test}")
    print(f"  Repetições:  {BATCH_SIZE} por variante")
    print(f"  Janela Δt:   {REPLAY_WINDOW_SECS}s")
    print(f"{'═' * 70}")

    # ── Montar lista de testes a executar ──
    tests_to_run = []

    if args.test in ("all", "baseline"):
        tests_to_run.append(suite.baseline_legitimate)

    if args.test in ("all", "spoofing"):
        tests_to_run.extend([
            suite.spoofing_forged_proof,
            suite.spoofing_null_proof,
            suite.spoofing_corrupted_proof,
            suite.spoofing_wrong_key,
        ])

    if args.test in ("all", "replay"):
        tests_to_run.extend([
            suite.replay_stale_timestamp,
            suite.replay_duplicate,
        ])

    # ── Executar testes com pausa entre diferentes baterias ──
    total_tests = len(tests_to_run)
    for i, test_func in enumerate(tests_to_run, 1):
        test_func()
        if i < total_tests and not args.no_pause:
            try:
                input("\n⏸  Pressione [ENTER] para ir para o próximo teste...")
            except (KeyboardInterrupt, EOFError):
                print("\n\nExecução interrompida pelo usuário.")
                break

    # ── Relatório consolidado e exportação ──
    suite.print_final_report()
    suite.export_json()


if __name__ == "__main__":
    main()
