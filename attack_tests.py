#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
  Script de Testes de Ataque — Validação de Segurança TCC GSIPP
═══════════════════════════════════════════════════════════════════

Simula 7 cenários de ataque contra o controlador UDP (Raspberry Pi).
Cada teste verifica se uma das 3 verificações rejeita o pacote corretamente.

Pré-requisitos:
  - Python 3.8+ com cbor2 e cryptography instalados
  - O controlador UDP rodando no Raspberry Pi (./udp_controller)
  - Estar na mesma rede local

Uso:
  python3 attack_tests.py --target <IP_RASPBERRY> [--port 4242] [--test <N>]

  --test all     → roda todos os testes
  --test 2       → roda apenas A2
  --test 2,3,6   → roda A2, A3 e A6

Autoria: Script de validação para TCC - Arquitetura GSIPP
"""

import argparse
import hashlib
import os
import socket
import struct
import sys
import time

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

# ═══════════════════════════════════════════════════════════════
# CONFIGURAÇÕES
# ═══════════════════════════════════════════════════════════════

DEFAULT_PORT = 4242
SENSOR_ID = "ESP-42"  # ID legítimo do sensor provisionado

# Chave privada LEGÍTIMA do ESP-42 (extraída do firmware — apenas para testes)
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

# Proof legítima do ESP-42 (1064 bytes, do firmware)
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
# FUNÇÕES AUXILIARES
# ═══════════════════════════════════════════════════════════════

def load_esp42_private_key():
    """Carrega a chave privada legítima do ESP-42."""
    return serialization.load_pem_private_key(ESP42_PRIVATE_KEY_PEM, password=None)


def generate_attacker_key():
    """Gera um par de chaves RSA-2048 do atacante (diferente do ESP-42)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_data(private_key, sensor_id: str, timestamp: int, reading: int) -> bytes:
    """
    Assina os dados exatamente como o ESP32 faz:
    SHA-256(sensor_id|timestamp|reading) + PKCS#1 v1.5
    """
    data_str = f"{sensor_id}|{timestamp}|{reading}"
    # Calcular hash SHA-256 manualmente (para ser compatível com mbedtls_pk_sign)
    digest = hashlib.sha256(data_str.encode("utf-8")).digest()
    # Assinar o hash com PKCS#1 v1.5 (prehashed)
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )
    return signature


def build_cbor_packet(
    sensor_id: str,
    timestamp: int,
    reading: int,
    signature: bytes,
    proof: bytes,
) -> bytes:
    """
    Constrói o payload CBOR com 5 campos, idêntico ao formato do ESP32:
      "1" → sensor_id (string)
      "2" → timestamp (uint)
      "3" → reading   (uint)
      "4" → signature (bytes)
      "5" → proof     (bytes)
    """
    payload = {
        "1": sensor_id,
        "2": timestamp,
        "3": reading,
        "4": signature,
        "5": proof,
    }
    return cbor2.dumps(payload)


def send_udp(target_ip: str, target_port: int, data: bytes, label: str = ""):
    """Envia um pacote UDP e imprime o status."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, (target_ip, target_port))
    sock.close()
    if label:
        print(f"   📤 Enviado: {label} ({len(data)} bytes)")


def build_legitimate_packet(reading: int = 9999) -> bytes:
    """Constrói um pacote 100% legítimo do ESP-42 (para uso nos testes de replay)."""
    key = load_esp42_private_key()
    ts = int(time.time())
    sig = sign_data(key, SENSOR_ID, ts, reading)
    return build_cbor_packet(SENSOR_ID, ts, reading, sig, ESP42_PROOF_BYTES), ts, reading


def separator(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


# ═══════════════════════════════════════════════════════════════
# TESTES DE ATAQUE
# ═══════════════════════════════════════════════════════════════


def test_a2_cloned_id_wrong_key(target_ip: str, port: int):
    """
    A2 — Spoofing: ID clonado + chave própria do atacante

    O atacante sabe o ID do sensor legítimo (ESP-42) e capturou sua
    membership proof. Mas NÃO tem a chave privada do ESP-42.
    Usa sua própria chave RSA para assinar.

    Resultado esperado: REJEITADO na Verificação 02 (Assinatura Inválida)
    Motivo: o controlador verifica com a chave pública do ESP-42,
            que não corresponde à chave do atacante.
    """
    separator("A2 — Spoofing: ID Clonado + Chave do Atacante")

    print("   Cenário: Atacante se passa por ESP-42 usando sua própria chave RSA")
    print("   Resultado esperado: REJEITADO (Verificação 02 — Assinatura Inválida)")
    print()

    # Gerar chave RSA-2048 do atacante
    attacker_key = generate_attacker_key()
    print("   🔑 Chave RSA-2048 do atacante gerada")

    ts = int(time.time())
    reading = 7777  # Dado falso

    # Assinar com a chave do ATACANTE (não do ESP-42)
    sig = sign_data(attacker_key, SENSOR_ID, ts, reading)
    print(f"   ✍️  Dados assinados com chave do ATACANTE: {SENSOR_ID}|{ts}|{reading}")

    # Usar a proof legítima do ESP-42 (capturada do ar)
    pkt = build_cbor_packet(SENSOR_ID, ts, reading, sig, ESP42_PROOF_BYTES)
    print(f"   📦 Pacote CBOR montado: {len(pkt)} bytes")

    send_udp(target_ip, port, pkt, "Pacote A2 (ID clonado + chave errada)")
    print("   ⏳ Verifique no terminal do Raspberry Pi...")


def test_a3_wrong_proof(target_ip: str, port: int):
    """
    A3 — Spoofing: Assinatura correta + proof corrompida/trocada

    O atacante de alguma forma tem a chave privada legítima do ESP-42
    (cenário: acesso ao firmware). Assina corretamente, mas a membership
    proof está corrompida (simulando troca por proof de outro sensor).

    Resultado esperado: REJEITADO na Verificação 03 (Prova Inválida)
    Motivo: witness^hash("ESP-42") ≠ accumulator (proof corrompida)
    """
    separator("A3 — Spoofing: Assinatura OK + Proof Corrompida")

    print("   Cenário: Assinatura RSA válida, mas proof de pertencimento corrompida")
    print("   Resultado esperado: REJEITADO (Verificação 03 — Prova Inválida)")
    print()

    key = load_esp42_private_key()
    ts = int(time.time())
    reading = 8888

    # Assinar corretamente com a chave legítima
    sig = sign_data(key, SENSOR_ID, ts, reading)
    print(f"   ✍️  Dados assinados com chave LEGÍTIMA do ESP-42")

    # Corromper a proof: inverter 16 bytes no meio da witness
    corrupted_proof = bytearray(ESP42_PROOF_BYTES)
    for i in range(50, 66):
        corrupted_proof[i] ^= 0xFF  # Flip de bits
    corrupted_proof = bytes(corrupted_proof)
    print(f"   💥 Proof corrompida: 16 bytes invertidos na posição 50-65")

    pkt = build_cbor_packet(SENSOR_ID, ts, reading, sig, corrupted_proof)
    print(f"   📦 Pacote CBOR montado: {len(pkt)} bytes")

    send_udp(target_ip, port, pkt, "Pacote A3 (proof corrompida)")
    print("   ⏳ Verifique no terminal do Raspberry Pi...")


def test_a4_replay_outside_window(target_ip: str, port: int):
    """
    A4 — Replay Attack: fora da janela de 5 segundos

    O atacante captura um pacote legítimo e o reenvia após 7 segundos.

    Resultado esperado: REJEITADO na Verificação 01 (Replay Attack)
    Motivo: |now - timestamp| > 5s
    """
    separator("A4 — Replay Attack: Fora da Janela (>5s)")

    print("   Cenário: Capturar pacote legítimo, esperar 7s, reenviar")
    print("   Resultado esperado: REJEITADO (Verificação 01 — Replay Attack)")
    print()

    # 1. Construir pacote legítimo com timestamp ATUAL
    pkt, ts, reading = build_legitimate_packet(reading=4444)
    print(f"   📦 Pacote legítimo capturado (ts={ts}, reading={reading})")

    # 2. Esperar 7 segundos (para o timestamp expirar)
    wait_secs = 7
    print(f"   ⏱️  Aguardando {wait_secs} segundos para o timestamp expirar...")
    for i in range(wait_secs, 0, -1):
        print(f"       {i}...", end="\r")
        time.sleep(1)
    print(f"       0 — Reenviando agora!                    ")

    # 3. Reenviar o pacote capturado (sem modificação)
    send_udp(target_ip, port, pkt, "Pacote A4 (replay fora da janela)")
    print("   ⏳ Verifique no terminal do Raspberry Pi...")


def test_a5_replay_inside_window(target_ip: str, port: int):
    """
    A5 — Replay Attack: dentro da janela de 5 segundos

    O atacante captura um pacote legítimo e o reenvia imediatamente
    (dentro da janela de Δt = 5s).

    Resultado esperado:
      - 1º envio: ACEITO (pacote legítimo)
      - 2º envio: REJEITADO na Verificação 01b (Replay Intra-Janela)
    Motivo: (id, timestamp, reading) já está no cache replay_seen
    """
    separator("A5 — Replay Attack: Dentro da Janela (<5s)")

    print("   Cenário: Enviar pacote legítimo, reenviar imediatamente (replay)")
    print("   Resultado esperado: 1º ACEITO, 2º REJEITADO (Verif. 01b — Intra-Janela)")
    print()

    # 1. Construir e enviar pacote legítimo
    pkt, ts, reading = build_legitimate_packet(reading=5555)
    print(f"   📦 Pacote legítimo construído (ts={ts}, reading={reading})")

    send_udp(target_ip, port, pkt, "1º envio (legítimo) — deve ser ACEITO")
    print("   ⏱️  Aguardando 1 segundo...")
    time.sleep(1)

    # 2. Reenviar o MESMO pacote (replay)
    send_udp(target_ip, port, pkt, "2º envio (replay) — deve ser REJEITADO")
    print("   ⏳ Verifique no terminal do Raspberry Pi: 1 aceito + 1 rejeitado")


def test_a6_data_tampering(target_ip: str, port: int):
    """
    A6 — Tampering: interceptação e alteração de dados

    O atacante captura um pacote legítimo no ar e altera o campo
    'reading' (ex: muda de 42 para 9999). A assinatura original
    não cobre o novo valor.

    Resultado esperado: REJEITADO na Verificação 02 (Assinatura Inválida)
    Motivo: SHA-256("ESP-42|ts|9999") ≠ SHA-256("ESP-42|ts|6666")
    """
    separator("A6 — Tampering: Alteração de Dados no Pacote")

    print("   Cenário: Capturar pacote, alterar reading, reenviar")
    print("   Resultado esperado: REJEITADO (Verificação 02 — Assinatura Inválida)")
    print()

    # 1. Construir pacote legítimo (assinado para reading=6666)
    key = load_esp42_private_key()
    ts = int(time.time())
    original_reading = 6666
    sig = sign_data(key, SENSOR_ID, ts, original_reading)
    print(f"   ✍️  Pacote original assinado: {SENSOR_ID}|{ts}|{original_reading}")

    # 2. O atacante altera o reading para 9999 (mas mantém a assinatura original)
    tampered_reading = 9999
    pkt = build_cbor_packet(SENSOR_ID, ts, tampered_reading, sig, ESP42_PROOF_BYTES)
    print(f"   💥 Dado alterado pelo atacante: reading {original_reading} → {tampered_reading}")
    print(f"   📦 Pacote CBOR montado com dado adulterado: {len(pkt)} bytes")

    send_udp(target_ip, port, pkt, "Pacote A6 (dado adulterado)")
    print("   ⏳ Verifique no terminal do Raspberry Pi...")


def test_a7_malformed_cbor(target_ip: str, port: int):
    """
    A7 — Fuzzing: pacotes CBOR malformados

    Envia dados completamente inválidos para testar se o controlador
    trata entradas maliciosas sem crash/panic.

    Resultado esperado: Pacote descartado (CBOR inválido / corrupted_cbor++)
    """
    separator("A7 — Fuzzing: CBOR Malformado")

    print("   Cenário: Enviar bytes aleatórios, CBOR truncado e payload gigante")
    print("   Resultado esperado: Todos descartados (erro de desserialização CBOR)")
    print()

    # Sub-teste 1: Bytes totalmente aleatórios
    garbage = os.urandom(256)
    send_udp(target_ip, port, garbage, "7a: 256 bytes aleatórios")
    time.sleep(0.3)

    # Sub-teste 2: CBOR válido mas com campos errados (string em vez de int)
    bad_payload = cbor2.dumps({"1": "ESP-42", "2": "not_a_number", "3": 42})
    send_udp(target_ip, port, bad_payload, "7b: CBOR com tipos errados (sem campo 4 e 5)")
    time.sleep(0.3)

    # Sub-teste 3: CBOR truncado (cortado pela metade)
    key = load_esp42_private_key()
    ts = int(time.time())
    sig = sign_data(key, SENSOR_ID, ts, 1111)
    valid_pkt = build_cbor_packet(SENSOR_ID, ts, 1111, sig, ESP42_PROOF_BYTES)
    truncated = valid_pkt[: len(valid_pkt) // 2]
    send_udp(target_ip, port, truncated, f"7c: CBOR truncado ({len(truncated)} de {len(valid_pkt)} bytes)")
    time.sleep(0.3)

    # Sub-teste 4: Pacote vazio
    send_udp(target_ip, port, b"", "7d: Pacote vazio (0 bytes)")

    print("   ⏳ Verifique que o controlador NÃO crashou e logou 4 erros de CBOR")


def test_a8_dos_flood(target_ip: str, port: int):
    """
    A8 — DoS: flood de pacotes inválidos

    Envia 100 pacotes inválidos em rajada para medir o impacto
    no processamento do controlador.

    Resultado esperado: Todos descartados, controlador continua operando
    """
    separator("A8 — DoS: Flood de Pacotes Inválidos")

    num_packets = 100
    print(f"   Cenário: Enviar {num_packets} pacotes inválidos em rajada")
    print("   Resultado esperado: Todos descartados, controlador estável")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    t_start = time.time()
    for i in range(num_packets):
        garbage = os.urandom(128)
        sock.sendto(garbage, (target_ip, port))

    elapsed = time.time() - t_start
    sock.close()

    print(f"   📤 {num_packets} pacotes enviados em {elapsed:.3f}s ({num_packets/elapsed:.0f} pkt/s)")
    print("   ⏳ Verifique que o controlador continua funcional (envie um pacote legítimo depois)")


# ═══════════════════════════════════════════════════════════════
# PACOTE LEGÍTIMO DE CONTROLE
# ═══════════════════════════════════════════════════════════════

def test_legitimate(target_ip: str, port: int):
    """
    Pacote de controle: envia um pacote 100% legítimo para confirmar
    que o controlador está operando e aceita pacotes válidos.
    """
    separator("CONTROLE — Pacote Legítimo (deve ser ACEITO)")

    print("   Cenário: Pacote totalmente válido do ESP-42")
    print("   Resultado esperado: ACEITO (todas as 3 verificações passam)")
    print()

    pkt, ts, reading = build_legitimate_packet(reading=1234)
    print(f"   📦 Pacote legítimo: id={SENSOR_ID}, ts={ts}, reading={reading}")

    send_udp(target_ip, port, pkt, "Pacote legítimo de controle")
    print("   ⏳ Verifique no terminal do Raspberry Pi: deve aparecer ACEITO ✓")


def test_a9_spoofing_valid_cbor_wrong_proof(target_ip: str, port: int):
    """
    A9 — Spoofing: Proof estruturalmente válida, mas de OUTRO sensor

    Atendendo à ressalva de que S1-S3 poderiam estar sendo rejeitados
    apenas na camada de desserialização (CBOR parser), este teste envia
    um pacote 100% válido sintaticamente:
    - ID = ESP-42
    - Timestamp válido
    - Assinatura RSA legítima de ESP-42
    - MAS a MembershipProof injetada pertence ao ESP-02 (valida em CBOR).

    Resultado esperado: REJEITADO na Verificação 03 (Prova Inválida)
    Motivo: witness(ESP-02)^hash("ESP-42") != accumulator.
    A rejeição ocorre puramente pela matemática do acumulador RSA.
    """
    separator("A9 — Spoofing com Proof de Outro Sensor")

    print("   Cenário: Pacote de ESP-42 com MembershipProof do ESP-02")
    print("   Resultado esperado: REJEITADO (Verificação 03 — Prova Inválida puramente criptográfica)")
    print()

    # Carregar a proof de outro sensor (ESP-02)
    proof_path = "/home/carlos_eduardo/estudos/accumulatorGSIPP/SnifferESP/proofs/ESP_02.proof"
    if not os.path.exists(proof_path):
        print(f"   ❌ Arquivo não encontrado: {proof_path}")
        return

    with open(proof_path, "rb") as f:
        esp02_proof_bytes = f.read()

    print(f"   📥 Proof do ESP-02 carregada: {len(esp02_proof_bytes)} bytes (CBOR válido)")

    # Construir pacote
    key = load_esp42_private_key()
    ts = int(time.time())
    reading = 1010

    # Assinatura válida para o ESP-42
    sig = sign_data(key, SENSOR_ID, ts, reading)
    print(f"   ✍️  Dados assinados com chave LEGÍTIMA do ESP-42")

    # Injetar a proof do ESP-02 (estruturalmente perfeita, criptograficamente incompatível com ESP-42)
    pkt = build_cbor_packet(SENSOR_ID, ts, reading, sig, esp02_proof_bytes)
    print(f"   📦 Pacote CBOR montado: {len(pkt)} bytes")

    send_udp(target_ip, port, pkt, "Pacote A9 (Spoofing com Proof de ESP-02)")
    print("   ⏳ Verifique no terminal do Raspberry Pi (deve rejeitar na Verificação 03)")

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

TESTS = {
    "0": ("Pacote Legítimo (controle)", test_legitimate),
    "2": ("A2 — ID Clonado + Chave Errada", test_a2_cloned_id_wrong_key),
    "3": ("A3 — Proof Corrompida", test_a3_wrong_proof),
    "4": ("A4 — Replay Fora da Janela", test_a4_replay_outside_window),
    "5": ("A5 — Replay Dentro da Janela", test_a5_replay_inside_window),
    "6": ("A6 — Tampering de Dados", test_a6_data_tampering),
    "7": ("A7 — CBOR Malformado", test_a7_malformed_cbor),
    "8": ("A8 — DoS Flood", test_a8_dos_flood),
    "9": ("A9 — Spoofing com Proof Válida de Outro Sensor", test_a9_spoofing_valid_cbor_wrong_proof),
}


def main():
    parser = argparse.ArgumentParser(
        description="Script de Testes de Ataque — TCC GSIPP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 attack_tests.py --target 10.5.18.72 --test all
  python3 attack_tests.py --target 10.5.18.72 --test 2
  python3 attack_tests.py --target 10.5.18.72 --test 2,3,6
  python3 attack_tests.py --target 10.5.18.72 --test 0    (pacote legítimo de controle)
        """,
    )
    parser.add_argument("--target", required=True, help="IP do Raspberry Pi (controlador)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Porta UDP (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--test",
        default="all",
        help="Testes a executar: 'all' ou números separados por vírgula (ex: 2,3,6)",
    )

    args = parser.parse_args()

    print()
    print("═" * 60)
    print("  🔒 Script de Testes de Ataque — TCC GSIPP")
    print("═" * 60)
    print(f"  Alvo:  {args.target}:{args.port}")
    print(f"  Testes: {args.test}")
    print("═" * 60)

    # Determinar quais testes rodar
    if args.test == "all":
        selected = sorted(TESTS.keys())
    else:
        selected = [t.strip() for t in args.test.split(",")]
        for t in selected:
            if t not in TESTS:
                print(f"\n❌ Teste '{t}' não existe. Opções: {', '.join(sorted(TESTS.keys()))}")
                sys.exit(1)

    # Menu
    print("\n   Testes selecionados:")
    for t in selected:
        name, _ = TESTS[t]
        print(f"     [{t}] {name}")

    input("\n   Pressione ENTER para iniciar (certifique-se que o controlador está rodando)...")

    # Executar testes
    for t in selected:
        name, func = TESTS[t]
        try:
            func(args.target, args.port)
        except Exception as e:
            print(f"\n   ❌ Erro no teste {t}: {e}")

        if t != selected[-1]:
            print()
            input("   Pressione ENTER para o próximo teste...")

    # Resumo
    separator("TODOS OS TESTES CONCLUÍDOS")
    print("   Verifique o terminal do Raspberry Pi para os resultados.")
    print("   Use Ctrl+C no controlador para ver o resumo da sessão.\n")


if __name__ == "__main__":
    main()
