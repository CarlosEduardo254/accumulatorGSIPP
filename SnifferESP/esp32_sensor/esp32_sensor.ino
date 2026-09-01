/*
 * ESP32 Sensor — Versão TCC (Arquitetura GSIPP)
 *
 * Funcionalidades:
 *   1. Sincronização NTP para UNIX timestamp real
 *   2. Assinatura digital RSA-2048 via mbedTLS (nativo do ESP32)
 *   3. Pacote CBOR com 5 campos (sensor_id, timestamp, sensor_data, signature,
 * membershipproof)
 *   4. Métricas de desempenho impressas no Serial Monitor
 *
 * Dependências: Nenhuma externa — usa apenas bibliotecas nativas do ESP32
 * (WiFi, mbedTLS, time.h)
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <time.h>

// mbedTLS — já incluído no ESP32 Arduino Core (via ESP-IDF)
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

// ============================================
// CONFIGURAÇÕES DE REDE
// ============================================

const char *WIFI_SSID = "Planeta Solar";
const char *WIFI_PASSWORD = "sede10204";
const char *SERVER_IP = "172.16.0.72"; // AJUSTE O IP
const uint16_t SERVER_PORT = 4242;
const char *SENSOR_ID = "ESP-42";
const uint32_t SEND_INTERVAL_MS = 3000;

// ============================================
// CONFIGURAÇÕES NTP
// ============================================

const char *NTP_SERVER = "pool.ntp.org";
const long GMT_OFFSET_SEC = -10800; // UTC-3 (Brasília)
const int DAYLIGHT_OFFSET_SEC = 0;

// ============================================
// CHAVE PRIVADA RSA-2048
// ============================================
// Gerada com: openssl genrsa 2048

const char *PRIVATE_KEY_PEM =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDg8/gBUdLHnfPi\n"
    "fpt4K/HH64ks9hTBgJrW0GP+6rMU3ndEzgr3tbKQEq9yhtQHO0iVTHmFKTHWkwdv\n"
    "iBiyjPOkp7psfXk49QRH74si9WZRZFgsaFdCvtmgNtjy8JbfdivND7gkcjovp5o3\n"
    "h5+obvigODWhquRduqrYbO7zs/AELw9pXlHu92G5k/3htsZf0X1NaQZx/KGApxV7\n"
    "GQb5FvpEwDDTcDVeXTmgxXrabmt9vjMeHIlRZUlEk11MKqGOfMPJqFYzNVDa19/Q\n"
    "GcjJsZOPxtY+DLwTBVQ7c3b4RnhNanBhBeo1+omeT8hzAdxGksSPAE12rEPnceUa\n"
    "muRvI1Q9AgMBAAECggEACw/cOn5iUdgh2dm1ffmVPGpH9trMBv7yvk0Fmc/DSiut\n"
    "bEgAkJFSDFUq5QQd0ZQ3+8WEtUhjD8TvqOuloUQeqBJqb7LU3vjngr0UF74/D5IS\n"
    "Zu6jmd/mNkN0NDAiDy+RtFYJTVuDonvIsOHdt0vrtH9HHeHYNIa9J4Ll1jybOS1a\n"
    "oalMPXiXZikxpvkEjX32Yi3I3L4YOF//yAR6iCQC/hsCRLwyh4T380IBSZV1/2tx\n"
    "Ns6B+ybS73xLrV9X+lbZDTFzBYRKJgfGs/3iivnGvqxYVtlJDJm4E8bpINABF7dc\n"
    "bEDIQdCftne1x5cL//6b8HL89YT1IRKbkhmzcp6iCQKBgQD7Hg4MzMHownTyDHBx\n"
    "otx3oLJcPeQ+DkRktEZyBA761h3ihsAiJpPTy2653CwITLQwoLasIeE5i6+f1Exz\n"
    "1DpcuH/ywSQKVK5RcvupnDO3Ccf2UqScL+XklyhsH6jmHipwB+KkLbPwiT3M6Vxn\n"
    "sNUWJ5sFTcvJQx9AuCUEhnw+GQKBgQDlU64C8VRxVt+DSl5gxZMbtOv2cHgwutU5\n"
    "SOq57L8lIn7EwgQyJAcAkzuBBVlbji6E+3GtUC3jGEDOMiRU9D25f2nx+Zla1YYt\n"
    "zwprSapyYc5CYk+55sFpDIh0D29oJVMD2qkZ8CMMakA2z/DAvX1YDZmOvMCS8llh\n"
    "+uUesl9DxQKBgBQQDqdPJJ7oClfcTo+Fp3+XQyjDeRzMHwK8tHQfhuLbgH+8rFUO\n"
    "J/lf43TN9majWjIYZP/TpR7n3hwy5fjLF+6YfwByFeMNaO/w89JVPHx/N46ig6xG\n"
    "12MwAHbDAMeB2Xoh5yWe0SWCkYFxk4RlSGEAwQ3nbUSjLDgLfkmiRQLhAoGAdz/H\n"
    "SdJyRamV+rCOWSYENDElTnX3meddfzdSj7HzR30jjG8TPXuMhJkLJTFB4SETQaV6\n"
    "3FPIOMHg2Rgr2l1TR4Vg8yoGu7wy1NlHorigwG/pkI2Mxa+fvV9+CVQJa4+VFnj6\n"
    "2/kKUKdjkt0YZTFj34ja4+V1AjSxlAiiYg8BCL0CgYEAmwmyXqo1ZzbnuMmRu5Bl\n"
    "Z3ift7jxvrMf7r93rLFkvS95D7xqYx+q1SvkK/+QtriEFGTUzFbC8mXJugZfmy/G\n"
    "2rmLH8AwARYqwY6NIPHKl8k4mY6f5c1LYKDMskUGPiPeEnawMSSm64cu3MVjxi+a\n"
    "dbhl6UebIeL+HnjKQ7xODw0=\n"
    "-----END PRIVATE KEY-----\n";

// ============================================
// MEMBERSHIP PROOF — Placeholder (Witness + PoE)
// ============================================
//  Cole aqui os bytes reais da Witness + PoE gerados pelo acumulador.

uint8_t MEMBERSHIP_PROOF[1064] = {
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
    0x37, 0x62, 0x65, 0x38, 0x38, 0x63, 0x37, 0x64};
const size_t PROOF_SIZE = sizeof(MEMBERSHIP_PROOF);

// ============================================
// VARIÁVEIS GLOBAIS
// ============================================

WiFiUDP udp;
uint64_t packetCounter = 0;

// Contextos criptográficos globais (mbedTLS)
// Inicializados uma vez no setup() — evita re-parse da chave PEM
// e re-seed do DRBG a cada pacote (~200ms de economia).
mbedtls_pk_context g_pk;
mbedtls_entropy_context g_entropy;
mbedtls_ctr_drbg_context g_ctr_drbg;
bool g_crypto_ready = false;

// ============================================
// CLASSE SimpleCBOR — Serialização manual
// ============================================

class SimpleCBOR {
private:
  uint8_t *buffer;
  size_t pos;
  size_t maxSize;
  bool overflow; // true se algum write ultrapassou o buffer

  // Verifica se há 'needed' bytes disponíveis; marca overflow e retorna false
  // se não.
  bool hasSpace(size_t needed) {
    if (pos + needed > maxSize) {
      overflow = true;
      return false;
    }
    return true;
  }

public:
  SimpleCBOR(uint8_t *buf, size_t size)
      : buffer(buf), pos(0), maxSize(size), overflow(false) {}

  // Retorna true se alguma escrita não coube no buffer
  bool hasOverflow() const { return overflow; }

  // Escreve cabeçalho de mapa CBOR (até 23 pares)
  void writeMap(uint8_t numPairs) {
    if (!hasSpace(1))
      return;
    buffer[pos++] = 0xA0 | numPairs;
  }

  // Escreve text string CBOR (Major type 3)
  void writeString(const char *str) {
    size_t len = strlen(str);
    size_t headerSz = (len < 24) ? 1 : (len <= 0xFF) ? 2 : 3;
    if (!hasSpace(headerSz + len))
      return;
    if (len < 24) {
      buffer[pos++] = 0x60 | len;
    } else if (len <= 0xFF) {
      buffer[pos++] = 0x78;
      buffer[pos++] = (uint8_t)len;
    } else {
      buffer[pos++] = 0x79;
      buffer[pos++] = (len >> 8) & 0xFF;
      buffer[pos++] = len & 0xFF;
    }
    memcpy(&buffer[pos], str, len);
    pos += len;
  }

  // Escreve unsigned integer CBOR (Major type 0)
  void writeUint64(uint64_t value) {
    size_t needed = (value < 24)            ? 1
                    : (value <= 0xFF)       ? 2
                    : (value <= 0xFFFF)     ? 3
                    : (value <= 0xFFFFFFFF) ? 5
                                            : 9;
    if (!hasSpace(needed))
      return;
    if (value < 24) {
      buffer[pos++] = (uint8_t)value;
    } else if (value <= 0xFF) {
      buffer[pos++] = 0x18;
      buffer[pos++] = (uint8_t)value;
    } else if (value <= 0xFFFF) {
      buffer[pos++] = 0x19;
      buffer[pos++] = (value >> 8) & 0xFF;
      buffer[pos++] = value & 0xFF;
    } else if (value <= 0xFFFFFFFF) {
      buffer[pos++] = 0x1A;
      buffer[pos++] = (value >> 24) & 0xFF;
      buffer[pos++] = (value >> 16) & 0xFF;
      buffer[pos++] = (value >> 8) & 0xFF;
      buffer[pos++] = value & 0xFF;
    } else {
      buffer[pos++] = 0x1B;
      for (int i = 7; i >= 0; i--) {
        buffer[pos++] = (value >> (i * 8)) & 0xFF;
      }
    }
  }

  // Escreve byte string CBOR (Major type 2)
  void writeBytes(const uint8_t *data, size_t len) {
    size_t headerSz = (len < 24) ? 1 : (len <= 0xFF) ? 2 : 3;
    if (!hasSpace(headerSz + len))
      return;
    if (len < 24) {
      buffer[pos++] = 0x40 | len;
    } else if (len <= 0xFF) {
      buffer[pos++] = 0x58;
      buffer[pos++] = (uint8_t)len;
    } else {
      buffer[pos++] = 0x59;
      buffer[pos++] = (len >> 8) & 0xFF;
      buffer[pos++] = len & 0xFF;
    }
    memcpy(&buffer[pos], data, len);
    pos += len;
  }

  size_t getSize() const { return pos; }
};

// ============================================
// INICIALIZAÇÃO CRIPTOGRÁFICA (executada uma vez no setup)
// ============================================

/**
 * Inicializa os contextos mbedTLS globais: chave privada, entropia e DRBG.
 * Chamada uma vez no setup(). Evita re-parse do PEM a cada pacote.
 */
void initCrypto() {
  char errorBuf[128];
  int ret;

  mbedtls_pk_init(&g_pk);
  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_ctr_drbg);

  // Seed do gerador de números aleatórios
  const char *pers = "esp32_sensor_sign";
  ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                              (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    mbedtls_strerror(ret, errorBuf, sizeof(errorBuf));
    Serial.printf(" Erro DRBG seed: %s\n", errorBuf);
    return;
  }

  // Parsear a chave privada PEM (uma única vez)
  ret = mbedtls_pk_parse_key(&g_pk, (const unsigned char *)PRIVATE_KEY_PEM,
                             strlen(PRIVATE_KEY_PEM) + 1, NULL, 0,
                             mbedtls_ctr_drbg_random, &g_ctr_drbg);
  if (ret != 0) {
    mbedtls_strerror(ret, errorBuf, sizeof(errorBuf));
    Serial.printf(" Erro ao parsear chave PEM: %s (code: -0x%04X)\n", errorBuf,
                  -ret);
    return;
  }

  g_crypto_ready = true;
  Serial.println(" Contexto criptográfico inicializado (RSA-2048)");
}

// ============================================
// ASSINATURA DIGITAL — RSA-2048 via mbedTLS
// ============================================

/**
 * Assina os dados do sensor usando RSA-2048 (PKCS#1 v1.5 + SHA-256).
 * Usa os contextos criptográficos globais (g_pk, g_ctr_drbg)
 * inicializados no setup() via initCrypto().
 *
 * Concatenação para o hash: sensor_id + timestamp_str + sensor_data_str
 * Delimitador '|' evita ambiguidade de concatenação.
 *
 * @param sensorId     ID do sensor (string C)
 * @param timestamp    UNIX timestamp em segundos
 * @param sensorData   Dado do sensor (packetCounter)
 * @param signatureOut Buffer de saída (mínimo 256 bytes para RSA-2048)
 * @param signatureLen Ponteiro para o tamanho da assinatura gerada
 * @return true se a assinatura foi gerada com sucesso
 */
bool signData(const char *sensorId, uint64_t timestamp, uint64_t sensorData,
              uint8_t *signatureOut, size_t *signatureLen) {
  if (!g_crypto_ready) {
    Serial.println(" Contexto criptográfico não inicializado!");
    return false;
  }

  int ret;
  char errorBuf[128];

  // --- 1. Montar o buffer de dados para hash ---
  // Concatenação delimitada: sensor_id | timestamp | sensor_data
  char dataBuffer[256];
  snprintf(dataBuffer, sizeof(dataBuffer), "%s|%llu|%llu", sensorId,
           (unsigned long long)timestamp, (unsigned long long)sensorData);

  // --- 2. Calcular SHA-256 do buffer concatenado ---
  uint8_t hash[32];
  ret = mbedtls_sha256((const unsigned char *)dataBuffer, strlen(dataBuffer),
                       hash, 0);
  if (ret != 0) {
    mbedtls_strerror(ret, errorBuf, sizeof(errorBuf));
    Serial.printf(" Erro SHA-256: %s\n", errorBuf);
    return false;
  }

  // --- 3. Assinar com a chave pré-carregada (global) ---
  size_t sigLen = 0;
  ret = mbedtls_pk_sign(&g_pk, MBEDTLS_MD_SHA256, hash, 32, signatureOut, 256,
                        &sigLen, mbedtls_ctr_drbg_random, &g_ctr_drbg);
  if (ret != 0) {
    mbedtls_strerror(ret, errorBuf, sizeof(errorBuf));
    Serial.printf(" Erro ao assinar: %s\n", errorBuf);
    return false;
  }

  *signatureLen = sigLen; // Deve ser 256 bytes para RSA-2048
  return true;
}

// ============================================
// CONEXÃO WI-FI
// ============================================

void connectWiFi() {
  Serial.println("\n Conectando ao WiFi...");
  Serial.printf("   SSID: %s\n", WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  uint8_t attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n WiFi conectado!");
    Serial.printf("   IP: %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("   Servidor: %s:%d\n", SERVER_IP, SERVER_PORT);
  } else {
    Serial.println("\n Falha WiFi!");
  }
}

// ============================================
// SINCRONIZAÇÃO NTP
// ============================================

/**
 * Sincroniza o relógio interno do ESP32 com um servidor NTP.
 * Bloqueia até obter um timestamp válido (> ano 2020).
 */
void syncNTP() {
  Serial.println(" Sincronizando relógio via NTP...");
  configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER);

  // Aguardar até obter um timestamp válido
  time_t now = 0;
  int attempts = 0;
  while (now < 1609459200 &&
         attempts < 30) { // 1609459200 = 2021-01-01 00:00:00 UTC
    delay(500);
    Serial.print(".");
    time(&now);
    attempts++;
  }

  if (now >= 1609459200) {
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);
    Serial.printf("\n NTP sincronizado! Hora: %04d-%02d-%02d %02d:%02d:%02d\n",
                  timeinfo.tm_year + 1900, timeinfo.tm_mon + 1,
                  timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min,
                  timeinfo.tm_sec);
    Serial.printf("   UNIX Timestamp: %llu\n", (unsigned long long)now);
  } else {
    Serial.println("\n Falha na sincronização NTP! Usando tempo interno.");
  }
}

// ============================================
// ENVIO DO PACOTE
// ============================================

void sendPacket() {
  // --- Obter UNIX timestamp via NTP ---
  time_t now;
  time(&now);
  uint64_t timestamp = (uint64_t)now;

  // Incrementar contador de dados do sensor
  packetCounter++;
  uint64_t sensorData = packetCounter;

  // ════════════════════════════════════════════
  // INÍCIO DA MEDIÇÃO DE DESEMPENHO
  // ════════════════════════════════════════════
  unsigned long t_start = millis();

  // --- 1. Gerar assinatura digital RSA-2048 ---
  uint8_t signature[256];
  size_t signatureLen = 0;

  bool signOk =
      signData(SENSOR_ID, timestamp, sensorData, signature, &signatureLen);

  if (!signOk) {
    Serial.println(" Falha na assinatura! Pacote descartado.");
    return;
  }

  // --- 2. Serializar pacote CBOR (mapa com 5 campos) ---
  uint8_t cborBuffer[2048];
  SimpleCBOR cbor(cborBuffer, sizeof(cborBuffer));

  cbor.writeMap(5);

  // Campo "1": sensor_id (String)
  cbor.writeString("1");
  cbor.writeString(SENSOR_ID);

  // Campo "2": timestamp (uint64 — UNIX epoch seconds)
  cbor.writeString("2");
  cbor.writeUint64(timestamp);

  // Campo "3": sensor_data (uint64 — packetCounter)
  cbor.writeString("3");
  cbor.writeUint64(sensorData);

  // Campo "4": signature (byte string — 256 bytes RSA-2048)
  cbor.writeString("4");
  cbor.writeBytes(signature, signatureLen);

  // Campo "5": membershipproof (byte string — Witness + PoE)
  cbor.writeString("5");
  cbor.writeBytes(MEMBERSHIP_PROOF, PROOF_SIZE);

  size_t cborSize = cbor.getSize();

  // Verificar se houve overflow no buffer CBOR
  if (cbor.hasOverflow()) {
    Serial.printf(" CBOR overflow! Payload (%d bytes) excede buffer (2048). "
                  "Pacote descartado.\n",
                  cborSize);
    return;
  }

  // ════════════════════════════════════════════
  // FIM DA MEDIÇÃO DE DESEMPENHO
  // ════════════════════════════════════════════
  unsigned long t_end = millis();

  // --- 3. Enviar via UDP ---
  IPAddress serverAddr;
  serverAddr.fromString(SERVER_IP);

  udp.beginPacket(serverAddr, SERVER_PORT);
  size_t sent = udp.write(cborBuffer, cborSize);
  bool success = udp.endPacket();

  // --- 4. Imprimir métricas ---
  if (success && sent == cborSize) {
    Serial.println("────────────────────────────────────────");
    Serial.printf(" Pacote #%llu enviado com sucesso via UDP\n",
                  (unsigned long long)sensorData);
    Serial.printf("   Sensor ID:    %s\n", SENSOR_ID);
    Serial.printf("   Timestamp:    %llu (UNIX)\n",
                  (unsigned long long)timestamp);
    Serial.printf("   Sensor Data:  %llu\n", (unsigned long long)sensorData);
    Serial.printf("   Assinatura:   %d bytes (RSA-2048)\n", signatureLen);
    Serial.printf("   Proof:        %d bytes\n", PROOF_SIZE);
    Serial.println("────────────────────────────────────────");
    Serial.printf("Tempo de processamento (ms): %lu\n", t_end - t_start);
    Serial.printf("Overhead de rede e tamanho do pacote (bytes): %d\n",
                  cborSize);
    Serial.printf("Total de pacotes enviados:   %llu\n",
                  (unsigned long long)packetCounter);
    Serial.println("────────────────────────────────────────\n");
  } else {
    Serial.printf(" Erro no envio UDP (%d/%d bytes)\n", sent, cborSize);
  }
}

// ============================================
// SETUP
// ============================================

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println("\n═══════════════════════════════════════");
  Serial.println("  ESP32 Sensor — Arquitetura TCC GSIPP");
  Serial.println("═══════════════════════════════════════");
  Serial.printf(" Sensor ID:        %s\n", SENSOR_ID);
  Serial.printf(" Proof:            %d bytes\n", PROOF_SIZE);
  Serial.printf(" Intervalo:        %lu ms\n", (unsigned long)SEND_INTERVAL_MS);
  Serial.printf(" Destino UDP:      %s:%d\n", SERVER_IP, SERVER_PORT);
  Serial.println("═══════════════════════════════════════\n");

  // 1. Inicializar contexto criptográfico (uma vez)
  initCrypto();
  if (!g_crypto_ready) {
    Serial.println(" ERRO FATAL: Contexto criptográfico falhou!");
    while (1)
      delay(1000);
  }

  // 2. Conectar Wi-Fi
  connectWiFi();
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(" ERRO: WiFi não conectado!");
    while (1)
      delay(1000);
  }

  // 3. Sincronizar relógio via NTP
  syncNTP();

  Serial.println("\n Pronto! Enviando pacotes via UDP...\n");
  delay(1000);
}

// ============================================
// LOOP
// ============================================

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(" WiFi desconectado!");
    connectWiFi();
  }

  if (WiFi.status() == WL_CONNECTED) {
    sendPacket();
  }

  delay(SEND_INTERVAL_MS);
}
