// ═══════════════════════════════════════════════════════════════════
// wifi_config.example.h — Template de credenciais de rede (versionado)
// ═══════════════════════════════════════════════════════════════════
// Copie para wifi_config.h (ignorado no Git) e preencha os valores reais:
//
//   cp wifi_config.example.h wifi_config.h
//
// NUNCA coloque a senha real neste arquivo de exemplo.

#pragma once

#define WIFI_SSID     "SeuWiFi"
#define WIFI_PASSWORD "SuaSenha"

// IP do controlador (Raspberry Pi / notebook rodando o udp_controller)
#define SERVER_IP     "192.168.1.100"
