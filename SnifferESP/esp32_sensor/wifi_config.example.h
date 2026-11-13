// ═══════════════════════════════════════════════════════════════════
// wifi_config.example.h — Template de credenciais de rede (versionado)
// ═══════════════════════════════════════════════════════════════════
// Copie para wifi_config.h (ignorado no Git) e preencha os valores reais:
//
//   cp wifi_config.example.h wifi_config.h
//
// NUNCA coloque a senha real neste arquivo de exemplo.

#pragma once

// Na versão rádio o Wi-Fi é usado apenas para sincronizar o NTP no boot.
#define WIFI_SSID     "SeuWiFi"
#define WIFI_PASSWORD "SuaSenha"

// IP do controlador — usado só pela versão Wi-Fi/UDP (branch main); ignorado
// aqui. Mantido para que o mesmo wifi_config.h sirva às duas branches.
#define SERVER_IP     "192.168.1.100"
