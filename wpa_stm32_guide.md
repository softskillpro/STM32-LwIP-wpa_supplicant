# WPA Supplicant Implementation Guide for STM32F4 with LwIP

## Table of Contents
1. [Introduction](#introduction)
2. [Solution 1: External Wi-Fi Module (ESP8266/ESP32)](#solution-1-external-wi-fi-module)
3. [Solution 2: Full WPA Supplicant Port](#solution-2-full-wpa-supplicant-port)
4. [Solution 3: Lightweight PPP Bridge](#solution-3-lightweight-ppp-bridge)
5. [Comparison Summary](#comparison-summary)

---

## Introduction

This guide provides three different approaches to implement WPA (Wi-Fi Protected Access) functionality on STM32F4 microcontrollers with LwIP networking stack. Each solution offers different trade-offs between complexity, control, and resource usage.

---

## Solution 1: External Wi-Fi Module

### Overview
This approach offloads all WPA handling to an external Wi-Fi module (ESP8266/ESP32), making it the simplest solution.

### Hardware Requirements
- STM32F4 microcontroller
- ESP8266 or ESP32 module with AT firmware
- UART connection between STM32 and Wi-Fi module
- 3.3V power supply

### Advantages
- ✅ Simple implementation
- ✅ Low STM32 resource usage
- ✅ Proven, stable WPA2 implementation
- ✅ Quick development time (1-2 weeks)

### Disadvantages
- ❌ Depends on external module
- ❌ Less control over Wi-Fi layer
- ❌ AT command parsing overhead

### Implementation

#### Header File: esp_wifi_interface.h

```c
#ifndef ESP_WIFI_INTERFACE_H
#define ESP_WIFI_INTERFACE_H

#include "stm32f4xx_hal.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

#define ESP_UART &huart2
#define ESP_BUFFER_SIZE 2048

typedef struct {
    char ssid[32];
    char password[64];
    uint8_t connected;
    ip_addr_t ip_addr;
} esp_wifi_t;

// Function prototypes
void esp_send_command(const char* cmd);
int esp_wait_response(const char* expected, uint32_t timeout);
int esp_init(void);
int esp_connect_wifi(const char* ssid, const char* password);
int esp_enable_passthrough(const char* remote_ip, uint16_t port);
err_t esp_netif_output(struct netif *netif, struct pbuf *p);
void esp_netif_input(struct netif *netif, uint8_t *data, uint16_t len);

#endif
```

#### Source File: esp_wifi_interface.c

```c
#include "esp_wifi_interface.h"
#include <string.h>

esp_wifi_t esp_wifi;
uint8_t esp_rx_buffer[ESP_BUFFER_SIZE];
uint16_t esp_rx_index = 0;

// Send AT command
void esp_send_command(const char* cmd) {
    HAL_UART_Transmit(ESP_UART, (uint8_t*)cmd, strlen(cmd), 1000);
    HAL_UART_Transmit(ESP_UART, (uint8_t*)"\r\n", 2, 100);
}

// Wait for response
int esp_wait_response(const char* expected, uint32_t timeout) {
    uint32_t start = HAL_GetTick();
    
    while((HAL_GetTick() - start) < timeout) {
        if(strstr((char*)esp_rx_buffer, expected)) {
            return 1;
        }
        HAL_Delay(10);
    }
    return 0;
}

// Initialize ESP module
int esp_init(void) {
    // Reset module
    esp_send_command("AT+RST");
    HAL_Delay(2000);
    
    // Test communication
    esp_send_command("AT");
    if(!esp_wait_response("OK", 1000)) return 0;
    
    // Set station mode
    esp_send_command("AT+CWMODE=1");
    if(!esp_wait_response("OK", 1000)) return 0;
    
    return 1;
}

// Connect to Wi-Fi with WPA2
int esp_connect_wifi(const char* ssid, const char* password) {
    char cmd[128];
    
    snprintf(cmd, sizeof(cmd), "AT+CWJAP=\"%s\",\"%s\"", ssid, password);
    esp_send_command(cmd);
    
    // Wait for connection (WPA handshake happens internally)
    if(esp_wait_response("WIFI CONNECTED", 15000)) {
        if(esp_wait_response("WIFI GOT IP", 5000)) {
            esp_wifi.connected = 1;
            return 1;
        }
    }
    
    return 0;
}

// Enable transparent transmission mode
int esp_enable_passthrough(const char* remote_ip, uint16_t port) {
    char cmd[64];
    
    // Single connection mode
    esp_send_command("AT+CIPMUX=0");
    if(!esp_wait_response("OK", 1000)) return 0;
    
    // Connect to remote server
    snprintf(cmd, sizeof(cmd), "AT+CIPSTART=\"TCP\",\"%s\",%d", remote_ip, port);
    esp_send_command(cmd);
    if(!esp_wait_response("CONNECT", 5000)) return 0;
    
    // Enter passthrough mode
    esp_send_command("AT+CIPMODE=1");
    if(!esp_wait_response("OK", 1000)) return 0;
    
    esp_send_command("AT+CIPSEND");
    if(!esp_wait_response(">", 1000)) return 0;
    
    return 1;
}

// LwIP netif for ESP8266
err_t esp_netif_output(struct netif *netif, struct pbuf *p) {
    // Send data through UART to ESP
    struct pbuf *q;
    for(q = p; q != NULL; q = q->next) {
        HAL_UART_Transmit(ESP_UART, q->payload, q->len, 1000);
    }
    return ERR_OK;
}

void esp_netif_input(struct netif *netif, uint8_t *data, uint16_t len) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if(p != NULL) {
        pbuf_take(p, data, len);
        if(netif->input(p, netif) != ERR_OK) {
            pbuf_free(p);
        }
    }
}

// UART RX callback
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    if(huart == ESP_UART) {
        // Process received data
        // In passthrough mode, feed to LwIP
        if(esp_wifi.connected) {
            // Feed to network stack
            extern struct netif esp_netif;
            esp_netif_input(&esp_netif, esp_rx_buffer, esp_rx_index);
        }
        esp_rx_index = 0;
    }
}
```

#### Main Application

```c
#include "esp_wifi_interface.h"

void wifi_app_main(void) {
    // Initialize ESP module
    if(!esp_init()) {
        printf("ESP init failed\n");
        return;
    }
    
    // Connect to Wi-Fi (WPA2 handled by ESP)
    if(esp_connect_wifi("YourSSID", "YourPassword")) {
        printf("Connected to Wi-Fi!\n");
        
        // Setup LwIP interface
        // Now you can use standard LwIP APIs
    } else {
        printf("Connection failed\n");
    }
}
```

### Resource Usage
- **RAM**: <16KB
- **Flash**: <32KB
- **Development Time**: 1-2 weeks

---

## Solution 2: Full WPA Supplicant Port

### Overview
Complete port of wpa_supplicant for maximum control over Wi-Fi security.

### Prerequisites
- mbedTLS or WolfSSL cryptographic library
- FreeRTOS for task management
- Wi-Fi driver (for CYW43xxx, RTL8xxx, or similar chips)
- 128KB+ RAM
- 512KB+ Flash

### Advantages
- ✅ Complete control over WPA/security
- ✅ Can support WPA Enterprise, WPA3
- ✅ No external dependencies
- ✅ Best for custom hardware

### Disadvantages
- ❌ Complex implementation
- ❌ High resource usage
- ❌ Long development time (2-3 months)
- ❌ Requires deep protocol knowledge

### Implementation

#### Header File: wpa_supplicant_port.h

```c
#ifndef WPA_SUPPLICANT_PORT_H
#define WPA_SUPPLICANT_PORT_H

#include "mbedtls/aes.h"
#include "mbedtls/sha1.h"
#include "mbedtls/md5.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

// WPA State Machine States
typedef enum {
    WPA_DISCONNECTED,
    WPA_SCANNING,
    WPA_ASSOCIATING,
    WPA_4WAY_HANDSHAKE,
    WPA_GROUP_HANDSHAKE,
    WPA_COMPLETED
} wpa_state_t;

// WPA Configuration
typedef struct {
    uint8_t ssid[32];
    size_t ssid_len;
    uint8_t psk[32];  // Pre-shared key (256 bits)
    uint8_t bssid[6];
    uint8_t own_addr[6];
} wpa_config_t;

// WPA Context
typedef struct {
    wpa_config_t config;
    wpa_state_t state;
    
    // Keys
    uint8_t pmk[32];      // Pairwise Master Key
    uint8_t ptk[64];      // Pairwise Transient Key
    uint8_t gtk[32];      // Group Temporal Key
    uint8_t snonce[32];   // Supplicant nonce
    uint8_t anonce[32];   // Authenticator nonce
    
    // Replay counter
    uint64_t replay_counter;
    
    // Synchronization
    SemaphoreHandle_t mutex;
    TaskHandle_t task_handle;
} wpa_supplicant_t;

// Function prototypes
int wpa_supplicant_init(wpa_supplicant_t *wpa);
int wpa_supplicant_set_config(wpa_supplicant_t *wpa, const char *ssid, 
                               const char *passphrase);
int wpa_supplicant_connect(wpa_supplicant_t *wpa);
void wpa_supplicant_rx_eapol(wpa_supplicant_t *wpa, const uint8_t *buf, 
                              size_t len);
void wpa_supplicant_task(void *param);

#endif
```

#### Source File: wpa_supplicant_port.c

```c
#include "wpa_supplicant_port.h"
#include "wifi_driver.h"  // Your Wi-Fi chip driver
#include <string.h>

// EAPOL-Key frame structure
#pragma pack(push, 1)
typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint8_t descriptor_type;
    uint16_t key_info;
    uint16_t key_length;
    uint64_t replay_counter;
    uint8_t key_nonce[32];
    uint8_t key_iv[16];
    uint8_t key_rsc[8];
    uint8_t key_id[8];
    uint8_t key_mic[16];
    uint16_t key_data_length;
    // key_data follows
} eapol_key_frame_t;
#pragma pack(pop)

// PBKDF2 for PSK generation
static void pbkdf2_sha1(const char *passphrase, const uint8_t *ssid, 
                        size_t ssid_len, uint8_t *output) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    
    // PBKDF2 with 4096 iterations
    mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const uint8_t*)passphrase, 
                              strlen(passphrase), ssid, ssid_len, 
                              4096, 32, output);
    
    mbedtls_md_free(&ctx);
}

// PRF for PTK derivation
static void wpa_prf(const uint8_t *key, size_t key_len,
                    const char *label,
                    const uint8_t *data, size_t data_len,
                    uint8_t *output, size_t output_len) {
    uint8_t counter = 0;
    size_t pos = 0;
    uint8_t hash[20];
    mbedtls_md_context_t ctx;
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    
    while(pos < output_len) {
        mbedtls_md_hmac_starts(&ctx, key, key_len);
        mbedtls_md_hmac_update(&ctx, (uint8_t*)label, strlen(label));
        mbedtls_md_hmac_update(&ctx, &counter, 1);
        mbedtls_md_hmac_update(&ctx, data, data_len);
        mbedtls_md_hmac_finish(&ctx, hash);
        
        size_t copy_len = (output_len - pos > 20) ? 20 : (output_len - pos);
        memcpy(output + pos, hash, copy_len);
        pos += copy_len;
        counter++;
    }
    
    mbedtls_md_free(&ctx);
}

// Derive PTK
static void wpa_derive_ptk(wpa_supplicant_t *wpa) {
    uint8_t data[76];
    size_t pos = 0;
    
    // data = Min(AA, SPA) || Max(AA, SPA) || 
    //        Min(ANonce, SNonce) || Max(ANonce, SNonce)
    if(memcmp(wpa->config.own_addr, wpa->config.bssid, 6) < 0) {
        memcpy(data + pos, wpa->config.own_addr, 6); pos += 6;
        memcpy(data + pos, wpa->config.bssid, 6); pos += 6;
    } else {
        memcpy(data + pos, wpa->config.bssid, 6); pos += 6;
        memcpy(data + pos, wpa->config.own_addr, 6); pos += 6;
    }
    
    if(memcmp(wpa->snonce, wpa->anonce, 32) < 0) {
        memcpy(data + pos, wpa->snonce, 32); pos += 32;
        memcpy(data + pos, wpa->anonce, 32); pos += 32;
    } else {
        memcpy(data + pos, wpa->anonce, 32); pos += 32;
        memcpy(data + pos, wpa->snonce, 32); pos += 32;
    }
    
    // PTK = PRF-X(PMK, "Pairwise key expansion", data)
    wpa_prf(wpa->pmk, 32, "Pairwise key expansion", data, 76, 
            wpa->ptk, 64);
}

// Calculate MIC
static void wpa_calculate_mic(const uint8_t *kck, const uint8_t *data, 
                              size_t len, uint8_t *mic) {
    mbedtls_md_context_t ctx;
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    mbedtls_md_hmac_starts(&ctx, kck, 16);
    mbedtls_md_hmac_update(&ctx, data, len);
    mbedtls_md_hmac_finish(&ctx, mic);
    mbedtls_md_free(&ctx);
}

// Initialize WPA supplicant
int wpa_supplicant_init(wpa_supplicant_t *wpa) {
    memset(wpa, 0, sizeof(wpa_supplicant_t));
    
    wpa->state = WPA_DISCONNECTED;
    wpa->mutex = xSemaphoreCreateMutex();
    
    if(wpa->mutex == NULL) return -1;
    
    // Create WPA task
    xTaskCreate(wpa_supplicant_task, "WPA", 4096, wpa, 3, 
                &wpa->task_handle);
    
    return 0;
}

// Set configuration
int wpa_supplicant_set_config(wpa_supplicant_t *wpa, const char *ssid, 
                               const char *passphrase) {
    xSemaphoreTake(wpa->mutex, portMAX_DELAY);
    
    // Store SSID
    wpa->config.ssid_len = strlen(ssid);
    memcpy(wpa->config.ssid, ssid, wpa->config.ssid_len);
    
    // Derive PSK from passphrase using PBKDF2
    pbkdf2_sha1(passphrase, wpa->config.ssid, wpa->config.ssid_len, 
                wpa->config.psk);
    
    // PMK = PSK for WPA2-PSK
    memcpy(wpa->pmk, wpa->config.psk, 32);
    
    xSemaphoreGive(wpa->mutex);
    return 0;
}

// Connect to Wi-Fi
int wpa_supplicant_connect(wpa_supplicant_t *wpa) {
    // Scan for network
    wpa->state = WPA_SCANNING;
    wifi_scan_result_t scan_result;
    
    if(wifi_scan(wpa->config.ssid, wpa->config.ssid_len, 
                 &scan_result) != 0) {
        return -1;
    }
    
    // Store BSSID
    memcpy(wpa->config.bssid, scan_result.bssid, 6);
    
    // Get own MAC address
    wifi_get_mac_address(wpa->config.own_addr);
    
    // Associate with AP (open authentication)
    wpa->state = WPA_ASSOCIATING;
    if(wifi_associate(scan_result.bssid, wpa->config.ssid, 
                      wpa->config.ssid_len) != 0) {
        return -1;
    }
    
    // Generate SNonce (random)
    wifi_get_random(wpa->snonce, 32);
    
    wpa->state = WPA_4WAY_HANDSHAKE;
    
    // Wait for EAPOL frames (Message 1 will arrive via rx_eapol)
    return 0;
}

// Process received EAPOL frame
void wpa_supplicant_rx_eapol(wpa_supplicant_t *wpa, const uint8_t *buf, 
                              size_t len) {
    if(len < sizeof(eapol_key_frame_t)) return;
    
    // Skip Ethernet header
    eapol_key_frame_t *eapol = (eapol_key_frame_t *)(buf + 14);
    
    uint16_t key_info = __builtin_bswap16(eapol->key_info);
    
    xSemaphoreTake(wpa->mutex, portMAX_DELAY);
    
    // Message 1: Pairwise = 1, Install = 0, Ack = 1, MIC = 0
    if((key_info & 0x0208) == 0x0008 && !(key_info & 0x0080)) {
        // Store ANonce
        memcpy(wpa->anonce, eapol->key_nonce, 32);
        wpa->replay_counter = __builtin_bswap64(eapol->replay_counter);
        
        // Derive PTK
        wpa_derive_ptk(wpa);
        
        // Send Message 2
        uint8_t msg2[256];
        eapol_key_frame_t *msg2_eapol = (eapol_key_frame_t *)(msg2 + 14);
        
        // Build Message 2 frame
        memset(msg2, 0, sizeof(msg2));
        // Fill Ethernet header (dst=bssid, src=own_addr, type=0x888E)
        memcpy(msg2, wpa->config.bssid, 6);
        memcpy(msg2 + 6, wpa->config.own_addr, 6);
        msg2[12] = 0x88;
        msg2[13] = 0x8E;
        
        // Fill EAPOL header
        msg2_eapol->version = 1;
        msg2_eapol->type = 3; // EAPOL-Key
        msg2_eapol->descriptor_type = 2; // RSN
        msg2_eapol->key_info = __builtin_bswap16(0x010A); // Pairwise, MIC
        memcpy(msg2_eapol->key_nonce, wpa->snonce, 32);
        msg2_eapol->replay_counter = eapol->replay_counter;
        
        // Calculate and set MIC (using KCK from PTK)
        wpa_calculate_mic(wpa->ptk, (uint8_t*)msg2_eapol, 
                         sizeof(eapol_key_frame_t), msg2_eapol->key_mic);
        
        // Send via Wi-Fi driver
        wifi_send_eapol(msg2, sizeof(eapol_key_frame_t) + 14);
    }
    // Message 3: Pairwise = 1, Install = 1, Ack = 1, MIC = 1
    else if((key_info & 0x03C8) == 0x03C8) {
        // Verify MIC
        uint8_t calculated_mic[16];
        uint8_t received_mic[16];
        memcpy(received_mic, eapol->key_mic, 16);
        memset((uint8_t*)eapol->key_mic, 0, 16);
        
        wpa_calculate_mic(wpa->ptk, (uint8_t*)eapol, len - 14, 
                         calculated_mic);
        
        if(memcmp(calculated_mic, received_mic, 16) != 0) {
            // MIC verification failed
            xSemaphoreGive(wpa->mutex);
            return;
        }
        
        // Extract and decrypt GTK if present
        // (GTK extraction code would go here)
        
        // Install keys
        wifi_install_ptk(wpa->ptk + 32, 16); // TK (Temporal Key)
        wifi_install_gtk(wpa->gtk, 16);
        
        // Send Message 4
        uint8_t msg4[128];
        eapol_key_frame_t *msg4_eapol = (eapol_key_frame_t *)(msg4 + 14);
        
        memset(msg4, 0, sizeof(msg4));
        
        // Fill Ethernet header
        memcpy(msg4, wpa->config.bssid, 6);
        memcpy(msg4 + 6, wpa->config.own_addr, 6);
        msg4[12] = 0x88;
        msg4[13] = 0x8E;
        
        // Fill EAPOL header
        msg4_eapol->version = 1;
        msg4_eapol->type = 3;
        msg4_eapol->descriptor_type = 2;
        msg4_eapol->key_info = __builtin_bswap16(0x030A); 
        // Pairwise, MIC, Secure
        msg4_eapol->replay_counter = eapol->replay_counter;
        
        wpa_calculate_mic(wpa->ptk, (uint8_t*)msg4_eapol, 
                         sizeof(eapol_key_frame_t), msg4_eapol->key_mic);
        
        wifi_send_eapol(msg4, sizeof(eapol_key_frame_t) + 14);
        
        // Connection complete!
        wpa->state = WPA_COMPLETED;
    }
    
    xSemaphoreGive(wpa->mutex);
}

// WPA task
void wpa_supplicant_task(void *param) {
    wpa_supplicant_t *wpa = (wpa_supplicant_t *)param;
    
    while(1) {
        // Handle state machine, timeouts, rekeys, etc.
        if(wpa->state == WPA_4WAY_HANDSHAKE) {
            // Timeout handling
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
```

#### Integration with LwIP

```c
#include "lwip/netif.h"
#include "wpa_supplicant_port.h"

struct netif wifi_netif;
wpa_supplicant_t wpa_ctx;

// Network interface init
err_t wifi_netif_init(struct netif *netif) {
    netif->name[0] = 'w';
    netif->name[1] = 'l';
    netif->output = etharp_output;
    netif->linkoutput = wifi_low_level_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | 
                   NETIF_FLAG_LINK_UP;
    
    // Set MAC address
    wifi_get_mac_address(netif->hwaddr);
    netif->hwaddr_len = 6;
    
    return ERR_OK;
}

// Main application
void app_main(void) {
    // Initialize Wi-Fi driver
    wifi_driver_init();
    
    // Initialize WPA supplicant
    wpa_supplicant_init(&wpa_ctx);
    wpa_supplicant_set_config(&wpa_ctx, "MyNetwork", "MyPassword123");
    
    // Connect
    wpa_supplicant_connect(&wpa_ctx);
    
    // Wait for connection
    while(wpa_ctx.state != WPA_COMPLETED) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Initialize LwIP
    lwip_init();
    netif_add(&wifi_netif, NULL, NULL, NULL, NULL, wifi_netif_init, 
              ethernet_input);
    netif_set_default(&wifi_netif);
    netif_set_up(&wifi_netif);
    
    // Start DHCP
    dhcp_start(&wifi_netif);
    
    printf("Connected to Wi-Fi with WPA2!\n");
}
```

### Resource Usage
- **RAM**: 128KB+
- **Flash**: 512KB+
- **Development Time**: 2-3 months

---

## Solution 3: Lightweight PPP Bridge

### Overview
Use PPP (Point-to-Point Protocol) over serial to let the module handle Wi-Fi while maintaining IP-level integration with LwIP.

### Advantages
- ✅ IP-level integration with LwIP
- ✅ Module handles WPA complexity
- ✅ Lower resource usage than full port
- ✅ Standard PPP protocol

### Disadvantages
- ❌ Requires PPP support in module firmware
- ❌ Some protocol overhead
- ❌ Module dependency remains

### Implementation

#### Header File: ppp_wifi_bridge.h

```c
#ifndef PPP_WIFI_BRIDGE_H
#define PPP_WIFI_BRIDGE_H

#include "lwip/netif.h"
#include "netif/ppp/ppp.h"
#include "netif/ppp/pppos.h"
#include "stm32f4xx_hal.h"

typedef struct {
    ppp_pcb *ppp;
    struct netif ppp_netif;
    UART_HandleTypeDef *huart;
    uint8_t connected;
} ppp_wifi_bridge_t;

int ppp_wifi_init(ppp_wifi_bridge_t *bridge, UART_HandleTypeDef *huart);
int ppp_wifi_connect(ppp_wifi_bridge_t *bridge, const char *ssid, 
                     const char *password);
void ppp_wifi_task(void *param);

#endif
```

#### Source File: ppp_wifi_bridge.c

```c
#include "ppp_wifi_bridge.h"
#include "esp_at_commands.h"
#include <string.h>

// PPP output callback
static u32_t ppp_output_callback(ppp_pcb *pcb, u8_t *data, u32_t len, 
                                 void *ctx) {
    ppp_wifi_bridge_t *bridge = (ppp_wifi_bridge_t *)ctx;
    
    // Send data to Wi-Fi module via UART
    HAL_UART_Transmit(bridge->huart, data, len, 1000);
    
    return len;
}

// PPP status callback
static void ppp_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx) {
    ppp_wifi_bridge_t *bridge = (ppp_wifi_bridge_t *)ctx;
    struct netif *pppif = ppp_netif(pcb);
    
    switch(err_code) {
        case PPPERR_NONE:
            printf("PPP: Connected\n");
            printf("IP: %s\n", ip4addr_ntoa(netif_ip4_addr(pppif)));
            printf("Netmask: %s\n", 
                   ip4addr_ntoa(netif_ip4_netmask(pppif)));
            printf("Gateway: %s\n", 
                   ip4addr_ntoa(netif_ip4_gw(pppif)));
            bridge->connected = 1;
            break;
            
        case PPPERR_PARAM:
            printf("PPP: Invalid parameter\n");
            break;
            
        case PPPERR_OPEN:
            printf("PPP: Unable to open PPP session\n");
            break;
            
        case PPPERR_DEVICE:
            printf("PPP: Invalid I/O device\n");
            break;
            
        case PPPERR_ALLOC:
            printf("PPP: Unable to allocate resources\n");
            break;
            
        case PPPERR_USER:
            printf("PPP: User interrupt\n");
            ppp_close(pcb, 0);
            break;
            
        case PPPERR_CONNECT:
            printf("PPP: Connection lost\n");
            bridge->connected = 0;
            break;
            
        default:
            printf("PPP: Unknown error %d\n", err_code);
            break;
    }
}

// Initialize PPP bridge
int ppp_wifi_init(ppp_wifi_bridge_t *bridge, UART_HandleTypeDef *huart) {
    memset(bridge, 0, sizeof(ppp_wifi_bridge_t));
    bridge->huart = huart;
    
    // Create PPP control block
    bridge->ppp = pppapi_pppos_create(&bridge->ppp_netif,
                                      ppp_output_callback,
                                      ppp_link_status_cb,
                                      bridge);
    
    if(bridge->ppp == NULL) {
        printf("Failed to create PPP instance\n");
        return -1;
    }
    
    // Set PPP to use default network interface
    ppp_set_default(bridge->ppp);
    
    return 0;
}

// Connect via Wi-Fi module with WPA
int ppp_wifi_connect(ppp_wifi_bridge_t *bridge, const char *ssid, 
                     const char *password) {
    char cmd[128];
    
    // Initialize ESP module
    esp_send_at_command("AT+RST");
    vTaskDelay(pdMS_TO_TICKS(2000));
    
    esp_send_at_command("AT");
    if(!esp_wait_ok(1000)) return -1;
    
    // Set station mode
    esp_send_at_command("AT+CWMODE=1");
    if(!esp_wait_ok(1000)) return -1;
    
    // Connect to Wi-Fi (WPA handled by module)
    snprintf(cmd, sizeof(cmd), "AT+CWJAP=\"%s\",\"%s\"", ssid, password);
    esp_send_at_command(cmd);
    
    if(!esp_wait_response("WIFI GOT IP", 15000)) {
        printf("Failed to connect to Wi-Fi\n");
        return -1;
    }
    
    // Enable PPP mode on ESP
    // (Custom firmware needed or use transparent mode)
    esp_send_at_command("AT+CIPMODE=2"); // Hypothetical PPP mode
    if(!esp_wait_ok(1000)) return -1;
    
    // Start PPP connection
    pppapi_connect(bridge->ppp, 0);
    
    return 0;
}

// UART RX handler - feed to PPP
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    extern ppp_wifi_bridge_t ppp_bridge;
    
    if(huart == ppp_bridge.huart) {
        uint8_t rx_byte;
        
        if(HAL_UART_Receive(huart, &rx_byte, 1, 0) == HAL_OK) {
            // Feed received data to PPP
            pppos_input(ppp_bridge.ppp, &rx_byte, 1);
        }
    }
}

// Task to handle PPP
void ppp_wifi_task(void *param) {
    ppp_wifi_bridge_t *bridge = (ppp_wifi_bridge_t *)param;
    
    while(1) {
        // PPP maintenance
        if(bridge->connected) {
            // Check link status periodically
            // Handle reconnection if needed
        }
        
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
```

#### Main Application

```c
#include "ppp_wifi_bridge.h"

ppp_wifi_bridge_t ppp_bridge;
extern UART_HandleTypeDef huart2;

void app_main(void) {
    // Initialize LwIP
    lwip_init();
    
    // Initialize PPP bridge
    if(ppp_wifi_init(&ppp_bridge, &huart2) != 0) {
        printf("PPP init failed\n");
        return;
    }
    
    // Connect to Wi-Fi with WPA2
    if(ppp_wifi_connect(&ppp_bridge, "YourSSID", "YourPassword") != 0) {
        printf("Connection failed\n");
        return;
    }
    
    // Create PPP task
    xTaskCreate(ppp_wifi_task, "PPP", 2048, &ppp_bridge, 2, NULL);
    
    // Wait for connection
    while(!ppp_bridge.connected) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    printf("PPP link established!\n");
    
    // Now you can use standard LwIP APIs
    // Example: TCP client, HTTP, MQTT, etc.
    
    // Example TCP connection
    struct netconn *conn = netconn_new(NETCONN_TCP);
    if(conn != NULL) {
        ip_addr_t server_ip;
        IP4_ADDR(&server_ip, 192, 168, 1, 100);
        
        if(netconn_connect(conn, &server_ip, 80) == ERR_OK) {
            printf("TCP connection established!\n");
            // Send/receive data
        }
        netconn_delete(conn);
    }
}
```

#### ESP AT Command Helper Functions

```c
// esp_at_commands.c
#include "esp_at_commands.h"

extern UART_HandleTypeDef huart2;
static uint8_t esp_response_buffer[512];
static volatile uint16_t esp_rx_index = 0;

void esp_send_at_command(const char *cmd) {
    HAL_UART_Transmit(&huart2, (uint8_t*)cmd, strlen(cmd), 1000);
    HAL_UART_Transmit(&huart2, (uint8_t*)"\r\n", 2, 100);
    
    // Clear response buffer
    memset(esp_response_buffer, 0, sizeof(esp_response_buffer));
    esp_rx_index = 0;
}

int esp_wait_ok(uint32_t timeout) {
    return esp_wait_response("OK", timeout);
}

int esp_wait_response(const char *expected, uint32_t timeout) {
    uint32_t start = HAL_GetTick();
    
    while((HAL_GetTick() - start) < timeout) {
        if(strstr((char*)esp_response_buffer, expected)) {
            return 1;
        }
        HAL_Delay(10);
    }
    return 0;
}

// UART RX interrupt handler
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    if(huart->Instance == USART2) {
        uint8_t data;
        if(HAL_UART_Receive(huart, &data, 1, 0) == HAL_OK) {
            if(esp_rx_index < sizeof(esp_response_buffer) - 1) {
                esp_response_buffer[esp_rx_index++] = data;
            }
        }
    }
}
```

### Resource Usage
- **RAM**: ~32KB
- **Flash**: ~64KB
- **Development Time**: 3-4 weeks

### Configuration Notes

1. **LwIP Configuration** - Enable PPP support in `lwipopts.h`:
```c
#define PPP_SUPPORT 1
#define PPPOS_SUPPORT 1
#define PAP_SUPPORT 1
#define CHAP_SUPPORT 1
```

2. **UART Configuration**:
   - Baud rate: 115200 (typical for ESP modules)
   - Data bits: 8
   - Stop bits: 1
   - Parity: None
   - Flow control: None (or hardware if available)

3. **Module Firmware**:
   - Standard AT firmware with PPP support, or
   - Custom firmware that bridges Wi-Fi to PPP
   - Alternative: Use SPI interface for better performance

---

## Comparison Summary

### Feature Comparison Table

| Feature | Solution 1 (AT) | Solution 2 (Full Port) | Solution 3 (PPP) |
|---------|----------------|----------------------|------------------|
| **Complexity** | Low | Very High | Medium |
| **RAM Usage** | <16KB | 128KB+ | ~32KB |
| **Flash Usage** | <32KB | 512KB+ | ~64KB |
| **Development Time** | 1-2 weeks | 2-3 months | 3-4 weeks |
| **Control Level** | Low | Complete | Medium |
| **WPA Support** | Module-dependent | WPA2/WPA3/Enterprise | Module-dependent |
| **Best For** | Prototyping, Simple apps | Custom hardware, Max control | Production systems |
| **Network Integration** | Custom/Limited | Full LwIP | Full LwIP via PPP |
| **Debugging Difficulty** | Easy | Very Hard | Medium |
| **Portability** | Module-specific | Hardware-specific | Module-specific |
| **Security Control** | Limited | Complete | Limited |
| **Power Consumption** | Module-dependent | Optimizable | Module-dependent |

### Performance Comparison

| Metric | Solution 1 | Solution 2 | Solution 3 |
|--------|-----------|-----------|-----------|
| **Throughput** | Medium (UART limited) | High (direct) | Medium (PPP overhead) |
| **Latency** | Medium | Low | Medium |
| **CPU Usage** | Low | Medium-High | Medium |
| **Memory Overhead** | Low | High | Medium |

### Use Case Recommendations

#### Choose Solution 1 (External Module) if:
- ✅ Rapid prototyping needed
- ✅ Simple application requirements
- ✅ Limited MCU resources
- ✅ Cost is secondary to time-to-market
- ✅ Standard Wi-Fi functionality sufficient

**Example Projects:**
- IoT sensors
- Home automation devices
- Simple data loggers
- Proof-of-concept systems

#### Choose Solution 2 (Full WPA Port) if:
- ✅ Custom Wi-Fi hardware integration
- ✅ Need WPA Enterprise or WPA3
- ✅ Maximum security control required
- ✅ Sufficient development time (months)
- ✅ Large MCU resources available
- ✅ Specific regulatory requirements

**Example Projects:**
- Industrial control systems
- Medical devices
- Enterprise security systems
- Custom wireless products

#### Choose Solution 3 (PPP Bridge) if:
- ✅ Need full IP stack integration
- ✅ Balanced resource usage required
- ✅ Standard networking protocols needed
- ✅ Module-based but professional solution
- ✅ Moderate development timeline

**Example Projects:**
- Commercial IoT products
- Professional monitoring systems
- Gateway devices
- Network appliances

---

## Additional Considerations

### Security Recommendations

1. **Key Storage**: Store Wi-Fi credentials in encrypted flash or secure elements
2. **Certificate Management**: For WPA Enterprise, implement proper certificate handling
3. **Update Mechanism**: Plan for firmware updates to patch security vulnerabilities
4. **Audit Logging**: Log authentication attempts and failures

### Debugging Tips

#### Solution 1 (AT Commands):
```c
// Enable verbose logging
void esp_debug_enable(void) {
    esp_send_command("AT+SYSLOG=1"); // Enable system logs
}

// Monitor UART traffic with logic analyzer or terminal
```

#### Solution 2 (Full Port):
```c
// Add debug prints in state machine
#define WPA_DEBUG 1

#if WPA_DEBUG
    #define WPA_LOG(fmt, ...) printf("[WPA] " fmt "\n", ##__VA_ARGS__)
#else
    #define WPA_LOG(fmt, ...)
#endif

// Use Wireshark to capture EAPOL frames
```

#### Solution 3 (PPP):
```c
// Enable PPP debug in lwipopts.h
#define PPP_DEBUG LWIP_DBG_ON
#define PPPOS_DEBUG LWIP_DBG_ON

// Monitor PPP negotiation
void ppp_debug_status(ppp_wifi_bridge_t *bridge) {
    printf("PPP State: %d\n", bridge->ppp->phase);
    printf("Link: %s\n", bridge->connected ? "UP" : "DOWN");
}
```

### Power Optimization

For battery-powered applications:

```c
// Solution 1 - Use ESP deep sleep
void esp_enter_sleep(uint32_t sleep_ms) {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "AT+GSLP=%lu", sleep_ms);
    esp_send_command(cmd);
}

// Solution 2 - Implement power save mode
void wpa_enable_power_save(wpa_supplicant_t *wpa) {
    wifi_set_power_save_mode(WIFI_PS_MIN_MODEM);
}

// Solution 3 - Use module sleep between transmissions
void ppp_power_save(ppp_wifi_bridge_t *bridge, uint8_t enable) {
    if(enable) {
        esp_send_at_command("AT+SLEEP=1");
    }
}
```

### Error Handling Best Practices

```c
// Robust connection handling
typedef enum {
    WIFI_STATE_DISCONNECTED,
    WIFI_STATE_CONNECTING,
    WIFI_STATE_CONNECTED,
    WIFI_STATE_ERROR
} wifi_state_t;

typedef struct {
    wifi_state_t state;
    uint8_t retry_count;
    uint32_t last_error;
} wifi_connection_manager_t;

void wifi_handle_error(wifi_connection_manager_t *mgr) {
    switch(mgr->last_error) {
        case WIFI_ERROR_AUTH_FAIL:
            // Wrong password - notify user
            printf("Authentication failed - check password\n");
            break;
            
        case WIFI_ERROR_AP_NOT_FOUND:
            // Retry scan
            if(mgr->retry_count++ < 5) {
                wifi_reconnect();
            }
            break;
            
        case WIFI_ERROR_TIMEOUT:
            // Reset module
            wifi_module_reset();
            break;
    }
}
```

---

## Testing and Validation

### Test Checklist

- [ ] Basic connectivity test
- [ ] WPA2-PSK authentication
- [ ] DHCP address acquisition
- [ ] TCP/UDP communication
- [ ] Reconnection after signal loss
- [ ] Multiple connect/disconnect cycles
- [ ] Long-duration stability test (24+ hours)
- [ ] Power cycle recovery
- [ ] Concurrent connections (if applicable)
- [ ] Throughput testing
- [ ] Security audit

### Performance Benchmarks

```c
// Throughput test
void test_throughput(void) {
    uint8_t buffer[1460];
    uint32_t start_time = HAL_GetTick();
    uint32_t bytes_sent = 0;
    
    for(int i = 0; i < 1000; i++) {
        if(tcp_send(buffer, sizeof(buffer)) == ERR_OK) {
            bytes_sent += sizeof(buffer);
        }
    }
    
    uint32_t elapsed = HAL_GetTick() - start_time;
    float throughput = (bytes_sent * 8.0f) / (elapsed / 1000.0f);
    
    printf("Throughput: %.2f kbps\n", throughput / 1000.0f);
}

// Latency test
void test_latency(void) {
    uint32_t start = HAL_GetTick();
    ping_send("8.8.8.8");
    // Wait for response
    uint32_t rtt = HAL_GetTick() - start;
    printf("RTT: %lu ms\n", rtt);
}
```

---

## Conclusion

Each solution offers distinct advantages:

- **Solution 1** is ideal for quick development and prototyping
- **Solution 2** provides maximum control for specialized applications
- **Solution 3** balances professional features with manageable complexity

Choose based on your project requirements, timeline, and available resources. For most commercial projects, **Solution 3 (PPP Bridge)** offers the best balance of features and development effort.

### Next Steps

1. Evaluate your hardware platform and constraints
2. Choose the appropriate solution
3. Set up development environment
4. Implement basic connectivity
5. Add error handling and robustness
6. Perform security audit
7. Conduct extensive testing
8. Plan for maintenance and updates

### Additional Resources

- **LwIP Documentation**: https://www.nongnu.org/lwip/
- **mbedTLS**: https://www.trustedfirmware.org/projects/mbed-tls/
- **WPA Supplicant**: https://w1.fi/wpa_supplicant/
- **STM32 HAL Reference**: https://www.st.com/
- **ESP AT Command Reference**: https://docs.espressif.com/

---

## Appendix: Common Issues and Solutions

### Issue 1: Connection Timeout
**Symptoms**: Module doesn't respond to AT commands  
**Solutions**:
- Check UART baud rate configuration
- Verify TX/RX pin connections
- Ensure proper power supply (3.3V, sufficient current)
- Add delays after module reset

### Issue 2: Authentication Failures
**Symptoms**: Can't connect to WPA2 network  
**Solutions**:
- Verify SSID and password are correct
- Check Wi-Fi security mode (WPA2-PSK vs WPA3)
- Ensure module firmware supports WPA2
- Check for special characters in password

### Issue 3: Intermittent Disconnections
**Symptoms**: Connection drops randomly  
**Solutions**:
- Check signal strength (RSSI)
- Implement reconnection logic
- Verify power supply stability
- Add watchdog timer
- Check for RF interference

### Issue 4: Low Throughput
**Symptoms**: Slow data transfer  
**Solutions**:
- Increase UART baud rate
- Enable hardware flow control
- Optimize buffer sizes
- Use DMA for UART transfers
- Check network congestion

### Issue 5: Memory Leaks
**Symptoms**: System crashes after extended operation  
**Solutions**:
- Properly free allocated buffers
- Check pbuf reference counting in LwIP
- Monitor heap usage
- Use static allocation where possible
- Implement heap monitoring

---

**Document Version**: 1.0  
**Last Updated**: January 2026  
**Author**: Technical Documentation  
**License**: MIT / Educational Use