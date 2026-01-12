# WPA Supplicant Porting Guide for STM32F4xx with LwIP

## Overview

This guide covers porting a minimal WPA2-PSK supplicant to STM32F4xx microcontrollers using LwIP as the TCP/IP stack. The implementation focuses on memory efficiency while maintaining compatibility with standard WPA2-PSK (CCMP) networks.

## Prerequisites

### Hardware
- STM32F4xx development board
- Wi-Fi module (see supported modules below)
- Sufficient RAM (minimum 64KB, recommended 128KB+)
- Sufficient Flash (minimum 128KB)

### Software
- STM32CubeF4 HAL
- LwIP 2.x
- FreeRTOS (optional but recommended)
- STM32CubeMX (for project setup)

### Supported Wi-Fi Modules
The implementation works with any module that supports:
1. Raw Ethernet frame transmission (for EAPOL)
2. Key installation API (PTK/GTK)
3. Association without encryption (WPA handshake happens after)

Common compatible modules:
- **ATWINC1500/ATWINC3400**: Native EAPOL passthrough support
- **ESP8266/ESP32**: Requires custom firmware or AT command extensions
- **Murata Type 1DX**: SPI-based, good STM32 support
- **WizFi360**: AT command based with EAPOL support

---

## Step-by-Step Porting Guide

### Step 1: Project Setup

```
project/
├── Core/
│   ├── Inc/
│   │   └── main.h
│   └── Src/
│       └── main.c
├── Drivers/
│   └── STM32F4xx_HAL_Driver/
├── Middlewares/
│   ├── LwIP/
│   └── FreeRTOS/
├── WPA/
│   ├── wpa_supplicant_minimal.h
│   ├── wpa_crypto_stm32.h
│   └── wpa_lwip_integration.c
└── WiFi_Driver/
    └── your_wifi_module.c
```

### Step 2: Configure STM32CubeMX

1. **Enable Peripherals**:
   - RNG (Random Number Generator) - Required
   - CRYP (if available on your MCU variant)
   - SPI/UART (for Wi-Fi module communication)

2. **Configure LwIP**:
   - Enable DHCP client
   - Configure memory pools (see Memory Optimization section)

3. **Configure FreeRTOS** (if using):
   - Create Wi-Fi task with 1KB+ stack
   - Create message queue for EAPOL frames

### Step 3: Implement Crypto Functions

The crypto layer requires these implementations:

```c
// Required crypto functions
void hmac_sha1(key, key_len, data, data_len, output);
void hmac_sha1_vector(key, key_len, num_elem, addr[], len[], output);
void aes_128_encrypt(key, plaintext, ciphertext);
int  aes_unwrap(kek, kek_len, cipher, cipher_len, plain);
int  crypto_get_random(buf, len);
```

**For STM32F4 with CRYP**: Use hardware AES acceleration
**For STM32F4 without CRYP**: Use provided software implementation

### Step 4: Implement Wi-Fi Hardware Abstraction

You must implement these functions for your specific Wi-Fi module:

```c
// Wi-Fi HAL functions to implement
int wifi_hw_init(void);
int wifi_hw_scan(void);
int wifi_hw_associate(const char *ssid, const uint8_t *bssid);
int wifi_hw_disconnect(void);
int wifi_hw_send_frame(const uint8_t *data, size_t len);
int wifi_hw_set_key(const uint8_t *key, size_t key_len, 
                    uint8_t key_index, bool pairwise);
int wifi_hw_get_mac(uint8_t mac[6]);
```

### Step 5: Connect Wi-Fi Module Events

Your Wi-Fi module driver must call these when events occur:

```c
// Call when association succeeds
wifi_on_associated(bssid);

// Call when disconnection occurs  
wifi_on_disconnected();

// Call when any Ethernet frame is received
wifi_on_rx_frame(data, len);
```

---

## Memory Optimization

### LwIP Configuration (lwipopts.h)

```c
// Reduce memory usage for constrained systems
#define MEM_SIZE                8000
#define MEMP_NUM_PBUF           16
#define PBUF_POOL_SIZE          8
#define PBUF_POOL_BUFSIZE       1536

// Disable unused protocols
#define LWIP_UDP                1
#define LWIP_TCP                1
#define LWIP_ICMP               1
#define LWIP_IGMP               0
#define LWIP_SNMP               0

// Single network interface
#define MEMP_NUM_NETIF          1
```

### WPA Supplicant Memory Usage

| Component | RAM (bytes) | Flash (bytes) |
|-----------|-------------|---------------|
| WPA Context | ~300 | - |
| Key Material | ~200 | - |
| TX Buffer | 256 | - |
| SHA-1 Context | 96 | - |
| AES S-Box | - | 256 |
| AES Round Keys | 176 | - |
| **Total** | **~1KB** | **~15KB** |

---

## Wi-Fi Module-Specific Notes

### ATWINC1500

```c
// Enable EAPOL passthrough in ATWINC
m2m_wifi_enable_monitoring_mode(NULL, 0);

// Register frame receive callback
m2m_wifi_set_receive_callback(wifi_on_rx_frame);

// Send raw frame
m2m_wifi_send_ethernet_pkt(data, len);
```

### ESP8266 (Custom Firmware)

Standard AT firmware doesn't support raw EAPOL. Options:
1. Use esp-idf with custom WPA callbacks
2. Modify NodeMCU firmware
3. Use ESP-NOW mode for EAPOL passthrough

### Generic SPI-Based Modules

```c
// Typical frame format
typedef struct {
    uint16_t length;
    uint8_t  type;  // 0x01 = data frame
    uint8_t  data[];
} spi_frame_t;

int wifi_hw_send_frame(const uint8_t *data, size_t len) {
    spi_frame_t *frame = alloca(sizeof(spi_frame_t) + len);
    frame->length = len;
    frame->type = 0x01;
    memcpy(frame->data, data, len);
    return spi_transmit(frame, sizeof(spi_frame_t) + len);
}
```

---

## Troubleshooting

### Common Issues

1. **Handshake fails at Message 2**
   - Verify ANonce is correctly copied
   - Check PTK derivation (address ordering)
   - Verify RSN IE matches AP's requirements

2. **MIC verification fails on Message 3**
   - Ensure PTK is derived correctly
   - Check AES-CMAC implementation
   - Verify byte ordering (big-endian for key_info)

3. **GTK decryption fails**
   - Implement proper AES decrypt (not just encrypt)
   - Check KEK extraction from PTK (bytes 16-31)

4. **No EAPOL frames received**
   - Verify Wi-Fi module allows raw frame reception
   - Check ethertype filtering (0x888E must pass)
   - Ensure association completed before expecting EAPOL

### Debugging Tips

```c
// Add debug output
#define WPA_DEBUG 1

#if WPA_DEBUG
#define WPA_LOG(fmt, ...) printf("[WPA] " fmt "\r\n", ##__VA_ARGS__)
#define WPA_HEXDUMP(label, data, len) do { \
    printf("[WPA] %s: ", label); \
    for(int i=0; i<len; i++) printf("%02x", data[i]); \
    printf("\r\n"); \
} while(0)
#else
#define WPA_LOG(...)
#define WPA_HEXDUMP(...)
#endif
```

---

## Security Considerations

1. **Clear keys from memory** after use
2. **Use hardware RNG** - don't use pseudo-random for nonces
3. **Protect key storage** - consider using STM32 OTP or secure element
4. **Validate all inputs** - check frame lengths before parsing
5. **Implement replay protection** - track replay counters

---

## Testing

### Test with Known Values

Use test vectors from IEEE 802.11i standard to verify crypto:

```c
// PMK derivation test
// SSID: "IEEE"  
// Passphrase: "password"
// Expected PMK: f4 2c 6f c5 2d f0 eb ef 9e bb 4b 90 b3 8a 5f 90...

// PTK derivation test vectors available in IEEE 802.11i-2004 Annex J
```

### Integration Test Steps

1. Connect to WPA2-PSK network with known credentials
2. Verify 4-way handshake completes
3. Verify DHCP address acquisition
4. Ping gateway to confirm encryption works
5. Test reconnection after disconnect

---

## References

- IEEE 802.11i-2004 Standard
- RFC 3394 - AES Key Wrap
- RFC 2104 - HMAC
- FIPS 197 - AES
- Original wpa_supplicant source: https://w1.fi/wpa_supplicant/
