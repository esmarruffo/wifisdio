// Add to a new file: arm7/source/wifisdio/net/eapol.h
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <nds/ndstypes.h>
#include "base.h"

#define PROTO_ETHER_EAPOL            0x8e88

#define EAPOL_KEY_TYPE_RC4           0x01
#define EAPOL_KEY_TYPE_RSN           0x02

// Key Info Flags
#define KEY_INFO_TYPE_MASK           0x0007  // Bits 0-2
#define KEY_INFO_TYPE_HMAC_MD5_RC4   0x0001
#define KEY_INFO_TYPE_HMAC_SHA1_AES  0x0002
#define KEY_INFO_KEY_TYPE            0x0008  // Bit 3: 1=Pairwise, 0=Group
#define KEY_INFO_INSTALL             0x0040  // Bit 6
#define KEY_INFO_ACK                 0x0080  // Bit 7
#define KEY_INFO_MIC                 0x0100  // Bit 8
#define KEY_INFO_SECURE              0x0200  // Bit 9
#define KEY_INFO_ERROR               0x0400  // Bit 10
#define KEY_INFO_REQUEST             0x0800  // Bit 11
#define KEY_INFO_ENCRYPTED_DATA      0x1000  // Bit 12

typedef struct {
    uint8_t version;         // 1 for 802.1X-2001, 2 for 802.1X-2004
    uint8_t type;            // 3 = EAPOL-Key
    uint16_t length;         // Length of the frame body (big-endian)
    uint8_t descriptor_type; // 1 = RC4, 2 = RSN/WPA2
    uint16_t key_info;       // Key information (big-endian)
    uint16_t key_length;     // Length of pairwise key (big-endian)
    uint64_t replay_counter; // Replay counter (big-endian)
    uint8_t key_nonce[32];   // Key nonce
    uint8_t key_iv[16];      // Key IV
    uint8_t key_rsc[8];      // Key receive sequence counter (little-endian)
    uint8_t key_id[8];       // Key identifier (reserved in WPA2)
    uint8_t key_mic[16];     // Key MIC
    uint16_t key_data_length; // Length of key data (big-endian)
    uint8_t key_data[];      // Key data field
} __attribute__((packed)) eapol_key_frame_t;

// WPA2 KDE (Key Data Encapsulation) type
#define KDE_TYPE_GTK 0x01 // Group Temporal Key

typedef struct {
    uint8_t type;           // Element ID (0xDD for KDE)
    uint8_t length;         // Length of the element data
    uint8_t oui[3];         // Organization-specific OUI (00-0F-AC for WPA2)
    uint8_t data_type;      // Data type within the OUI
    uint8_t data[];         // Variable length data
} __attribute__((packed)) kde_t;

// Handshake state
typedef enum {
    EAPOL_STATE_INIT,
    EAPOL_STATE_RECEIVED_MSG1,
    EAPOL_STATE_SENT_MSG2,
    EAPOL_STATE_RECEIVED_MSG3,
    EAPOL_STATE_COMPLETE
} eapol_state_t;


TWL_CODE void eapol_handle_packet(net_address_t* source, uint8_t* data, size_t len);
TWL_CODE void eapol_init(void);