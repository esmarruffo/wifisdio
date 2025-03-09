// Add to a new file: arm7/source/wifisdio/net/eapol.c
#include "eapol.h"
#include "crypto.h"
#include "../wifisdio.h"
#include "../wifi.h"
#include "../wmi.h"
#include "net_alloc.h"

#include <string.h>
#include <nds.h>


// Global state for the handshake
TWL_BSS static eapol_state_t current_state = EAPOL_STATE_INIT;
TWL_BSS static uint8_t anonce[32];  // ANonce received from AP
TWL_BSS static uint8_t snonce[32];  // Our SNonce
TWL_BSS static uint8_t ptk[64];     // Pairwise Transient Key (64 bytes for WPA2)
TWL_BSS static uint8_t gtk[32];     // Group Temporal Key
TWL_BSS static uint8_t ap_mac[6];   // MAC of the access point
TWL_BSS static uint8_t gtk_index;   // GTK key index

TWL_CODE void eapol_init(void) {
    current_state = EAPOL_STATE_INIT;
    memset(anonce, 0, sizeof(anonce));
    memset(snonce, 0, sizeof(snonce));
    memset(ptk, 0, sizeof(ptk));
    memset(gtk, 0, sizeof(gtk));
    memset(ap_mac, 0, sizeof(ap_mac));
    gtk_index = 0;
}

// Send EAPOL Message 2 (in response to Message 1)
TWL_CODE static void send_eapol_message2(net_address_t* target, eapol_key_frame_t* msg1) {
    // Allocate buffer for Message 2
    size_t eapol_len = sizeof(eapol_key_frame_t);
    size_t packet_len = eapol_len + 8; // LLC/SNAP header (8) + EAPOL frame
    uint8_t* packet = net_malloc(packet_len);
    
    if (!packet) {
        panic("EAPOL: Failed to allocate memory for Message 2");
        return;
    }
    
    // Set up LLC/SNAP header
    uint8_t* llc = packet;
    llc[0] = 0xAA; llc[1] = 0xAA; llc[2] = 0x03; // LLC header
    llc[3] = 0x00; llc[4] = 0x00; llc[5] = 0x00; // OUI
    llc[6] = 0x88; llc[7] = 0x8E;               // Protocol (EAPOL)
    
    // Set up EAPOL frame
    eapol_key_frame_t* eapol = (eapol_key_frame_t*)(packet + 8);
    eapol->version = 1;
    eapol->type = 3; // EAPOL-Key
    eapol->length = htons(eapol_len - 4); // Length of frame body
    
    eapol->descriptor_type = EAPOL_KEY_TYPE_RSN;
    eapol->key_info = htons(KEY_INFO_TYPE_HMAC_SHA1_AES | KEY_INFO_KEY_TYPE | KEY_INFO_MIC);
    eapol->key_length = htons(16); // AES key length
    eapol->replay_counter = msg1->replay_counter; // Match replay counter from Message 1
    
    // Copy our SNonce
    memcpy(eapol->key_nonce, snonce, 32);
    
    // Clear fields that should be zero
    memset(eapol->key_iv, 0, 16);
    memset(eapol->key_rsc, 0, 8);
    memset(eapol->key_id, 0, 8);
    memset(eapol->key_mic, 0, 16);
    eapol->key_data_length = htons(0);
    
    // Compute and set MIC using KCK (first 16 bytes of PTK)
    compute_mic(ptk, eapol, eapol_len, eapol->key_mic);
    
    // Send the packet
    print("EAPOL: Sending Message 2\n");
    net_send_packet(PROTO_ETHER_EAPOL, target, packet, packet_len);
    
    net_free(packet);
    current_state = EAPOL_STATE_SENT_MSG2;
}

// Send EAPOL Message 4 (in response to Message 3)
TWL_CODE static void send_eapol_message4(net_address_t* target, eapol_key_frame_t* msg3) {
    // Allocate buffer for Message 4
    size_t eapol_len = sizeof(eapol_key_frame_t);
    size_t packet_len = eapol_len + 8; // LLC/SNAP header (8) + EAPOL frame
    uint8_t* packet = net_malloc(packet_len);
    
    if (!packet) {
        panic("EAPOL: Failed to allocate memory for Message 4");
        return;
    }
    
    // Set up LLC/SNAP header
    uint8_t* llc = packet;
    llc[0] = 0xAA; llc[1] = 0xAA; llc[2] = 0x03; // LLC header
    llc[3] = 0x00; llc[4] = 0x00; llc[5] = 0x00; // OUI
    llc[6] = 0x88; llc[7] = 0x8E;               // Protocol (EAPOL)
    
    // Set up EAPOL frame
    eapol_key_frame_t* eapol = (eapol_key_frame_t*)(packet + 8);
    eapol->version = 1;
    eapol->type = 3; // EAPOL-Key
    eapol->length = htons(eapol_len - 4); // Length of frame body
    
    eapol->descriptor_type = EAPOL_KEY_TYPE_RSN;
    eapol->key_info = htons(KEY_INFO_TYPE_HMAC_SHA1_AES | KEY_INFO_KEY_TYPE | 
                            KEY_INFO_MIC | KEY_INFO_SECURE);
    eapol->key_length = htons(16); // AES key length
    eapol->replay_counter = msg3->replay_counter; // Match replay counter from Message 3
    
    // Clear nonce and other fields
    memset(eapol->key_nonce, 0, 32);
    memset(eapol->key_iv, 0, 16);
    memset(eapol->key_rsc, 0, 8);
    memset(eapol->key_id, 0, 8);
    memset(eapol->key_mic, 0, 16);
    eapol->key_data_length = htons(0);
    
    // Compute and set MIC using KCK (first 16 bytes of PTK)
    compute_mic(ptk, eapol, eapol_len, eapol->key_mic);
    
    // Send the packet
    print("EAPOL: Sending Message 4\n");
    net_send_packet(PROTO_ETHER_EAPOL, target, packet, packet_len);
    
    net_free(packet);
    current_state = EAPOL_STATE_COMPLETE;
    
    print("EAPOL: 4-way handshake complete!\n");
    
    // Actually install the keys in the WiFi chip
    // We use PTK[32:47] as the Temporal Key (TK) for AES-CCMP
    sdio_wmi_add_cipher_key_cmd(0, 0, CRYPT_AES, KEY_USAGE_PAIRWISE | KEY_USAGE_TX,
                               KEY_OP_INIT_TSC | KEY_OP_INIT_RSC, 16, ptk + 32);
    
    // Install GTK for receiving broadcast/multicast
    sdio_wmi_add_cipher_key_cmd(0, gtk_index, CRYPT_AES, KEY_USAGE_GROUP,
                               KEY_OP_INIT_TSC | KEY_OP_INIT_RSC, 16, gtk);
}

// Handle an incoming EAPOL packet
TWL_CODE void eapol_handle_packet(net_address_t* source, uint8_t* data, size_t len) {
    eapol_key_frame_t* eapol = (eapol_key_frame_t*)data;
    
    if (eapol->type != 3) { // Not an EAPOL-Key frame
        print("EAPOL: Not a Key frame, type=%d\n", eapol->type);
        return;
    }
    
    if (eapol->descriptor_type != EAPOL_KEY_TYPE_RSN) {
        print("EAPOL: Not an RSN/WPA2 Key, type=%d\n", eapol->descriptor_type);
        return;
    }
    
    // Convert key_info from big-endian
    uint16_t key_info = ntohs(eapol->key_info);
    print("EAPOL: Key frame received, info=0x%04x, state=%d\n", key_info, current_state);
    
    switch (current_state) {
        case EAPOL_STATE_INIT:
            // Expecting Message 1 (no MIC, has ACK)
            if (!(key_info & KEY_INFO_MIC) && (key_info & KEY_INFO_ACK)) {
                print("EAPOL: Received Message 1\n");
                
                // Save AP's MAC address
                memcpy(ap_mac, source->mac, 6);
                
                // Save ANonce
                memcpy(anonce, eapol->key_nonce, 32);
                
                // Generate our SNonce
                generate_nonce(snonce, 32);
                
                // Get PMK from firmware configuration
                extern WifiAp_t access_points[6];
                extern uint8_t ap_index;
                uint8_t* pmk = access_points[ap_index].psk;
                
                // Compute PTK
                extern uint8_t device_mac[6]; // Our MAC address
                compute_ptk(pmk, device_mac, ap_mac, anonce, snonce, ptk, 64);
                
                // Send Message 2
                send_eapol_message2(source, eapol);
            } else {
                print("EAPOL: Unexpected Message 1 format\n");
            }
            break;
            
        case EAPOL_STATE_SENT_MSG2:
            // Expecting Message 3 (has MIC, has Install, has Encrypted Data)
            if ((key_info & KEY_INFO_MIC) && (key_info & KEY_INFO_INSTALL) && 
                (key_info & KEY_INFO_ENCRYPTED_DATA)) {
                print("EAPOL: Received Message 3\n");
                
                // Verify MIC
                uint8_t orig_mic[16];
                memcpy(orig_mic, eapol->key_mic, 16);
                memset(eapol->key_mic, 0, 16);
                
                uint8_t calc_mic[16];
                compute_mic(ptk, eapol, len, calc_mic);
                
                if (memcmp(orig_mic, calc_mic, 16) != 0) {
                    print("EAPOL: Message 3 MIC verification failed\n");
                    current_state = EAPOL_STATE_INIT; // Reset state
                    return;
                }
                
                // Restore original MIC
                memcpy(eapol->key_mic, orig_mic, 16);
                
                // Extract GTK from encrypted key data
                uint16_t key_data_len = ntohs(eapol->key_data_length);
                uint8_t* key_data = eapol->key_data;
                
                // Decrypt key data using KEK (bytes 16-31 of PTK)
                uint8_t* kek = ptk + 16;
                uint8_t* decrypted = net_malloc(key_data_len);
                
                if (!decrypted) {
                    panic("EAPOL: Failed to allocate memory for decrypted data");
                    return;
                }
                
                if (!aes_unwrap(kek, key_data, key_data_len, decrypted)) {
                    print("EAPOL: Failed to decrypt key data\n");
                    net_free(decrypted);
                    return;
                }
                
                // Parse decrypted data to find GTK KDE
                // Typical format: [DD] [len] [00 0F AC 01] [key_id] [00] [GTK...]
                kde_t* kde = (kde_t*)decrypted;
                
                if (kde->type == 0xDD && // Vendor specific
                    kde->oui[0] == 0x00 && kde->oui[1] == 0x0F && kde->oui[2] == 0xAC && // WPA2 OUI
                    kde->data_type == KDE_TYPE_GTK) { // GTK KDE
                    
                    // Extract GTK key index (bits 0-1) and TX bit (bit 2)
                    gtk_index = kde->data[0] & 0x03;
                    uint8_t* gtk_data = kde->data + 2; // Skip key index and reserved byte
                    
                    // Copy GTK (16 bytes for AES-CCMP)
                    memcpy(gtk, gtk_data, 16);
                    
                    print("EAPOL: Extracted GTK with index %d\n", gtk_index);
                } else {
                    print("EAPOL: Could not find GTK KDE in decrypted data\n");
                }
                
                net_free(decrypted);
                
                // Send Message 4
                send_eapol_message4(source, eapol);
            } else {
                print("EAPOL: Unexpected Message 3 format\n");
            }
            break;
            
        default:
            print("EAPOL: Unexpected message in state %d\n", current_state);
            break;
    }
}