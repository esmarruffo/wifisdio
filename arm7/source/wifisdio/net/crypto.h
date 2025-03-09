// Add to a new file: arm7/source/wifisdio/net/crypto.h
#pragma once

#include <stdint.h>
#include <stddef.h>


// HMAC-SHA1 function
void hmac_sha1(const uint8_t* key, size_t key_len, 
               const uint8_t* data, size_t data_len, 
               uint8_t* output);

// PRF (Pseudo-Random Function) for WPA2
void prf(const uint8_t* key, size_t key_len,
         const uint8_t* prefix, size_t prefix_len,
         uint8_t* output, size_t output_len);

// Generate a nonce for EAPOL
void generate_nonce(uint8_t* nonce, size_t len);

// Compute PTK from PMK, addresses, and nonces
void compute_ptk(const uint8_t* pmk, 
                 const uint8_t* addr1, const uint8_t* addr2,
                 const uint8_t* nonce1, const uint8_t* nonce2,
                 uint8_t* ptk, size_t ptk_len);

// Compute MIC for EAPOL frame
void compute_mic(const uint8_t* kck, const void* data, size_t data_len, uint8_t* mic);

// Verify MIC in EAPOL frame
int verify_mic(const uint8_t* kck, const void* data, size_t data_len, const uint8_t* mic);

// AES unwrap function for decrypting GTK
int aes_unwrap(const uint8_t* kek, const uint8_t* data, size_t data_len, uint8_t* output);