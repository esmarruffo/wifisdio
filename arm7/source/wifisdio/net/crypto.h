// Add to a new file: arm7/source/wifisdio/net/crypto.h
#pragma once

#include <stdint.h>
#include <stddef.h>

#include <nds/ndstypes.h>

// HMAC-SHA1 function
TWL_CODE void hmac_sha1(
    const uint8_t* key,
    size_t key_len, 
    const uint8_t* data,
    size_t data_len, 
    uint8_t* output
);

// PRF (Pseudo-Random Function) for WPA2

TWL_CODE void prf(
    const uint8_t* key,
    size_t key_len,
    const char* label,
    size_t label_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* output,
    size_t output_len
);

// Generate a nonce for EAPOL
TWL_CODE void generate_nonce(uint8_t* nonce, size_t len);

// Compute PTK from PMK, addresses, and nonces
TWL_CODE void compute_ptk(const uint8_t* pmk, 
                 const uint8_t* addr1, const uint8_t* addr2,
                 const uint8_t* nonce1, const uint8_t* nonce2,
                 uint8_t* ptk, size_t ptk_len);

// Compute MIC for EAPOL frame
TWL_CODE void compute_mic(const uint8_t* kck, const void* data, size_t data_len, uint8_t* mic);

// Verify MIC in EAPOL frame
TWL_CODE int verify_mic(const uint8_t* kck, const void* data, size_t data_len, const uint8_t* mic);

// AES unwrap function for decrypting GTK
TWL_CODE int aes_unwrap(const uint8_t* kek, const uint8_t* data, size_t data_len, uint8_t* output);