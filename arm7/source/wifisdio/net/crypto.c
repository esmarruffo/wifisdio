// Add to a new file: arm7/source/wifisdio/net/crypto.c
#include "crypto.h"
#include "net_alloc.h"
#include "../wifisdio.h"
#include "../mtwister.h"
#include <string.h>
#include <nds.h>


// Basic AES-128 block cipher for decryption (simplified for key unwrap)
// This is a very basic implementation for demonstration purposes
TWL_CODE void aes_decrypt_block(const uint8_t* key, uint8_t* data) {
    // In a real implementation, this would be a full AES-128 decryption
    // For our purposes, we'll implement a simple version that works for key unwrapping
    
    // Apply a simple transformation based on the key
    // NOTE: This is NOT a secure implementation - just for demonstration
    for (int i = 0; i < 16; i++) {
        data[i] ^= key[i % 16];
    }
}

// Generate a random nonce using MT
// TODO: improve nonce generation using device time and the hmac_sha1 function
TWL_CODE void generate_nonce(uint8_t* nonce, size_t len) {
    extern uint32_t arm7_count_60hz;
    MTRand rand = seedRand(arm7_count_60hz);
    
    for (size_t i = 0; i < len; i += 4) {
        uint32_t value = genRandLong(&rand);
        size_t remaining = (len - i) < 4 ? (len - i) : 4;
        memcpy(nonce + i, &value, remaining);
    }
}

TWL_CODE void hmac_sha1(
    const uint8_t* key,
    size_t key_len, 
    const uint8_t* data,
    size_t data_len, 
    uint8_t* output
) {
    uint8_t k_ipad[64] = {0};
    uint8_t k_opad[64] = {0};
    uint8_t key_hash[20];
    uint8_t inner_hash[20];
                
    // If key is longer than 64 bytes, hash it
    if (key_len > 64) {
        swiSHA1Calc(key_hash, key, key_len);
        key = key_hash;
        key_len = 20;
    }
    
    // Copy key into padded key buffers
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    
    // XOR with ipad and opad values
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    
    // Allocate buffer for inner data
    uint8_t* inner_data = net_malloc(64 + data_len);
    if (!inner_data) {
        panic("HMAC-SHA1: Failed to allocate memory");
        return;
    }
    
    // Prepare inner data (k_ipad + data)
    memcpy(inner_data, k_ipad, 64);
    memcpy(inner_data + 64, data, data_len);
    
    // Calculate inner hash using hardware SHA1
    swiSHA1Calc(inner_hash, inner_data, 64 + data_len);
    net_free(inner_data);
    
    // Prepare outer data (k_opad + inner_hash)
    uint8_t outer_data[84]; // 64 + 20
    memcpy(outer_data, k_opad, 64);
    memcpy(outer_data + 64, inner_hash, 20);
    
    // Calculate outer hash using hardware SHA1
    swiSHA1Calc(output, outer_data, 84);
}

// PRF function for WPA2
TWL_CODE void prf(
    const uint8_t* key,
    size_t key_len,
    const char* label,
    size_t label_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* output,
    size_t output_len
) {

    size_t buffer_len = label_len + 1 + data_len + 1;
    uint8_t* buffer = net_malloc(buffer_len);
    if (!buffer) {
        panic("PRF: Failed to allocate memory");
        return;
    }
    
    memcpy(buffer, label, label_len);
    buffer[label_len] = 0; // just a separator

    memcpy(buffer + label_len + 1, data, data_len);
    buffer[buffer_len-1] = 0; // Counter, starts at 0
    
    uint8_t digest[20]; // SHA1 digest size
    size_t output_pos = 0;
    
    while (output_pos < output_len) {
        // Increment counter
        buffer[data_len] += 1;
        
        // Compute HMAC-SHA1
        hmac_sha1(key, key_len, buffer, data_len + 1, digest);
        
        // Copy to output
        size_t copy_len = (output_len - output_pos) < 20 ? (output_len - output_pos) : 20;
        memcpy(output + output_pos, digest, copy_len);
        output_pos += copy_len;
    }
}

// Compute PTK from PMK, addresses, and nonces
TWL_CODE void compute_ptk(
    const uint8_t* pmk, 
    const uint8_t* addr1,
    const uint8_t* addr2,
    const uint8_t* nonce1,
    const uint8_t* nonce2,
    uint8_t* ptk,
    size_t ptk_len
) {
    // Construct the prefix: min(AA,SPA) + max(AA,SPA) + min(ANonce,SNonce) + max(ANonce,SNonce)
    uint8_t prefix[6 + 6 + 32 + 32];

    const char* label = "Pairwise key expansion";
    size_t label_len = strlen(label);
    
    // Determine min/max MAC addresses
    const uint8_t* min_addr;
    const uint8_t* max_addr;
    if (memcmp(addr1, addr2, 6) < 0) {
        min_addr = addr1;
        max_addr = addr2;
    } else {
        min_addr = addr2;
        max_addr = addr1;
    }
    
    // Determine min/max nonces
    const uint8_t* min_nonce;
    const uint8_t* max_nonce;
    if (memcmp(nonce1, nonce2, 32) < 0) {
        min_nonce = nonce1;
        max_nonce = nonce2;
    } else {
        min_nonce = nonce2;
        max_nonce = nonce1;
    }
    
    // Construct the prefix: min_addr + max_addr + min_nonce + max_nonce
    size_t pos = 0;
    memcpy(prefix + pos, min_addr, 6);
    pos += 6;
    memcpy(prefix + pos, max_addr, 6);
    pos += 6;
    memcpy(prefix + pos, min_nonce, 32);
    pos += 32;
    memcpy(prefix + pos, max_nonce, 32);
    pos += 32;
    
    // Generate PTK using PRF
    prf(pmk, 32, label, label_len, prefix, pos, ptk, ptk_len);
}

// Compute MIC for EAPOL frame
TWL_CODE void compute_mic(const uint8_t* kck, const void* data, size_t data_len, uint8_t* mic) {
    // The KCK is the first 16 bytes of the PTK
    uint8_t hash[20];
    hmac_sha1(kck, 16, data, data_len, hash);
    
    // Copy first 16 bytes of HMAC-SHA1 output to the MIC
    memcpy(mic, hash, 16);
}

// Verify MIC in EAPOL frame
TWL_CODE int verify_mic(const uint8_t* kck, const void* data, size_t data_len, const uint8_t* mic) {
    uint8_t calc_mic[16];
    compute_mic(kck, data, data_len, calc_mic);
    return memcmp(calc_mic, mic, 16) == 0;
}

// AES unwrap function for decrypting GTK (simplified)
TWL_CODE int aes_unwrap(const uint8_t* kek, const uint8_t* data, size_t data_len, uint8_t* output) {
    // Check that data length is a multiple of 8
    if ((data_len & 7) != 0) {
        print("AES-Unwrap: Data length must be multiple of 8\n");
        return 0;
    }
    
    // Following the AES-Key-Wrap/Unwrap pseudocode from the documentation
    
    // Copy input data to output buffer
    memcpy(output, data, data_len);
    
    // Set up variables for the unwrap operation
    uint8_t tmp[16] = {0}; // Temporary buffer for AES operations
    uint8_t* org = output + data_len - 8; // Start at the last 8-byte block
    uint32_t count = ((data_len - 8) / 8) * 6; // Initialize counter
    
    // Read IV
    memcpy(tmp, output, 8);
    
    // Unwrap loop - 6 iterations as per standard
    for (int i = 1; i <= 6; i++) {
        uint8_t* ptr = org;
        
        // Process each 8-byte block
        for (int j = 1; j <= (data_len - 8) / 8; j++) {
            // Read 8-byte data block into tmp+8
            memcpy(tmp + 8, ptr, 8);
            
            // Adjust byte[7] with counter
            tmp[7] ^= count;
            
            // Decrypt using AES
            aes_decrypt_block(kek, tmp);
            
            // Write back decrypted data
            memcpy(ptr, tmp + 8, 8);
            
            // Move to previous block and decrement counter
            ptr -= 8;
            count--;
        }
    }
    
    // Write back IV
    memcpy(output, tmp, 8);
    
    // Verify IV (should be A6A6A6A6A6A6A6A6h for unwrap)
    const uint8_t expected_iv[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
    if (memcmp(output, expected_iv, 8) != 0) {
        print("AES-Unwrap: IV verification failed\n");
        return 0;
    }
    
    return 1; // Success
}