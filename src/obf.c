#include <stdint.h>
#include <string.h>
#include "../include/aes128e.h"
#include "../include/obf.h"

/*
 * AES-128 OFB Mode Implementation
 * -------------------------------
 * This file implements AES-128 encryption in Output Feedback (OFB) mode as specified in
 * NIST Special Publication 800-38A.
 *
 * OFB mode turns a block cipher into a synchronous stream cipher. It encrypts a fixed IV
 * and then feeds each cipher output back as input to produce a keystream. The plaintext
 * is XORed with this keystream to produce ciphertext.
 *
 * Author: Anthonios Deeb & Abedalla Zoabi
 * Date: 2025
 */

void OFBaes128e(uint8_t *ciphertext, const uint8_t *plaintext, uint32_t length,
                uint8_t *iv, const uint8_t *key)
{
    uint8_t block_out[16] = {0};
    uint8_t feedback[16] = {0};

    // Copy IV into feedback buffer
    memcpy(feedback, iv, 16);

    uint32_t full_blocks = length / 16;
    uint32_t remaining = length % 16;

    // Encrypt each 16-byte block
    for (uint32_t i = 0; i < full_blocks; ++i) {
        aes128e(block_out, feedback, key);  // Generate keystream block
        for (int j = 0; j < 16; ++j) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ block_out[j];  // XOR with plaintext
        }
        memcpy(feedback, block_out, 16);  // Update feedback with current keystream block
    }

    // Handle final partial block if it exists
    if (remaining > 0) {
        aes128e(block_out, feedback, key);  // Generate next keystream block
        for (uint32_t j = 0; j < remaining; ++j) {
            ciphertext[full_blocks * 16 + j] = plaintext[full_blocks * 16 + j] ^ block_out[j];
        }
    }
}
