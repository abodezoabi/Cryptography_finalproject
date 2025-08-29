/*
 * AES-128 Encryption Header
 * -------------------------
 * This header declares the interface for AES-128 block encryption.
 * The implementation performs encryption on a single 16-byte block
 * using a 16-byte key according to the FIPS-197 standard.
 *
 */
#ifndef AES128E_H
#define AES128E_H

#include <stdint.h>

/**
 * Encrypts a single 16-byte block using AES-128.
 * 
 * @param output 16-byte output buffer (ciphertext)
 * @param input 16-byte input buffer (plaintext block)
 * @param key   16-byte AES-128 key
 */
void aes128e(uint8_t *output, const uint8_t *input, const uint8_t *key);

#endif // AES128E_H