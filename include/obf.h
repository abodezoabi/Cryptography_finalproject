/*
 * ofb.h
 *
 * This header file declares the OFBaes128e function, which implements the
 * AES-128 encryption in Output Feedback (OFB) mode as specified by
 * NIST Special Publication 800-38A.
 *
 * The function performs encryption (and decryption, since OFB is symmetric)
 * of a given plaintext using a provided 128-bit AES key and initialization vector (IV).
 *
 */

#ifndef OFB_H
#define OFB_H

#include <stdint.h>

void OFBaes128e(uint8_t *ciphertext, const uint8_t *plaintext, uint32_t length,
                uint8_t *iv, const uint8_t *key);

#endif // OFB_H