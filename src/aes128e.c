/********************************************************************************
 * aes128e.c
 *
 * This file implements the core AES-128 encryption algorithm used in OFB mode.
 * It provides the necessary functions to perform AES-128 block encryption,
 * including key expansion, substitution, permutation, and mixing operations.
 *
 * The AES-128 algorithm operates on 128-bit blocks and uses a 128-bit key.
 * This implementation follows the standard AES specification with 10 rounds.
 ********************************************************************************/

#include <stdint.h>
#include <string.h>
#include "../include/aes128e.h"

// AES constants
#define Nb 4  // Number of columns (32-bit words) comprising the State. For AES, Nb = 4.
#define Nk 4  // Number of 32-bit words comprising the Cipher Key. For AES-128, Nk = 4.
#define Nr 10 // Number of rounds in AES Cipher. For AES-128, Nr = 10.

/*
 * The substitution box (S-box) is a non-linear substitution table used in the SubBytes step.
 * It provides the non-linearity in the cipher and is designed to resist cryptanalysis.
 */
static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*
 * The round constant word array (Rcon) contains constants used in the KeyExpansion step.
 * Each element is used to introduce non-linearity and ensure keys differ in each round.
 */
static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36
};

/*
 * KeyExpansion generates the round keys from the original cipher key.
 * It expands the 128-bit key into a series of round keys for each encryption round.
 */
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key) {
    unsigned i, j, k;
    uint8_t tempa[4];

    // The first round key is the key itself
    for (i = 0; i < Nk; ++i) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        k = (i - 1) * 4;
        tempa[0] = RoundKey[k + 0];
        tempa[1] = RoundKey[k + 1];
        tempa[2] = RoundKey[k + 2];
        tempa[3] = RoundKey[k + 3];

        // Every Nk words, apply the core schedule function
        if (i % Nk == 0) {
            const uint8_t u8tmp = tempa[0];
            // Rotate the 4-byte word and apply S-box substitution
            tempa[0] = sbox[tempa[1]] ^ Rcon[i / Nk];
            tempa[1] = sbox[tempa[2]];
            tempa[2] = sbox[tempa[3]];
            tempa[3] = sbox[u8tmp];
        }

        j = i * 4;
        k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

/*
 * AddRoundKey XORs the state with a portion of the expanded key corresponding to the current round.
 * This step integrates the key material into the state.
 */
static void AddRoundKey(uint8_t round, uint8_t* state, const uint8_t* RoundKey) {
    for (uint8_t i = 0; i < 16; ++i) {
        state[i] ^= RoundKey[(round * Nb * 4) + i];
    }
}

/*
 * SubBytes substitutes each byte in the state with its corresponding byte in the S-box.
 * This non-linear substitution provides confusion in the cipher.
 */
static void SubBytes(uint8_t* state) {
    for (uint8_t i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

/*
 * ShiftRows shifts the rows of the state cyclically to the left by different offsets.
 * This step provides diffusion by transposing the bytes within each row.
 */
static void ShiftRows(uint8_t* state) {
    uint8_t temp;

    // Row 1 (1-byte left circular shift)
    temp = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = temp;

    // Row 2 (2-byte left circular shift)
    temp = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp = state[6];
    state[6]  = state[14];
    state[14] = temp;

    // Row 3 (3-byte left circular shift, equivalent to 1-byte right circular shift)
    temp = state[3];
    state[3]  = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = temp;
}

/*
 * xtime multiplies a byte by 2 in the GF(2^8) finite field.
 * This operation is used in the MixColumns step to perform polynomial multiplication.
 */
static void xtime(uint8_t* x) {
    *x = (*x << 1) ^ ((*x & 0x80) ? 0x1b : 0x00);
}

/*
 * MixColumns mixes the bytes of each column in the state using a fixed polynomial.
 * This step provides diffusion by combining the bytes within each column.
 */
static void MixColumns(uint8_t* state) {
    uint8_t Tmp, Tm, t;
    for (int i = 0; i < 4; ++i) {
        t = state[i*4+0];
        Tmp = state[i*4+0] ^ state[i*4+1] ^ state[i*4+2] ^ state[i*4+3];
        
        // Perform multiplication and XOR operations in GF(2^8)
        Tm = state[i*4+0] ^ state[i*4+1]; xtime(&Tm); state[i*4+0] ^= Tm ^ Tmp;

        Tm = state[i*4+1] ^ state[i*4+2]; xtime(&Tm); state[i*4+1] ^= Tm ^ Tmp;

        Tm = state[i*4+2] ^ state[i*4+3]; xtime(&Tm); state[i*4+2] ^= Tm ^ Tmp;

        Tm = state[i*4+3] ^ t;            xtime(&Tm); state[i*4+3] ^= Tm ^ Tmp;
    }
}

/*
 * aes128e performs AES-128 encryption on a single 16-byte block.
 * It takes an input block and a 128-bit key and produces the encrypted output block.
 */
void aes128e(uint8_t* output, const uint8_t* input, const uint8_t* key) {
    uint8_t RoundKey[176]; // Expanded key for all rounds
    uint8_t state[16];
    memcpy(state, input, 16);

    KeyExpansion(RoundKey, key);

    AddRoundKey(0, state, RoundKey);

    for (uint8_t round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    // Final round without MixColumns
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);

    memcpy(output, state, 16);
}
