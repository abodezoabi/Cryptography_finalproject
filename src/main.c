/*
* AES-128 in OFB Mode - Main Program
* ----------------------------------
* This program performs file encryption and decryption using the AES-128 algorithm
* in Output Feedback (OFB) mode. It adheres to the FIPS-197 and NIST SP 800-38A standards.
*
* Usage:
*   ./aes_ofb -e input.txt encrypted.bin key.bin iv.bin     // Encrypt a file
*   ./aes_ofb -d encrypted.bin output.txt key.bin iv.bin    // Decrypt a file
*
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../include/aes128e.h"
#include "../include/obf.h"

void print_hex(const char* label, const uint8_t* data, uint32_t len) {
    printf("%s: ", label);
    for (uint32_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <-e|-d> <input_file> <output_file> <key_file> <iv_file>\n", argv[0]);
        return 1;
    }

    int encrypt = strcmp(argv[1], "-e") == 0;
    if (!encrypt && strcmp(argv[1], "-d") != 0) {
        fprintf(stderr, "Invalid mode '%s'. Use -e to encrypt or -d to decrypt.\n", argv[1]);
        return 1;
    }

    FILE *fin = fopen(argv[2], "rb");
    FILE *fout = fopen(argv[3], "wb");
    FILE *fkey = fopen(argv[4], "rb");
    FILE *fiv = fopen(argv[5], "rb");
    if (!fin || !fout || !fkey || !fiv) {
        perror("Error opening files");
        return 1;
    }

    fseek(fkey, 0, SEEK_END);
    long key_size = ftell(fkey);
    rewind(fkey);

    fseek(fiv, 0, SEEK_END);
    long iv_size = ftell(fiv);
    rewind(fiv);

    if (key_size != 16) {
        fprintf(stderr, "❌ Error: Key must be exactly 16 bytes (got %ld bytes).\n", key_size);
        fclose(fkey); fclose(fiv); fclose(fin); fclose(fout);
        return 1;
    }

    if (iv_size != 16) {
        fprintf(stderr, "❌ Error: IV must be exactly 16 bytes (got %ld bytes).\n", iv_size);
        fclose(fkey); fclose(fiv); fclose(fin); fclose(fout);
        return 1;
    }

    uint8_t key[16], iv[16];
    size_t bytes_read_key = fread(key, 1, 16, fkey);
    int extra_key_byte = fgetc(fkey);
    if (bytes_read_key != 16 || extra_key_byte != EOF) {
        fprintf(stderr, "❌ Error: Key file must contain exactly 16 bytes (no more, no less).\n");
        fclose(fkey); fclose(fiv); fclose(fin); fclose(fout);
        return 1;
    }

    size_t bytes_read_iv = fread(iv, 1, 16, fiv);
    int extra_iv_byte = fgetc(fiv);
    if (bytes_read_iv != 16 || extra_iv_byte != EOF) {
        fprintf(stderr, "❌ Error: IV file must contain exactly 16 bytes (no more, no less).\n");
        fclose(fkey); fclose(fiv); fclose(fin); fclose(fout);
        return 1;
    }

    fclose(fkey);
    fclose(fiv);

    fseek(fin, 0, SEEK_END);
    size_t file_size = (size_t) ftell(fin);
    rewind(fin);

    uint8_t* input = malloc(file_size);
    uint8_t* output = malloc(file_size);
    if (!input || !output) {
        fprintf(stderr, "❌ Error: Memory allocation failed.\n");
        fclose(fin);
        if (input) free(input);
        if (output) free(output);
        return 1;
    }
    if (fread(input, 1, file_size, fin) != file_size) {
        fprintf(stderr, "❌ Error: Failed to read input file completely.\n");
        fclose(fin);
        free(input);
        free(output);
        return 1;
    }
    fclose(fin);

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    OFBaes128e(output, input, file_size, iv_copy, key);

    fwrite(output, 1, file_size, fout);
    fclose(fout);

    free(input);
    free(output);

    printf("%s completed.\n", encrypt ? "Encryption" : "Decryption");
    return 0;
}