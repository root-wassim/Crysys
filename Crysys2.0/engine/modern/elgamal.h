#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <stdint.h>

void elgamal_generate_keys(uint64_t p, uint64_t g, uint64_t* privKey, uint64_t* pubKey);
void elgamal_encrypt(const char* plaintext, uint64_t p, uint64_t g, uint64_t pubKey, uint64_t** c1, uint64_t** c2, int* out_len);
char* elgamal_decrypt(const uint64_t* c1, const uint64_t* c2, int len, uint64_t p, uint64_t privKey);

#endif
