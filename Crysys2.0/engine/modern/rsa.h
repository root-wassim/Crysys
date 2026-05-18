#ifndef RSA_H
#define RSA_H

#include <stdint.h>

void rsa_generate_keys(uint64_t p, uint64_t q, uint64_t* n, uint64_t* e, uint64_t* d);
uint64_t* rsa_encrypt(const char* plaintext, uint64_t e, uint64_t n, int* out_len);
char* rsa_decrypt(const uint64_t* ciphertext, int len, uint64_t d, uint64_t n);

#endif
