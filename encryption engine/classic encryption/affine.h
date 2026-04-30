#ifndef AFFINE_H
#define AFFINE_H

char* affine_encrypt(const char* plaintext, int a, int b);
char* affine_decrypt(const char* ciphertext, int a, int b);

#endif
