#ifndef DES_H
#define DES_H

char* des_encrypt(const char* plaintext, const char* key);
char* des_decrypt(const char* ciphertext, const char* key);

#endif
