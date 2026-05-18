#ifndef RC4_H
#define RC4_H

char* rc4_encrypt(const char* plaintext, const char* key);
char* rc4_decrypt(const char* ciphertext, const char* key);

#endif
