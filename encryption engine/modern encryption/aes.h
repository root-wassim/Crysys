#ifndef AES_H
#define AES_H

char* aes_encrypt(const char* plaintext, const char* key);
char* aes_decrypt(const char* ciphertext, const char* key);

#endif
