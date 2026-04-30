#ifndef HILL_H
#define HILL_H

char* hill_encrypt(const char* plaintext, const char* key, int size);
char* hill_decrypt(const char* ciphertext, const char* key, int size);

#endif
