#include "vigenere.h"
#include "../core/utils.h"
#include <string.h>
#include <ctype.h>

char* vigenere_encrypt(const char* plaintext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!plaintext || strlen(plaintext) == 0) return strdup("");
    size_t len = strlen(plaintext);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;

    size_t keyLen = strlen(key);
    char* upperKey = (char*)malloc(keyLen + 1);
    int validKeyLen = 0;
    for (size_t i = 0; i < keyLen; i++) {
        if (key[i] != ' ') {
            upperKey[validKeyLen++] = toupper(key[i]);
        }
    }
    upperKey[validKeyLen] = '\0';
    if (validKeyLen == 0) {
        free(upperKey);
        free(result);
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        char r = toupper(plaintext[i]);
        if (r >= 'A' && r <= 'Z') {
            int num = r - 'A';
            int keyNum = upperKey[i % validKeyLen] - 'A';
            int newNum = (num + keyNum) % 26;
            result[i] = ReverseAlphabetMap[newNum];
        } else {
            result[i] = r;
        }
    }
    result[len] = '\0';
    free(upperKey);
    return result;
}

char* vigenere_decrypt(const char* ciphertext, const char* key) {
    if (!key || strlen(key) == 0) return NULL;
    if (!ciphertext || strlen(ciphertext) == 0) return strdup("");
    size_t len = strlen(ciphertext);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;

    size_t keyLen = strlen(key);
    char* upperKey = (char*)malloc(keyLen + 1);
    int validKeyLen = 0;
    for (size_t i = 0; i < keyLen; i++) {
        if (key[i] != ' ') {
            upperKey[validKeyLen++] = toupper(key[i]);
        }
    }
    upperKey[validKeyLen] = '\0';
    if (validKeyLen == 0) {
        free(upperKey);
        free(result);
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        char r = toupper(ciphertext[i]);
        if (r >= 'A' && r <= 'Z') {
            int num = r - 'A';
            int keyNum = upperKey[i % validKeyLen] - 'A';
            int newNum = (num - keyNum + 26) % 26;
            result[i] = ReverseAlphabetMap[newNum];
        } else {
            result[i] = r;
        }
    }
    result[len] = '\0';
    free(upperKey);
    return result;
}
