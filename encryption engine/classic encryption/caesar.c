#include "caesar.h"
#include "../core/utils.h"
#include <string.h>

char* caesar_encrypt(const char* plaintext, int decalage) {
    size_t len = strlen(plaintext);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        char r = plaintext[i];
        if (r >= 'A' && r <= 'Z') {
            int num = r - 'A';
            int newNum = (num + decalage) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum];
        } else if (r >= 'a' && r <= 'z') {
            int num = r - 'a';
            int newNum = (num + decalage) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum] - 'A' + 'a';
        } else {
            result[i] = r;
        }
    }
    result[len] = '\0';
    return result;
}

char* caesar_decrypt(const char* ciphertext, int decalage) {
    size_t len = strlen(ciphertext);
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        char r = ciphertext[i];
        if (r >= 'A' && r <= 'Z') {
            int num = r - 'A';
            int newNum = (num - decalage) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum];
        } else if (r >= 'a' && r <= 'z') {
            int num = r - 'a';
            int newNum = (num - decalage) % 26;
            if (newNum < 0) newNum += 26;
            result[i] = ReverseAlphabetMap[newNum] - 'A' + 'a';
        } else {
            result[i] = r;
        }
    }
    result[len] = '\0';
    return result;
}
