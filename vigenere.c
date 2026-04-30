#include "vigenere.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static char *vigenere_process(const char *text, const char *key, int encrypt) {
    if (!text || !key) return NULL;
    size_t klen = strlen(key);
    if (klen == 0) return NULL;
    size_t len = strlen(text);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    size_t ki = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = text[i];
        if (isalpha((unsigned char)ch)) {
            char base = isupper((unsigned char)ch) ? 'A' : 'a';
            int kshift = tolower((unsigned char)key[ki % klen]) - 'a';
            if (encrypt)
                out[i] = (char)(((ch - base + kshift) % 26) + base);
            else
                out[i] = (char)(((ch - base - kshift + 26) % 26) + base);
            ki++;
        } else {
            out[i] = ch;
        }
    }
    out[len] = '\0';
    return out;
}

char *vigenere_encrypt(const char *plaintext, const char *key) {
    return vigenere_process(plaintext, key, 1);
}

char *vigenere_decrypt(const char *ciphertext, const char *key) {
    return vigenere_process(ciphertext, key, 0);
}

static int vigenere_process_file(const char *infile, const char *outfile, const char *key, int encrypt) {
    if (!key) return -1;
    size_t klen = strlen(key);
    if (klen == 0) return -1;
    FILE *fin = fopen(infile, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { fclose(fin); return -1; }
    int c;
    size_t ki = 0;
    while ((c = fgetc(fin)) != EOF) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int kshift = tolower((unsigned char)key[ki % klen]) - 'a';
            if (encrypt) c = ((c - base + kshift) % 26) + base;
            else c = ((c - base - kshift + 26) % 26) + base;
            ki++;
        }
        fputc(c, fout);
    }
    fclose(fin); fclose(fout);
    return 0;
}

int vigenere_encrypt_file(const char *infile, const char *outfile, const char *key) {
    return vigenere_process_file(infile, outfile, key, 1);
}

int vigenere_decrypt_file(const char *infile, const char *outfile, const char *key) {
    return vigenere_process_file(infile, outfile, key, 0);
}
