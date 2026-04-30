#include "affine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static int mod_inverse(int a, int m) {
    a = ((a % m) + m) % m;
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 1) return x;
    return -1;
}

char *affine_encrypt(const char *plaintext, int a, int b) {
    if (!plaintext) return NULL;
    if (mod_inverse(a, 26) == -1) return NULL;
    size_t len = strlen(plaintext);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        if (isupper((unsigned char)plaintext[i]))
            out[i] = (char)(((a * (plaintext[i] - 'A') + b) % 26 + 26) % 26 + 'A');
        else if (islower((unsigned char)plaintext[i]))
            out[i] = (char)(((a * (plaintext[i] - 'a') + b) % 26 + 26) % 26 + 'a');
        else
            out[i] = plaintext[i];
    }
    out[len] = '\0';
    return out;
}

char *affine_decrypt(const char *ciphertext, int a, int b) {
    if (!ciphertext) return NULL;
    int a_inv = mod_inverse(a, 26);
    if (a_inv == -1) return NULL;
    size_t len = strlen(ciphertext);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        if (isupper((unsigned char)ciphertext[i]))
            out[i] = (char)((a_inv * ((ciphertext[i] - 'A') - b + 26 * 26) % 26 + 26) % 26 + 'A');
        else if (islower((unsigned char)ciphertext[i]))
            out[i] = (char)((a_inv * ((ciphertext[i] - 'a') - b + 26 * 26) % 26 + 26) % 26 + 'a');
        else
            out[i] = ciphertext[i];
    }
    out[len] = '\0';
    return out;
}

int affine_encrypt_file(const char *infile, const char *outfile, int a, int b) {
    if (mod_inverse(a, 26) == -1) return -1;
    FILE *fin = fopen(infile, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { fclose(fin); return -1; }
    int c;
    while ((c = fgetc(fin)) != EOF) {
        if (isupper(c)) c = ((a * (c - 'A') + b) % 26 + 26) % 26 + 'A';
        else if (islower(c)) c = ((a * (c - 'a') + b) % 26 + 26) % 26 + 'a';
        fputc(c, fout);
    }
    fclose(fin); fclose(fout);
    return 0;
}

int affine_decrypt_file(const char *infile, const char *outfile, int a, int b) {
    int a_inv = mod_inverse(a, 26);
    if (a_inv == -1) return -1;
    FILE *fin = fopen(infile, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { fclose(fin); return -1; }
    int c;
    while ((c = fgetc(fin)) != EOF) {
        if (isupper(c)) c = (a_inv * ((c - 'A') - b + 26 * 26) % 26 + 26) % 26 + 'A';
        else if (islower(c)) c = (a_inv * ((c - 'a') - b + 26 * 26) % 26 + 26) % 26 + 'a';
        fputc(c, fout);
    }
    fclose(fin); fclose(fout);
    return 0;
}
