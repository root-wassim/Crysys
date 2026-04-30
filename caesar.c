#include "caesar.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

char *caesar_encrypt(const char *plaintext, int shift) {
    if (!plaintext) return NULL;
    size_t len = strlen(plaintext);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    shift = ((shift % 26) + 26) % 26;
    for (size_t i = 0; i < len; i++) {
        if (isupper((unsigned char)plaintext[i]))
            out[i] = (char)(((plaintext[i] - 'A' + shift) % 26) + 'A');
        else if (islower((unsigned char)plaintext[i]))
            out[i] = (char)(((plaintext[i] - 'a' + shift) % 26) + 'a');
        else
            out[i] = plaintext[i];
    }
    out[len] = '\0';
    return out;
}

char *caesar_decrypt(const char *ciphertext, int shift) {
    return caesar_encrypt(ciphertext, -shift);
}

static int caesar_process_file(const char *infile, const char *outfile, int shift) {
    FILE *fin = fopen(infile, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(outfile, "wb");
    if (!fout) { fclose(fin); return -1; }
    int c;
    int s = ((shift % 26) + 26) % 26;
    while ((c = fgetc(fin)) != EOF) {
        if (isupper(c)) c = ((c - 'A' + s) % 26) + 'A';
        else if (islower(c)) c = ((c - 'a' + s) % 26) + 'a';
        fputc(c, fout);
    }
    fclose(fin);
    fclose(fout);
    return 0;
}

int caesar_encrypt_file(const char *infile, const char *outfile, int shift) {
    return caesar_process_file(infile, outfile, shift);
}

int caesar_decrypt_file(const char *infile, const char *outfile, int shift) {
    return caesar_process_file(infile, outfile, -shift);
}
