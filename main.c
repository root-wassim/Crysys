#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "classic_encryption/caesar.h"
#include "classic_encryption/affine.h"
#include "classic_encryption/vigenere.h"
#include "classic_encryption/playfair.h"
#include "classic_encryption/hill.h"
#include "modern_encryption/rc4.h"
#include "modern_encryption/des.h"
#include "modern_encryption/aes.h"
#include "hash/md5.h"
#include "hash/sha256.h"

static void print_menu(void) {
    printf("\n====================================\n");
    printf("       C CRYPTO TOOLKIT\n");
    printf("====================================\n");
    printf("  CLASSIC ENCRYPTION\n");
    printf("   1. Caesar Cipher\n");
    printf("   2. Affine Cipher\n");
    printf("   3. Vigenere Cipher\n");
    printf("   4. Playfair Cipher\n");
    printf("   5. Hill Cipher\n");
    printf("  MODERN ENCRYPTION\n");
    printf("   6. RC4\n");
    printf("   7. DES\n");
    printf("   8. AES-128\n");
    printf("  HASH FUNCTIONS\n");
    printf("   9. MD5\n");
    printf("  10. SHA-256\n");
    printf("   0. Exit\n");
    printf("====================================\n");
    printf("Select: ");
}

static int get_int(const char *prompt) {
    printf("%s", prompt);
    int v; scanf("%d", &v);
    return v;
}

static void get_str(const char *prompt, char *buf, int size) {
    printf("%s", prompt);
    getchar();
    fgets(buf, size, stdin);
    buf[strcspn(buf, "\n")] = '\0';
}

static int get_op(void) {
    printf("  Operation: 1=Encrypt  2=Decrypt\n  Choice: ");
    int v; scanf("%d", &v); return v;
}

static int get_target(void) {
    printf("  Target: 1=Text  2=File\n  Choice: ");
    int v; scanf("%d", &v); return v;
}

static void do_caesar(void) {
    int op = get_op();
    int target = get_target();
    int shift = get_int("  Shift (integer): ");
    char buf[4096], infile[512], outfile[512];
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        char *res = (op == 1) ? caesar_encrypt(buf, shift) : caesar_decrypt(buf, shift);
        if (res) { printf("  Result: %s\n", res); free(res); }
    } else {
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1) ? caesar_encrypt_file(infile, outfile, shift)
                          : caesar_decrypt_file(infile, outfile, shift);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_affine(void) {
    int op = get_op();
    int target = get_target();
    int a = get_int("  Key a: ");
    int b = get_int("  Key b: ");
    char buf[4096], infile[512], outfile[512];
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        char *res = (op == 1) ? affine_encrypt(buf, a, b) : affine_decrypt(buf, a, b);
        if (res) { printf("  Result: %s\n", res); free(res); }
        else printf("  Error: key 'a' has no modular inverse mod 26.\n");
    } else {
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1) ? affine_encrypt_file(infile, outfile, a, b)
                          : affine_decrypt_file(infile, outfile, a, b);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_vigenere(void) {
    int op = get_op();
    int target = get_target();
    char key[256], buf[4096], infile[512], outfile[512];
    get_str("  Key: ", key, sizeof(key));
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        char *res = (op == 1) ? vigenere_encrypt(buf, key) : vigenere_decrypt(buf, key);
        if (res) { printf("  Result: %s\n", res); free(res); }
    } else {
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1) ? vigenere_encrypt_file(infile, outfile, key)
                          : vigenere_decrypt_file(infile, outfile, key);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_playfair(void) {
    int op = get_op();
    int target = get_target();
    char key[256], buf[4096], infile[512], outfile[512];
    get_str("  Key: ", key, sizeof(key));
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        char *res = (op == 1) ? playfair_encrypt(buf, key) : playfair_decrypt(buf, key);
        if (res) { printf("  Result: %s\n", res); free(res); }
    } else {
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1) ? playfair_encrypt_file(infile, outfile, key)
                          : playfair_decrypt_file(infile, outfile, key);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_hill(void) {
    int op = get_op();
    int target = get_target();
    int size = get_int("  Matrix size (2 or 3): ");
    if (size != 2 && size != 3) { printf("  Invalid size.\n"); return; }
    int key[9];
    printf("  Enter %dx%d key matrix values row by row:\n", size, size);
    for (int i = 0; i < size * size; i++) {
        printf("  [%d]: ", i);
        scanf("%d", &key[i]);
    }
    char buf[4096], infile[512], outfile[512];
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        char *res = (op == 1) ? hill_encrypt(buf, key, size) : hill_decrypt(buf, key, size);
        if (res) { printf("  Result: %s\n", res); free(res); }
        else printf("  Error: matrix not invertible mod 26.\n");
    } else {
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1) ? hill_encrypt_file(infile, outfile, key, size)
                          : hill_decrypt_file(infile, outfile, key, size);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_rc4(void) {
    int op = get_op();
    int target = get_target();
    char keystr[256];
    get_str("  Key (ASCII): ", keystr, sizeof(keystr));
    size_t klen = strlen(keystr);
    char buf[4096], infile[512], outfile[512];
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        size_t inlen = strlen(buf);
        size_t outlen;
        unsigned char *res = (op == 1)
            ? rc4_encrypt((unsigned char *)buf, inlen, (unsigned char *)keystr, klen, &outlen)
            : rc4_decrypt((unsigned char *)buf, inlen, (unsigned char *)keystr, klen, &outlen);
        if (res) {
            printf("  Result (hex): ");
            for (size_t i = 0; i < outlen; i++) printf("%02x", res[i]);
            printf("\n");
            free(res);
        }
    } else {
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1)
            ? rc4_encrypt_file(infile, outfile, (unsigned char *)keystr, klen)
            : rc4_decrypt_file(infile, outfile, (unsigned char *)keystr, klen);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_des(void) {
    int op = get_op();
    int target = get_target();
    char keystr[64];
    get_str("  Key (8 chars, padded if shorter): ", keystr, sizeof(keystr));
    uint8_t key[8] = {0};
    for (int i = 0; i < 8 && keystr[i]; i++) key[i] = (uint8_t)keystr[i];
    if (target == 1) {
        char buf[64];
        get_str("  Input text (max 8 chars): ", buf, sizeof(buf));
        uint8_t in[8] = {0}, out[8];
        for (int i = 0; i < 8 && buf[i]; i++) in[i] = (uint8_t)buf[i];
        if (op == 1) des_encrypt_block(in, out, key);
        else des_decrypt_block(in, out, key);
        printf("  Result (hex): ");
        for (int i = 0; i < 8; i++) printf("%02x", out[i]);
        printf("\n");
    } else {
        char infile[512], outfile[512];
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1) ? des_encrypt_file(infile, outfile, key)
                          : des_decrypt_file(infile, outfile, key);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_aes(void) {
    int op = get_op();
    int target = get_target();
    char keystr[64];
    get_str("  Key (16 chars for AES-128, padded if shorter): ", keystr, sizeof(keystr));
    uint8_t key[16] = {0};
    for (int i = 0; i < 16 && keystr[i]; i++) key[i] = (uint8_t)keystr[i];
    if (target == 1) {
        char buf[64];
        get_str("  Input text (max 16 chars): ", buf, sizeof(buf));
        uint8_t in[16] = {0}, out[16];
        for (int i = 0; i < 16 && buf[i]; i++) in[i] = (uint8_t)buf[i];
        if (op == 1) aes_encrypt_block(in, out, key, 128);
        else aes_decrypt_block(in, out, key, 128);
        printf("  Result (hex): ");
        for (int i = 0; i < 16; i++) printf("%02x", out[i]);
        printf("\n");
    } else {
        char infile[512], outfile[512];
        get_str("  Input file: ", infile, sizeof(infile));
        get_str("  Output file: ", outfile, sizeof(outfile));
        int r = (op == 1) ? aes_encrypt_file(infile, outfile, key, 128)
                          : aes_decrypt_file(infile, outfile, key, 128);
        printf(r == 0 ? "  Done.\n" : "  Error.\n");
    }
}

static void do_md5(void) {
    int target = get_target();
    uint8_t digest[16];
    char hex[33];
    char buf[4096], path[512];
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        md5_hash((uint8_t *)buf, strlen(buf), digest);
        md5_digest_to_hex(digest, hex);
        printf("  MD5: %s\n", hex);
    } else {
        get_str("  File path: ", path, sizeof(path));
        if (md5_hash_file(path, digest) == 0) {
            md5_digest_to_hex(digest, hex);
            printf("  MD5: %s\n", hex);
        } else printf("  Error reading file.\n");
    }
}

static void do_sha256(void) {
    int target = get_target();
    uint8_t digest[32];
    char hex[65];
    char buf[4096], path[512];
    if (target == 1) {
        get_str("  Input text: ", buf, sizeof(buf));
        sha256_hash((uint8_t *)buf, strlen(buf), digest);
        sha256_digest_to_hex(digest, hex);
        printf("  SHA-256: %s\n", hex);
    } else {
        get_str("  File path: ", path, sizeof(path));
        if (sha256_hash_file(path, digest) == 0) {
            sha256_digest_to_hex(digest, hex);
            printf("  SHA-256: %s\n", hex);
        } else printf("  Error reading file.\n");
    }
}

int main(void) {
    int choice;
    do {
        print_menu();
        scanf("%d", &choice);
        switch (choice) {
            case 1: do_caesar();   break;
            case 2: do_affine();   break;
            case 3: do_vigenere(); break;
            case 4: do_playfair(); break;
            case 5: do_hill();     break;
            case 6: do_rc4();      break;
            case 7: do_des();      break;
            case 8: do_aes();      break;
            case 9: do_md5();      break;
            case 10: do_sha256();  break;
            case 0: printf("  Bye.\n"); break;
            default: printf("  Invalid choice.\n");
        }
    } while (choice != 0);
    return 0;
}
