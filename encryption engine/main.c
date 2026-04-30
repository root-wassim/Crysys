#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "core/utils.h"
#include "classic encryption/caesar.h"
#include "classic encryption/affine.h"
#include "classic encryption/vigenere.h"
#include "classic encryption/playfair.h"
#include "classic encryption/hill.h"
#include "modern encryption/aes.h"
#include "modern encryption/des.h"
#include "modern encryption/rc4.h"
#include "modern encryption/rc6.h"
#include "modern encryption/serpent.h"
#include "modern encryption/dh.h"
#include "modern encryption/rsa.h"
#include "modern encryption/elgamal.h"
#include "hash/md5.h"
#include "hash/sha256.h"
#include "classic encryption/cryptanalysis.h"

void print_usage() {
    printf("Usage: crysys_cli [options] <input text>\n");
    printf("Options:\n");
    printf("  -a <algo>   Algorithm (caesar, affine, vigenere, playfair, hill, rc4, des, aes, rc6, serpent, dh, rsa, elgamal, md5, sha256)\n");
    printf("  -m <mode>   Mode (encrypt, decrypt, hash, keygen)\n");
    printf("  -k <key>    Key for encryption/decryption\n");
    printf("  -i <file>   Input file\n");
    printf("  -o <file>   Output file\n");
    printf("  -s <shift>  Shift value for Caesar (default: 3)\n");
    printf("  -p <param>  a parameter for Affine cipher\n");
    printf("  -b <param>  b parameter for Affine cipher\n");
    printf("  -n <size>   Matrix size for Hill cipher (2 or 3)\n");
    printf("  -q <prime>  Prime for DH/ElGamal\n");
    printf("  -g <gen>    Generator for DH/ElGamal\n");
}

void interactive_mode();
char* process_crypto(const char* algo, const char* mode, const char* key, const char* input, int shift, int aParam, int bParam, int matrixSize, uint64_t prime, uint64_t generator);

int main(int argc, char* argv[]) {
    if (argc == 1) {
        interactive_mode();
        return 0;
    }

    char* algo = "caesar";
    char* mode = "encrypt";
    char* key = "";
    char* inputFile = NULL;
    char* outputFile = NULL;
    int shift = 3;
    int aParam = 1;
    int bParam = 0;
    int matrixSize = 2;
    uint64_t prime = 0;
    uint64_t generator = 0;

    int opt;
    while ((opt = getopt(argc, argv, "a:m:k:i:o:s:p:b:n:q:g:h")) != -1) {
        switch (opt) {
            case 'a': algo = optarg; break;
            case 'm': mode = optarg; break;
            case 'k': key = optarg; break;
            case 'i': inputFile = optarg; break;
            case 'o': outputFile = optarg; break;
            case 's': shift = atoi(optarg); break;
            case 'p': aParam = atoi(optarg); break;
            case 'b': bParam = atoi(optarg); break;
            case 'n': matrixSize = atoi(optarg); break;
            case 'q': prime = strtoull(optarg, NULL, 10); break;
            case 'g': generator = strtoull(optarg, NULL, 10); break;
            case 'h': print_usage(); return 0;
            default: print_usage(); return 1;
        }
    }

    char* input = NULL;
    if (inputFile) {
        size_t len;
        input = read_file(inputFile, &len);
        if (!input) {
            fprintf(stderr, "Error reading input file\n");
            return 1;
        }
    } else if (optind < argc) {
        input = strdup(argv[optind]);
    } else if (strcmp(mode, "keygen") != 0) {
        char buffer[4096];
        if (fgets(buffer, sizeof(buffer), stdin)) {
            buffer[strcspn(buffer, "\n")] = 0;
            input = strdup(buffer);
        } else {
            input = strdup("");
        }
    }

    char* output = process_crypto(algo, mode, key, input ? input : "", shift, aParam, bParam, matrixSize, prime, generator);

    if (!output) {
        fprintf(stderr, "Error processing %s in %s mode\n", algo, mode);
        if (input) free(input);
        return 1;
    }

    if (outputFile) {
        write_file(outputFile, output, strlen(output));
    } else {
        printf("%s\n", output);
    }

    if (input) free(input);
    free(output);
    return 0;
}

char* process_crypto(const char* algo, const char* mode, const char* key, const char* input, int shift, int aParam, int bParam, int matrixSize, uint64_t prime, uint64_t generator) {
    char* output = NULL;
    if (prime == 0) prime = 104729;
    if (generator == 0) generator = 2;

    if (strcmp(algo, "caesar") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = caesar_encrypt(input, shift);
        else output = caesar_decrypt(input, shift);
    } else if (strcmp(algo, "affine") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = affine_encrypt(input, aParam, bParam);
        else output = affine_decrypt(input, aParam, bParam);
    } else if (strcmp(algo, "vigenere") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = vigenere_encrypt(input, key);
        else output = vigenere_decrypt(input, key);
    } else if (strcmp(algo, "playfair") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = playfair_encrypt(input, key);
        else output = playfair_decrypt(input, key);
    } else if (strcmp(algo, "hill") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = hill_encrypt(input, key, matrixSize);
        else output = hill_decrypt(input, key, matrixSize);
    } else if (strcmp(algo, "rc4") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = rc4_encrypt(input, key);
        else output = rc4_decrypt(input, key);
    } else if (strcmp(algo, "des") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = des_encrypt(input, key);
        else output = des_decrypt(input, key);
    } else if (strcmp(algo, "aes") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = aes_encrypt(input, key);
        else output = aes_decrypt(input, key);
    } else if (strcmp(algo, "rc6") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = rc6_encrypt(input, key);
        else output = rc6_decrypt(input, key);
    } else if (strcmp(algo, "serpent") == 0) {
        if (strcmp(mode, "encrypt") == 0) output = serpent_encrypt(input, key);
        else output = serpent_decrypt(input, key);
    } else if (strcmp(algo, "md5") == 0) {
        output = md5_hash(input);
    } else if (strcmp(algo, "sha256") == 0) {
        output = sha256_hash(input);
    } else if (strcmp(algo, "dh") == 0) {
        if (strcmp(mode, "keygen") == 0) {
            uint64_t priv, pub;
            dh_generate_keys(prime, generator, &priv, &pub);
            output = (char*)malloc(128);
            sprintf(output, "Private: %lu\nPublic: %lu\n", priv, pub);
        } else if (strcmp(mode, "encrypt") == 0) {
            uint64_t otherPub = strtoull(key, NULL, 10);
            uint64_t priv, pub;
            dh_generate_keys(prime, generator, &priv, &pub);
            uint64_t secret = dh_compute_secret(prime, priv, otherPub);
            output = (char*)malloc(256);
            sprintf(output, "Private: %lu\nPublic: %lu\nShared Secret: %lu\n", priv, pub, secret);
        }
    } else if (strcmp(algo, "rsa") == 0) {
        if (strcmp(mode, "keygen") == 0) {
            uint64_t n, e, d;
            rsa_generate_keys(104729, 104723, &n, &e, &d); // Example primes
            output = (char*)malloc(256);
            sprintf(output, "Public Key (N): %lu\nPublic Key (E): %lu\nPrivate Key (D): %lu\nPrivate Key (N): %lu\n", n, e, d, n);
        } else if (strcmp(mode, "encrypt") == 0) {
            uint64_t e = 65537, n = strtoull(key, NULL, 10);
            int len;
            uint64_t* c = rsa_encrypt(input, e, n, &len);
            output = (char*)malloc(len * 20 + 1);
            output[0] = '\0';
            for (int i = 0; i < len; i++) {
                char tmp[24];
                sprintf(tmp, "%lu,", c[i]);
                strcat(output, tmp);
            }
            free(c);
        } else if (strcmp(mode, "decrypt") == 0) {
            uint64_t d = 0, n = 0; 
            sscanf(key, "%lu,%lu", &d, &n);
            int count = 0;
            for (int i = 0; input[i]; i++) if (input[i] == ',') count++;
            uint64_t* c = (uint64_t*)malloc(count * sizeof(uint64_t));
            char* input_copy = strdup(input);
            char* token = strtok(input_copy, ",");
            int idx = 0;
            while (token) {
                c[idx++] = strtoull(token, NULL, 10);
                token = strtok(NULL, ",");
            }
            output = rsa_decrypt(c, count, d, n);
            free(input_copy);
            free(c);
        }
    } else if (strcmp(algo, "elgamal") == 0) {
        if (strcmp(mode, "keygen") == 0) {
            uint64_t priv, pub;
            elgamal_generate_keys(prime, generator, &priv, &pub);
            output = (char*)malloc(128);
            sprintf(output, "Private: %lu\nPublic: %lu\n", priv, pub);
        } else if (strcmp(mode, "encrypt") == 0) {
            uint64_t pubKey = strtoull(key, NULL, 10);
            uint64_t *c1, *c2;
            int len;
            elgamal_encrypt(input, prime, generator, pubKey, &c1, &c2, &len);
            output = (char*)malloc(len * 40 + 1);
            output[0] = '\0';
            for (int i = 0; i < len; i++) {
                char tmp[48];
                sprintf(tmp, "%lu|%lu,", c1[i], c2[i]);
                strcat(output, tmp);
            }
            free(c1); free(c2);
        } else if (strcmp(mode, "decrypt") == 0) {
            uint64_t privKey = strtoull(key, NULL, 10);
            int count = 0;
            for (int i = 0; input[i]; i++) if (input[i] == ',') count++;
            uint64_t *c1 = (uint64_t*)malloc(count * sizeof(uint64_t));
            uint64_t *c2 = (uint64_t*)malloc(count * sizeof(uint64_t));
            char* input_copy = strdup(input);
            char* token = strtok(input_copy, ",");
            int idx = 0;
            while (token && idx < count) {
                sscanf(token, "%lu|%lu", &c1[idx], &c2[idx]);
                idx++;
                token = strtok(NULL, ",");
            }
            output = elgamal_decrypt(c1, c2, count, prime, privKey);
            free(input_copy);
            free(c1); free(c2);
        }
    }

    return output;
}

void interactive_mode() {
    int choice = 0;
    char input[4096] = {0};
    char filepath[1024] = {0};
    char* data = NULL;

    printf("=========================================\n");
    printf("        Crysys Interactive Menu          \n");
    printf("=========================================\n");
    printf("1. Encryption\n");
    printf("2. Decryption\n");
    printf("3. Cryptanalysis\n");
    printf("Choose operation (1-3): ");
    if (scanf("%d", &choice) != 1) return;
    
    // consume newline left by scanf
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }

    int input_type = 0;
    printf("\nInput from:\n1. Text\n2. File\nChoose input source (1-2): ");
    if (scanf("%d", &input_type) != 1) return;
    while ((c = getchar()) != '\n' && c != EOF) { }

    if (input_type == 2) {
        printf("Enter file path: ");
        if (fgets(filepath, sizeof(filepath), stdin)) {
            filepath[strcspn(filepath, "\n")] = 0;
            size_t len;
            data = read_file(filepath, &len);
            if (!data) {
                printf("Error reading file.\n");
                return;
            }
        }
    } else {
        printf("Enter Input Text: ");
        if (fgets(input, sizeof(input), stdin)) {
            input[strcspn(input, "\n")] = 0;
        }
        data = strdup(input);
    }

    if (choice == 3) {
        // Cryptanalysis
        int crypto_choice = 0;
        printf("\nCryptanalysis Options:\n");
        printf("1. Index of Coincidence (Indice de coïncidence)\n");
        printf("2. Probable Word Method (Vigenère)\n");
        printf("3. Frequency Analysis (Vigenère)\n");
        printf("Choose analysis method (1-3): ");
        if (scanf("%d", &crypto_choice) != 1) {
            free(data);
            return;
        }
        while ((c = getchar()) != '\n' && c != EOF) { }

        if (crypto_choice == 1) {
            double ic = calc_index_of_coincidence(data);
            printf("\n---> Index of Coincidence: %f\n\n", ic);
        } else if (crypto_choice == 2) {
            char pw[256];
            printf("Enter probable word: ");
            if (fgets(pw, sizeof(pw), stdin)) pw[strcspn(pw, "\n")] = 0;
            char* res = probable_word_vigenere(data, pw);
            printf("\n%s\n", res);
            free(res);
        } else if (crypto_choice == 3) {
            int kl = 0;
            printf("Enter estimated key length: ");
            if (scanf("%d", &kl) == 1) {
                char* res = freq_analysis_vigenere(data, kl);
                printf("\n---> Deduced Key (assuming French 'E'): %s\n\n", res);
                free(res);
            }
        }
    } else {
        // Encrypt or Decrypt
        char algo[32], key[256];
        char mode[32] = {0};
        strcpy(mode, (choice == 1) ? "encrypt" : "decrypt");

        printf("Enter Algorithm (e.g. aes, des, vigenere, etc): ");
        if (scanf("%31s", algo) != 1) { free(data); return; }
        while ((c = getchar()) != '\n' && c != EOF) { }

        printf("Enter Key / Shift / Params (press Enter if none): ");
        if (fgets(key, sizeof(key), stdin)) {
            key[strcspn(key, "\n")] = 0;
        }

        int shift = 3;
        if (strcmp(algo, "caesar") == 0 && strlen(key) > 0) shift = atoi(key);

        char* output = process_crypto(algo, mode, key, data, shift, 1, 0, 2, 0, 0);

        if (output) {
            printf("\n---> Result:\n%s\n\n", output);
            free(output);
        } else {
            printf("\n---> Error processing request.\n\n");
        }
    }

    free(data);
}
