#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "engine/core/utils.h"
#include "engine/classic/caesar.h"
#include "engine/classic/affine.h"
#include "engine/classic/vigenere.h"
#include "engine/classic/playfair.h"
#include "engine/classic/hill.h"
#include "engine/classic/cryptanalysis.h"
#include "engine/modern/aes.h"
#include "engine/modern/des.h"
#include "engine/modern/rc4.h"
#include "engine/modern/rc6.h"
#include "engine/modern/serpent.h"
#include "engine/modern/dh.h"
#include "engine/modern/rsa.h"
#include "engine/modern/elgamal.h"
#include "engine/hash/md5.h"
#include "engine/hash/sha256.h"

/* ═══════════════════════════════════════════════════════════════════
   Crysys 2.0 — Unified Cryptography Engine CLI
   Supports: caesar, affine, vigenere, playfair, hill (classic)
             aes, des, rc4, rc6, serpent (symmetric)
             rsa, dh, elgamal (asymmetric)
             md5, sha256 (hash)
             cryptanalysis (index of coincidence, frequency analysis)
   ═══════════════════════════════════════════════════════════════════ */

void print_usage() {
    printf("Crysys 2.0 — Unified Encryption Engine\n");
    printf("Usage: crysys_cli [options] <input text>\n\n");
    printf("Options:\n");
    printf("  -a <algo>   Algorithm:\n");
    printf("              classic: caesar, affine, vigenere, playfair, hill\n");
    printf("              modern:  aes, des, rc4, rc6, serpent\n");
    printf("              asymm:   rsa, dh, elgamal\n");
    printf("              hash:    md5, sha256\n");
    printf("              analysis: ic, freq_analysis, probable_word\n");
    printf("  -m <mode>   Mode: encrypt, decrypt, hash, keygen, analyze\n");
    printf("  -k <key>    Key for encryption/decryption\n");
    printf("  -i <file>   Input file\n");
    printf("  -o <file>   Output file\n");
    printf("  -s <shift>  Shift value for Caesar cipher (default: 3)\n");
    printf("  -p <param>  'a' parameter for Affine cipher\n");
    printf("  -b <param>  'b' parameter for Affine cipher\n");
    printf("  -n <size>   Matrix size for Hill cipher (2 or 3)\n");
    printf("  -q <prime>  Prime number for DH/ElGamal\n");
    printf("  -g <gen>    Generator for DH/ElGamal\n");
    printf("  -l <len>    Key length estimate for frequency analysis\n");
    printf("  -w <word>   Probable word for cryptanalysis\n");
    printf("  -h          Show this help\n");
}

char* process_crypto(const char* algo, const char* mode, const char* key,
                     const char* input, int shift, int aParam, int bParam,
                     int matrixSize, uint64_t prime, uint64_t generator,
                     int keyLen, const char* probableWord);
void interactive_mode();

int main(int argc, char* argv[]) {
    if (argc == 1) {
        interactive_mode();
        return 0;
    }

    char* algo         = "caesar";
    char* mode         = "encrypt";
    char* key          = "";
    char* inputFile    = NULL;
    char* outputFile   = NULL;
    char* probableWord = "";
    int   shift        = 3;
    int   aParam       = 1;
    int   bParam       = 0;
    int   matrixSize   = 2;
    int   keyLen       = 6;
    uint64_t prime     = 0;
    uint64_t generator = 0;

    int opt;
    while ((opt = getopt(argc, argv, "a:m:k:i:o:s:p:b:n:q:g:l:w:h")) != -1) {
        switch (opt) {
            case 'a': algo         = optarg; break;
            case 'm': mode         = optarg; break;
            case 'k': key          = optarg; break;
            case 'i': inputFile    = optarg; break;
            case 'o': outputFile   = optarg; break;
            case 's': shift        = atoi(optarg); break;
            case 'p': aParam       = atoi(optarg); break;
            case 'b': bParam       = atoi(optarg); break;
            case 'n': matrixSize   = atoi(optarg); break;
            case 'q': prime        = strtoull(optarg, NULL, 10); break;
            case 'g': generator    = strtoull(optarg, NULL, 10); break;
            case 'l': keyLen       = atoi(optarg); break;
            case 'w': probableWord = optarg; break;
            case 'h': print_usage(); return 0;
            default:  print_usage(); return 1;
        }
    }

    char* input = NULL;
    if (inputFile) {
        size_t len;
        input = read_file(inputFile, &len);
        if (!input) { fprintf(stderr, "Error reading input file\n"); return 1; }
    } else if (optind < argc) {
        input = strdup(argv[optind]);
    } else if (strcmp(mode, "keygen") != 0) {
        char buffer[4096];
        if (fgets(buffer, sizeof(buffer), stdin)) {
            buffer[strcspn(buffer, "\r\n")] = 0;
            input = strdup(buffer);
        } else {
            input = strdup("");
        }
    }

    char* output = process_crypto(algo, mode, key, input ? input : "",
                                  shift, aParam, bParam, matrixSize,
                                  prime, generator, keyLen, probableWord);

    if (!output) {
        fprintf(stderr, "Error processing '%s' in '%s' mode\n", algo, mode);
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

static int estimate_vigenere_key_length(const char* ciphertext) {
    char clean_ct[4096] = {0};
    int len = 0;
    for(int i = 0; ciphertext[i]; i++){
        if (((ciphertext[i] >= 'a' && ciphertext[i] <= 'z') || 
             (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z')) && len < 4095) {
            clean_ct[len++] = (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') ? (ciphertext[i] - 'a' + 'A') : ciphertext[i];
        }
    }
    if (len < 10) return 1;
    
    int best_len = 1;
    double best_ic_diff = 999.0;
    
    for (int k = 1; k <= 15 && k < len / 2; k++) {
        double avg_ic = 0.0;
        for (int col = 0; col < k; col++) {
            int col_counts[26] = {0};
            int col_total = 0;
            for (int i = col; i < len; i += k) {
                col_counts[clean_ct[i] - 'A']++;
                col_total++;
            }
            if (col_total > 1) {
                double col_ic = 0.0;
                for (int c = 0; c < 26; c++) {
                    col_ic += (double)(col_counts[c] * (col_counts[c] - 1));
                }
                col_ic /= (double)(col_total * (col_total - 1));
                avg_ic += col_ic;
            }
        }
        avg_ic /= k;
        double diff = (avg_ic - 0.0667) < 0 ? -(avg_ic - 0.0667) : (avg_ic - 0.0667);
        if (diff < best_ic_diff) {
            best_ic_diff = diff;
            best_len = k;
        }
    }
    return best_len;
}

char* process_crypto(const char* algo, const char* mode, const char* key,
                     const char* input, int shift, int aParam, int bParam,
                     int matrixSize, uint64_t prime, uint64_t generator,
                     int keyLen, const char* probableWord) {
    char* output = NULL;
    if (prime     == 0) prime     = 104729;
    if (generator == 0) generator = 2;

    /* ── Classic ciphers ─────────────────────────────────────────── */
    if (strcmp(algo, "caesar") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? caesar_encrypt(input, shift)
            : caesar_decrypt(input, shift);

    } else if (strcmp(algo, "affine") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? affine_encrypt(input, aParam, bParam)
            : affine_decrypt(input, aParam, bParam);

    } else if (strcmp(algo, "vigenere") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? vigenere_encrypt(input, key)
            : vigenere_decrypt(input, key);

    } else if (strcmp(algo, "playfair") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? playfair_encrypt(input, key)
            : playfair_decrypt(input, key);

    } else if (strcmp(algo, "hill") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? hill_encrypt(input, key, matrixSize)
            : hill_decrypt(input, key, matrixSize);

    /* ── Symmetric (modern) ──────────────────────────────────────── */
    } else if (strcmp(algo, "rc4") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? rc4_encrypt(input, key)
            : rc4_decrypt(input, key);

    } else if (strcmp(algo, "des") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? des_encrypt(input, key)
            : des_decrypt(input, key);

    } else if (strcmp(algo, "aes") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? aes_encrypt(input, key)
            : aes_decrypt(input, key);

    } else if (strcmp(algo, "rc6") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? rc6_encrypt(input, key)
            : rc6_decrypt(input, key);

    } else if (strcmp(algo, "serpent") == 0) {
        output = (strcmp(mode, "encrypt") == 0)
            ? serpent_encrypt(input, key)
            : serpent_decrypt(input, key);

    /* ── Hash ────────────────────────────────────────────────────── */
    } else if (strcmp(algo, "md5") == 0) {
        output = md5_hash(input);

    } else if (strcmp(algo, "sha256") == 0) {
        output = sha256_hash(input);

    /* ── Cryptanalysis ───────────────────────────────────────────── */
    } else if (strcmp(algo, "ic") == 0) {
        double ic = calc_index_of_coincidence(input);
        const char* possible_algo = (ic > 0.055) ? "Caesar / Affine Cipher (Monoalphabetic)" : "Vigenère Cipher (Polyalphabetic)";
        output = (char*)malloc(512);
        if (output) {
            sprintf(output, 
                "INDEX OF COINCIDENCE: %.6f\n"
                "Possible Algorithm  : %s\n\n"
                "Interpretation:\n"
                "  - English Plaintext: ~0.0667\n"
                "  - Monoalphabetic (Caesar/Affine): ~0.0667\n"
                "  - Polyalphabetic (Vigenere): ~0.0385 to 0.0450\n\n"
                "Verdict:\n"
                "  %s",
                ic, possible_algo,
                (ic > 0.055) ? "High IC: Monoalphabetic structure detected. Key size is likely 1." 
                             : "Low IC: Polyalphabetic/Vigenere structure detected. Key size is likely > 1."
            );
        }

    } else if (strcmp(algo, "probable_word") == 0) {
        output = probable_word_vigenere(input, probableWord);

    } else if (strcmp(algo, "freq_analysis") == 0) {
        int target_len = keyLen;
        int auto_estimated = 0;
        if (target_len <= 0) {
            target_len = estimate_vigenere_key_length(input);
            auto_estimated = 1;
        }
        char* guessed_key = freq_analysis_vigenere(input, target_len);
        char* decrypted_text = vigenere_decrypt(input, guessed_key);
        output = (char*)malloc(strlen(guessed_key) + strlen(decrypted_text) + 512);
        if (output) {
            sprintf(output, 
                "AUTOMATED CRYPTANALYSIS RESULTS:\n"
                "-----------------------------------\n"
                "Possible Algorithm : Vigenère Cipher\n"
                "Estimated Key Size : %d %s\n"
                "Estimated Key      : %s\n\n"
                "Decrypted Plaintext:\n%s\n\n"
                "Methodology:\n"
                "  1. Estimated key length using Index of Coincidence.\n"
                "  2. Performed frequency analysis assuming 'E' is\n"
                "     the most frequent character in each subgroup.\n"
                "  3. Decrypted ciphertext with estimated key.",
                target_len, auto_estimated ? "(Auto-detected)" : "(User-specified)",
                guessed_key, decrypted_text
            );
        }
        free(guessed_key);
        free(decrypted_text);

    /* ── Asymmetric: DH ─────────────────────────────────────────── */
    } else if (strcmp(algo, "dh") == 0) {
        if (strcmp(mode, "keygen") == 0) {
            uint64_t priv, pub;
            dh_generate_keys(prime, generator, &priv, &pub);
            output = (char*)malloc(128);
            if (output) sprintf(output, "Private: %llu\nPublic: %llu\n",
                                (unsigned long long)priv, (unsigned long long)pub);
        } else if (strcmp(mode, "encrypt") == 0) {
            uint64_t otherPub = strtoull(key, NULL, 10);
            uint64_t priv, pub;
            dh_generate_keys(prime, generator, &priv, &pub);
            uint64_t secret = dh_compute_secret(prime, priv, otherPub);
            output = (char*)malloc(256);
            if (output) sprintf(output,
                "Private: %llu\nPublic: %llu\nShared Secret: %llu\n",
                (unsigned long long)priv,
                (unsigned long long)pub,
                (unsigned long long)secret);
        }

    /* ── Asymmetric: RSA ────────────────────────────────────────── */
    } else if (strcmp(algo, "rsa") == 0) {
        if (strcmp(mode, "keygen") == 0) {
            uint64_t n, e, d;
            rsa_generate_keys(32749, 32771, &n, &e, &d);
            output = (char*)malloc(512);
            if (output) sprintf(output,
                "Public Key (E,N) : %llu,%llu\n"
                "Private Key (D,N): %llu,%llu\n"
                "Tip: Copy-paste the entire comma-separated key above into the key field.",
                (unsigned long long)e, (unsigned long long)n,
                (unsigned long long)d, (unsigned long long)n);
        } else if (strcmp(mode, "encrypt") == 0) {
            uint64_t e = 65537, n = 0;
            if (strchr(key, ',')) {
                sscanf(key, "%llu,%llu", (unsigned long long*)&e, (unsigned long long*)&n);
            } else {
                n = strtoull(key, NULL, 10);
            }
            int len;
            uint64_t* c = rsa_encrypt(input, e, n, &len);
            if (c) {
                output = (char*)malloc(len * 22 + 1);
                if (output) {
                    output[0] = '\0';
                    for (int i = 0; i < len; i++) {
                        char tmp[24];
                        sprintf(tmp, "%llu,", (unsigned long long)c[i]);
                        strcat(output, tmp);
                    }
                }
                free(c);
            }
        } else if (strcmp(mode, "decrypt") == 0) {
            uint64_t d = 0, n = 0;
            if (strchr(key, ',')) {
                sscanf(key, "%llu,%llu", (unsigned long long*)&d, (unsigned long long*)&n);
            } else {
                d = strtoull(key, NULL, 10);
            }
            
            if (n == 0) {
                output = strdup("Error: Private key must be in format D,N (e.g. 10242277433,10968988637)");
            } else {
                int count = 0;
                for (int i = 0; input[i]; i++) if (input[i] == ',') count++;
                if (count > 0) {
                    uint64_t* c = (uint64_t*)malloc(count * sizeof(uint64_t));
                    char* input_copy = strdup(input);
                    if (c && input_copy) {
                        char* token = strtok(input_copy, ",");
                        int idx = 0;
                        while (token && idx < count) {
                            c[idx++] = strtoull(token, NULL, 10);
                            token = strtok(NULL, ",");
                        }
                        output = rsa_decrypt(c, count, d, n);
                    }
                    if (c) free(c);
                    if (input_copy) free(input_copy);
                }
            }
        }

    /* ── Asymmetric: ElGamal ────────────────────────────────────── */
    } else if (strcmp(algo, "elgamal") == 0) {
        if (strcmp(mode, "keygen") == 0) {
            uint64_t priv, pub;
            elgamal_generate_keys(prime, generator, &priv, &pub);
            output = (char*)malloc(128);
            if (output) sprintf(output, "Private: %llu\nPublic: %llu\n",
                                (unsigned long long)priv, (unsigned long long)pub);
        } else if (strcmp(mode, "encrypt") == 0) {
            uint64_t pubKey = strtoull(key, NULL, 10);
            uint64_t *c1, *c2;
            int len;
            elgamal_encrypt(input, prime, generator, pubKey, &c1, &c2, &len);
            if (c1 && c2) {
                output = (char*)malloc(len * 42 + 1);
                if (output) {
                    output[0] = '\0';
                    for (int i = 0; i < len; i++) {
                        char tmp[50];
                        sprintf(tmp, "%llu|%llu,",
                                (unsigned long long)c1[i], (unsigned long long)c2[i]);
                        strcat(output, tmp);
                    }
                }
                free(c1); free(c2);
            }
        } else if (strcmp(mode, "decrypt") == 0) {
            uint64_t privKey = strtoull(key, NULL, 10);
            int count = 0;
            for (int i = 0; input[i]; i++) if (input[i] == ',') count++;
            if (count > 0) {
                uint64_t *c1 = (uint64_t*)malloc(count * sizeof(uint64_t));
                uint64_t *c2 = (uint64_t*)malloc(count * sizeof(uint64_t));
                char* input_copy = strdup(input);
                if (c1 && c2 && input_copy) {
                    char* token = strtok(input_copy, ",");
                    int idx = 0;
                    while (token && idx < count) {
                        sscanf(token, "%llu|%llu",
                               (unsigned long long*)&c1[idx],
                               (unsigned long long*)&c2[idx]);
                        idx++;
                        token = strtok(NULL, ",");
                    }
                    output = elgamal_decrypt(c1, c2, count, prime, privKey);
                }
                if (c1) free(c1);
                if (c2) free(c2);
                if (input_copy) free(input_copy);
            }
        }
    }

    return output;
}

/* ═══════════════════════════════════════════════════════════════════
   Interactive mode — for direct terminal use
   ═══════════════════════════════════════════════════════════════════ */
void interactive_mode() {
    int choice = 0;
    char input[4096] = {0};
    char filepath[1024] = {0};
    char* data = NULL;

    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║     Crysys 2.0 — Interactive CLI      ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");
    printf("1. Encrypt\n2. Decrypt\n3. Hash\n4. Cryptanalysis\n");
    printf("\nChoose operation (1-4): ");
    if (scanf("%d", &choice) != 1) return;

    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int input_type = 0;
    printf("\nInput from:\n1. Text\n2. File\nChoose (1-2): ");
    if (scanf("%d", &input_type) != 1) return;
    while ((c = getchar()) != '\n' && c != EOF) {}

    if (input_type == 2) {
        printf("Enter file path: ");
        if (fgets(filepath, sizeof(filepath), stdin)) {
            filepath[strcspn(filepath, "\n")] = 0;
            size_t len;
            data = read_file(filepath, &len);
            if (!data) { printf("Error reading file.\n"); return; }
        }
    } else {
        printf("Enter text: ");
        if (fgets(input, sizeof(input), stdin)) {
            input[strcspn(input, "\n")] = 0;
        }
        data = strdup(input);
    }

    if (choice == 4) {
        printf("\nCryptanalysis:\n1. Index of Coincidence\n2. Probable Word\n3. Frequency Analysis\nChoose (1-3): ");
        int cc = 0;
        if (scanf("%d", &cc) != 1) { free(data); return; }
        while ((c = getchar()) != '\n' && c != EOF) {}

        if (cc == 1) {
            double ic = calc_index_of_coincidence(data);
            printf("\n---> Index of Coincidence: %.6f\n\n", ic);
        } else if (cc == 2) {
            char pw[256];
            printf("Probable word: ");
            if (fgets(pw, sizeof(pw), stdin)) pw[strcspn(pw, "\n")] = 0;
            char* res = probable_word_vigenere(data, pw);
            printf("\n%s\n", res); free(res);
        } else if (cc == 3) {
            int kl = 0;
            printf("Estimated key length: ");
            if (scanf("%d", &kl) == 1) {
                char* res = freq_analysis_vigenere(data, kl);
                printf("\n---> Deduced Key: %s\n\n", res); free(res);
            }
        }
    } else if (choice == 3) {
        char algo[32];
        printf("Hash algorithm (md5/sha256): ");
        if (scanf("%31s", algo) != 1) { free(data); return; }
        char* result = process_crypto(algo, "hash", "", data, 3, 1, 0, 2, 0, 0, 6, "");
        if (result) { printf("\n---> Hash: %s\n\n", result); free(result); }
    } else {
        char algo[32], key[256];
        char mode[32] = {0};
        strcpy(mode, (choice == 1) ? "encrypt" : "decrypt");

        printf("Algorithm (caesar/affine/vigenere/playfair/hill/aes/des/rc4/rc6/serpent/rsa/dh/elgamal): ");
        if (scanf("%31s", algo) != 1) { free(data); return; }
        while ((c = getchar()) != '\n' && c != EOF) {}

        printf("Key / Params (Enter if none): ");
        if (fgets(key, sizeof(key), stdin)) key[strcspn(key, "\n")] = 0;

        int shift = 3;
        if (strcmp(algo, "caesar") == 0 && strlen(key) > 0) shift = atoi(key);

        char* result = process_crypto(algo, mode, key, data, shift, 1, 0, 2, 0, 0, 6, "");
        if (result) { printf("\n---> Result:\n%s\n\n", result); free(result); }
        else printf("\n---> Error processing request.\n\n");
    }

    free(data);
}
