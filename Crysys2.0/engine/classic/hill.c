#include "hill.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>

static int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return abs(a);
}

static int modInverse(int a, int m) {
    a = ((a % m) + m) % m;
    for (int i = 1; i < m; i++) {
        if ((a * i) % m == 1) {
            return i;
        }
    }
    return 1;
}

static int matrixDeterminant(int** m, int n) {
    if (n == 1) {
        return m[0][0];
    }
    if (n == 2) {
        return m[0][0] * m[1][1] - m[0][1] * m[1][0];
    }
    
    int det = 0;
    int** sub = (int**)malloc((n - 1) * sizeof(int*));
    for (int i = 0; i < n - 1; i++) sub[i] = (int*)malloc((n - 1) * sizeof(int));
    
    for (int i = 0; i < n; i++) {
        for (int j = 1; j < n; j++) {
            for (int k = 0; k < n - 1; k++) {
                if (k >= i) {
                    sub[j-1][k] = m[j][k+1];
                } else {
                    sub[j-1][k] = m[j][k];
                }
            }
        }
        int sign = (i % 2 == 0) ? 1 : -1;
        det += sign * m[0][i] * matrixDeterminant(sub, n - 1);
    }
    
    for (int i = 0; i < n - 1; i++) free(sub[i]);
    free(sub);
    return det;
}

static int** getInverseMatrix(int** m, int size) {
    int det = matrixDeterminant(m, size);
    det = ((det % 26) + 26) % 26;
    int detInv = modInverse(det, 26);
    
    int** adjugate = (int**)malloc(size * sizeof(int*));
    int** inv = (int**)malloc(size * sizeof(int*));
    for (int i = 0; i < size; i++) {
        adjugate[i] = (int*)malloc(size * sizeof(int));
        inv[i] = (int*)malloc(size * sizeof(int));
    }
    
    int** sub = (int**)malloc((size - 1) * sizeof(int*));
    for (int i = 0; i < size - 1; i++) sub[i] = (int*)malloc((size - 1) * sizeof(int));
    
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            int row = 0, col = 0;
            for (int x = 0; x < size; x++) {
                for (int y = 0; y < size; y++) {
                    if (x != i && y != j) {
                        sub[row][col] = m[x][y];
                        col++;
                        if (col == size - 1) {
                            col = 0;
                            row++;
                        }
                    }
                }
            }
            int cofactor = ((i + j) % 2 == 0 ? 1 : -1) * matrixDeterminant(sub, size - 1);
            adjugate[i][j] = ((cofactor % 26) + 26) % 26;
        }
    }
    
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            inv[i][j] = (adjugate[j][i] * detInv) % 26;
        }
    }
    
    for (int i = 0; i < size; i++) free(adjugate[i]);
    free(adjugate);
    for (int i = 0; i < size - 1; i++) free(sub[i]);
    free(sub);
    
    return inv;
}

static void matrixMultiply(int** m, int* vec, int* res, int size) {
    for (int i = 0; i < size; i++) {
        int sum = 0;
        for (int j = 0; j < size; j++) {
            sum += m[i][j] * vec[j];
        }
        res[i] = sum % 26;
    }
}

char* hill_encrypt(const char* plaintext, const char* key, int size) {
    if (!key || strlen(key) == 0) return NULL;
    if (!plaintext || strlen(plaintext) == 0) return strdup("");
    if (size != 2 && size != 3) return NULL;
    
    int hasDigits = 0;
    for (size_t i = 0; i < strlen(key); i++) {
        if (isdigit((unsigned char)key[i])) {
            hasDigits = 1;
            break;
        }
    }
    
    int* keyNumbers = (int*)malloc((strlen(key) + 16) * sizeof(int));
    int k_idx = 0;
    
    if (hasDigits) {
        char* keyCopy = strdup(key);
        char* token = strtok(keyCopy, " ,;");
        while (token != NULL) {
            char* endptr;
            long val = strtol(token, &endptr, 10);
            if (endptr != token) {
                keyNumbers[k_idx++] = (int)val;
            }
            token = strtok(NULL, " ,;");
        }
        free(keyCopy);
    } else {
        for (size_t i = 0; i < strlen(key); i++) {
            char c = toupper((unsigned char)key[i]);
            if (c >= 'A' && c <= 'Z') {
                int num = c - 'A';
                if (c == 'J') num = 8; // 'I'
                keyNumbers[k_idx++] = num;
            }
        }
    }
    
    if (k_idx < size * size) {
        free(keyNumbers);
        return NULL;
    }
    
    int** matrix = (int**)malloc(size * sizeof(int*));
    for (int i = 0; i < size; i++) {
        matrix[i] = (int*)malloc(size * sizeof(int));
        for (int j = 0; j < size; j++) {
            matrix[i][j] = keyNumbers[i * size + j] % 26;
        }
    }
    free(keyNumbers);
    
    int det = matrixDeterminant(matrix, size);
    det = ((det % 26) + 26) % 26;
    if (gcd(det, 26) != 1) {
        for (int i = 0; i < size; i++) free(matrix[i]);
        free(matrix);
        return NULL;
    }
    
    size_t len = strlen(plaintext);
    char* chars = (char*)malloc(len + size + 1);
    int c_idx = 0;
    for (size_t i = 0; i < len; i++) {
        char c = toupper(plaintext[i]);
        if (c == 'J') c = 'I';
        if (c >= 'A' && c <= 'Z') {
            chars[c_idx++] = c;
        }
    }
    while (c_idx % size != 0) {
        chars[c_idx++] = 'X';
    }
    chars[c_idx] = '\0';
    
    char* result = (char*)malloc(c_idx + 1);
    int* vec = (int*)malloc(size * sizeof(int));
    int* enc_vec = (int*)malloc(size * sizeof(int));
    
    for (int i = 0; i < c_idx; i += size) {
        for (int j = 0; j < size; j++) {
            vec[j] = chars[i+j] - 'A';
        }
        matrixMultiply(matrix, vec, enc_vec, size);
        for (int j = 0; j < size; j++) {
            result[i+j] = enc_vec[j] + 'A';
        }
    }
    result[c_idx] = '\0';
    
    free(chars);
    free(vec);
    free(enc_vec);
    for (int i = 0; i < size; i++) free(matrix[i]);
    free(matrix);
    
    return result;
}

char* hill_decrypt(const char* ciphertext, const char* key, int size) {
    if (!key || strlen(key) == 0) return NULL;
    if (!ciphertext || strlen(ciphertext) == 0) return strdup("");
    if (size != 2 && size != 3) return NULL;
    size_t len = strlen(ciphertext);
    if (len % size != 0) return NULL;
    
    int hasDigits = 0;
    for (size_t i = 0; i < strlen(key); i++) {
        if (isdigit((unsigned char)key[i])) {
            hasDigits = 1;
            break;
        }
    }
    
    int* keyNumbers = (int*)malloc((strlen(key) + 16) * sizeof(int));
    int k_idx = 0;
    
    if (hasDigits) {
        char* keyCopy = strdup(key);
        char* token = strtok(keyCopy, " ,;");
        while (token != NULL) {
            char* endptr;
            long val = strtol(token, &endptr, 10);
            if (endptr != token) {
                keyNumbers[k_idx++] = (int)val;
            }
            token = strtok(NULL, " ,;");
        }
        free(keyCopy);
    } else {
        for (size_t i = 0; i < strlen(key); i++) {
            char c = toupper((unsigned char)key[i]);
            if (c >= 'A' && c <= 'Z') {
                int num = c - 'A';
                if (c == 'J') num = 8;
                keyNumbers[k_idx++] = num;
            }
        }
    }
    
    if (k_idx < size * size) {
        free(keyNumbers);
        return NULL;
    }
    
    int** matrix = (int**)malloc(size * sizeof(int*));
    for (int i = 0; i < size; i++) {
        matrix[i] = (int*)malloc(size * sizeof(int));
        for (int j = 0; j < size; j++) {
            matrix[i][j] = keyNumbers[i * size + j] % 26;
        }
    }
    free(keyNumbers);
    
    int det = matrixDeterminant(matrix, size);
    det = ((det % 26) + 26) % 26;
    if (gcd(det, 26) != 1) {
        for (int i = 0; i < size; i++) free(matrix[i]);
        free(matrix);
        return NULL;
    }
    
    int** invMatrix = getInverseMatrix(matrix, size);
    
    char* result = (char*)malloc(len + 1);
    int* vec = (int*)malloc(size * sizeof(int));
    int* dec_vec = (int*)malloc(size * sizeof(int));
    
    for (size_t i = 0; i < len; i += size) {
        for (int j = 0; j < size; j++) {
            vec[j] = ciphertext[i+j] - 'A';
        }
        matrixMultiply(invMatrix, vec, dec_vec, size);
        for (int j = 0; j < size; j++) {
            result[i+j] = dec_vec[j] + 'A';
        }
    }
    result[len] = '\0';
    
    free(vec);
    free(dec_vec);
    for (int i = 0; i < size; i++) {
        free(matrix[i]);
        free(invMatrix[i]);
    }
    free(matrix);
    free(invMatrix);
    
    return result;
}
