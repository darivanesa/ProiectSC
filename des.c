#include "DES.h"
#include <stdio.h>
#include <stdint.h>

#define KEY_SIZE 8


void initialPermutation(uint8_t *block) {
    static const uint8_t ipTable[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    uint8_t temp[8];
    memset(temp, 0, 8);

    for (int i = 0; i < 64; ++i) {
        uint8_t bit = block[(ipTable[i] - 1) / 8] >> (7 - ((ipTable[i] - 1) % 8)) & 1;
        temp[i / 8] |= bit << (7 - (i % 8));
    }

    memcpy(block, temp, 8);
}

void expansion(uint8_t *rightHalf, uint8_t *expanded) {
    static const uint8_t expansionTable[48] = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };

    for (int i = 0; i < 48; ++i) {
        uint8_t bit = rightHalf[(expansionTable[i] - 1) / 8] >> (7 - ((expansionTable[i] - 1) % 8)) & 1;
        expanded[i / 8] |= bit << (7 - (i % 8));
    }
}

void substitution(uint8_t *input, uint8_t *output) {
    static const uint8_t sBox[8][4][16] = {
    // S-box 1
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    // S-box 2
    {
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    // S-box 3
    {
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},

    },
    // S-box 4
    {
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    // S-box 5
    {
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    // S-box 6
    {
       {12,  1, 10, 15,  9,  2,   6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,   9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8,  12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5,  15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    // S-box 7
    {
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    // S-box 8
    {
       { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
        { 8, 15,  2,  9,  4,  1, 13, 14,  0,  7, 11, 10,  6, 12,  5,  3},
        {12, 10,  0, 15, 14,  4,  7,  9,  2,  3,  6,  1, 13,  5, 11,  8}
    }
};

    for (int i = 0; i < 8; ++i) {
        int row = ((input[i] & 0x80) >> 4) | ((input[i] & 0x04) >> 2);
        int col = (input[i] & 0x78) >> 3;
        output[i] = sBox[i][row][col];
    }
}

void finalPermutation(uint8_t *block) {
    static const uint8_t fpTable[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

    uint8_t temp[8];
    memset(temp, 0, 8);

    for (int i = 0; i < 64; ++i) {
        uint8_t bit = block[(fpTable[i] - 1) / 8] >> (7 - ((fpTable[i] - 1) % 8)) & 1;
        temp[i / 8] |= bit << (7 - (i % 8));
    }

    memcpy(block, temp, 8);
}


void permutation(uint8_t *block, const uint8_t *permutationTable, size_t tableSize) {
    uint8_t *temp = malloc(tableSize * sizeof(uint8_t));
    if (temp == NULL) {
        return;
    }

    for (size_t i = 0; i < tableSize; ++i) {
        temp[i] = block[i];
    }

    memcpy(block, temp, tableSize);

    free(temp);
}

void generateRoundKeys(uint8_t *key, uint8_t roundKeys[16][48]) {
    static const uint8_t pc1[] = {57, 49, 41, 33, 25, 17, 9,
                                   1, 58, 50, 42, 34, 26, 18,
                                   10, 2, 59, 51, 43, 35, 27,
                                   19, 11, 3, 60, 52, 44, 36,
                                   63, 55, 47, 39, 31, 23, 15,
                                   7, 62, 54, 46, 38, 30, 22,
                                   14, 6, 61, 53, 45, 37, 29,
                                   21, 13, 5, 28, 20, 12, 4};

    static const uint8_t pc2[] = {14, 17, 11, 24, 1, 5, 3, 28,
                                   15, 6, 21, 10, 23, 19, 12, 4,
                                   26, 8, 16, 7, 27, 20, 13, 2,
                                   41, 52, 31, 37, 47, 55, 30, 40,
                                   51, 45, 33, 48, 44, 49, 39, 56,
                                   34, 53, 46, 42, 50, 36, 29, 32};

    static const uint8_t shiftBits[] = {1, 1, 2, 2, 2, 2, 2, 2,
                                         1, 2, 2, 2, 2, 2, 2, 1};

    uint8_t permutedKey[56];
    for (int i = 0; i < 56; ++i) {
        permutedKey[i] = key[pc1[i] - 1];
    }

    uint8_t left[28], right[28];

    for (int i = 0; i < 28; ++i) {
        left[i] = permutedKey[i];
        right[i] = permutedKey[i + 28];
    }

    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < shiftBits[i]; ++j) {
            uint8_t temp = left[0];
            for (int k = 0; k < 27; ++k) {
                left[k] = left[k + 1];
                right[k] = right[k + 1];
            }
            left[27] = temp;
            right[27] = right[0];
        }

        uint8_t combinedKey[56];
        memcpy(combinedKey, left, 28);
        memcpy(combinedKey + 28, right, 28);
        for (int j = 0; j < 48; ++j) {
            roundKeys[i][j] = combinedKey[pc2[j] - 1];
        }
    }
}


void encryptBlock(uint8_t *block, uint8_t *key) {
    initialPermutation(block);

    uint8_t roundKeys[16][48];
    generateRoundKeys(key, roundKeys);

    for (int round = 0; round < 16; ++round) {
        uint8_t tempBlock[64];
        memcpy(tempBlock, block, 64);

        uint8_t expandedRight[48];
        expansion(tempBlock + 32, expandedRight);

        for (int i = 0; i < 48; ++i) {
            tempBlock[32 + i] = expandedRight[i] ^ roundKeys[round][i];
        }
        substitution(tempBlock + 32, tempBlock + 32);
        permutation(tempBlock + 32, NULL, 32);

        for (int i = 0; i < 32; ++i) {
            tempBlock[i] ^= tempBlock[32 + i];
        }

        memcpy(tempBlock, block + 32, 32);

        memcpy(block, tempBlock, 64);
    }

    finalPermutation(block);
}

void decryptBlock(uint8_t *block, uint8_t *key) {
    initialPermutation(block);

    uint8_t roundKeys[16][48];
    generateRoundKeys(key, roundKeys);

    for (int round = 15; round >= 0; --round) {
        uint8_t tempBlock[64];
        memcpy(tempBlock, block, 64);

        uint8_t expandedRight[48];
        expansion(tempBlock + 32, expandedRight);

        for (int i = 0; i < 48; ++i) {
            tempBlock[32 + i] = expandedRight[i] ^ roundKeys[round][i];
        }
        substitution(tempBlock + 32, tempBlock + 32);
        permutation(tempBlock + 32, NULL, 32);

        for (int i = 0; i < 32; ++i) {
            tempBlock[i] ^= tempBlock[32 + i];
        }

        memcpy(tempBlock, block + 32, 32);

        memcpy(block, tempBlock, 64);
    }

    finalPermutation(block);
}

void DESEncrypt(const char *inputFileName, const char *outputFileName, const char *DESKeyFileName) {
    uint8_t DESKey[KEY_SIZE];
    FILE *DESKeyFile = fopen(DESKeyFileName, "rb");
    if (DESKeyFile == NULL) {
        printf("Nu s-a putut deschide fisierul pentru cheia DES!\n");
        return;
    }

    if (fread(DESKey, sizeof(uint8_t), KEY_SIZE, DESKeyFile) != KEY_SIZE) {
        printf("Eroare la citirea cheii DES din fisier!\n");
        fclose(DESKeyFile);
        return;
    }

    fclose(DESKeyFile);

    FILE *inputFile = fopen(inputFileName, "rb");
    if (inputFile == NULL) {
        printf("Nu s-a putut deschide fisierul de intrare!\n");
        return;
    }

    FILE *outputFile = fopen(outputFileName, "wb");
    if (outputFile == NULL) {
        printf("Nu s-a putut deschide fisierul de iesire!\n");
        fclose(inputFile);
        return;
    }

    uint8_t block[8];
    while (fread(block, sizeof(uint8_t), 8, inputFile) == 8) {
        encryptBlock(block, DESKey);
        fwrite(block, sizeof(uint8_t), 8, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);

    printf("Criptare finalizata!\n");
}

void DESDecrypt(const char *inputFileName, const char *outputFileName, const char *DESKeyFileName) {
    uint8_t DESKey[KEY_SIZE];
    FILE *DESKeyFile = fopen(DESKeyFileName, "rb");
    if (DESKeyFile == NULL) {
        printf("Nu s-a putut deschide fisierul pentru cheia DES!\n");
        return;
    }

    if (fread(DESKey, sizeof(uint8_t), KEY_SIZE, DESKeyFile) != KEY_SIZE) {
        printf("Eroare la citirea cheii DES din fisier!\n");
        fclose(DESKeyFile);
        return;
    }

    fclose(DESKeyFile);

    FILE *inputFile = fopen(inputFileName, "rb");
    if (inputFile == NULL) {
        printf("Nu s-a putut deschide fisierul de intrare!\n");
        return;
    }

    FILE *outputFile = fopen(outputFileName, "wb");
    if (outputFile == NULL) {
        printf("Nu s-a putut deschide fisierul de iesire!\n");
        fclose(inputFile);
        return;
    }

    uint8_t block[8];
    while (fread(block, sizeof(uint8_t), 8, inputFile) == 8) {
        decryptBlock(block, DESKey);
        fwrite(block, sizeof(uint8_t), 8, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);

    printf("Decriptare finalizata!\n");
}


