#include "AES.h"
#include "sBox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES_ROUNDS 10
#define KEY_SIZE 16

static const uint8_t shiftRowTab[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x05, 0x06, 0x07, 0x04,
    0x0a, 0x0b, 0x08, 0x09,
    0x0d, 0x0e, 0x0f, 0x0c
};

static const uint8_t shiftRowTabInv[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x07, 0x04, 0x05, 0x06,
    0x0a, 0x0b, 0x08, 0x09,
    0x0d, 0x0e, 0x0f, 0x0c
};

void rotWord(uint8_t *word) {
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

void subWord(uint8_t *word) {
    for (int i = 0; i < 4; ++i) {
        word[i] = sBox[word[i]];
    }
}

uint8_t rcon(int round) {
    if (round == 1) return 0x01;
    if (round == 2) return 0x02;
    if (round == 3) return 0x04;
    if (round == 4) return 0x08;
    if (round == 5) return 0x10;
    if (round == 6) return 0x20;
    if (round == 7) return 0x40;
    if (round == 8) return 0x80;
    if (round == 9) return 0x1b;
    if (round == 10) return 0x36;
    return 0x00;
}

void keyExpansion(const uint8_t *key, uint8_t *roundKeys) {
    int bytesGenerated = 0;
    int currentRound = 1;

    memcpy(roundKeys, key, KEY_SIZE);
    bytesGenerated += KEY_SIZE;
    roundKeys += KEY_SIZE;

    uint8_t temp[4];

    while (bytesGenerated < (AES_ROUNDS + 1) * AES_BLOCK_SIZE) {
        memcpy(temp, roundKeys - 4, 4);

        if (bytesGenerated % KEY_SIZE == 0) {
            rotWord(temp);
            subWord(temp);
            temp[0] ^= rcon(currentRound);
            currentRound++;
        }

        for (int i = 0; i < 4; ++i) {
            roundKeys[i] = roundKeys[i - KEY_SIZE] ^ temp[i];
        }

        roundKeys += 4;
        bytesGenerated += 4;
    }
}

void subBytes(uint8_t *state) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = sBox[state[i]];
    }
}

void shiftRows(uint8_t *state) {
    uint8_t tmp[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        tmp[i] = state[shiftRowTab[i]];
    }
    memcpy(state, tmp, AES_BLOCK_SIZE);
}

uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t carry;

    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }

        carry = a & 0x80;
        a <<= 1;

        if (carry) {
            a ^= 0x1b;
        }

        b >>= 1;
    }

    return result;
}

void mixColumns(uint8_t *state) {
    uint8_t tmp[AES_BLOCK_SIZE];

    for (int i = 0; i < AES_BLOCK_SIZE; i += 4) {
        tmp[i] = (uint8_t)(multiply(0x02, state[i]) ^ multiply(0x03, state[i + 1]) ^ state[i + 2] ^ state[i + 3]);
        tmp[i + 1] = (uint8_t)(state[i] ^ multiply(0x02, state[i + 1]) ^ multiply(0x03, state[i + 2]) ^ state[i + 3]);
        tmp[i + 2] = (uint8_t)(state[i] ^ state[i + 1] ^ multiply(0x02, state[i + 2]) ^ multiply(0x03, state[i + 3]));
        tmp[i + 3] = (uint8_t)(multiply(0x03, state[i]) ^ state[i + 1] ^ state[i + 2] ^ multiply(0x02, state[i + 3]));
    }

    memcpy(state, tmp, AES_BLOCK_SIZE);
}

void mixColumnsInv(uint8_t *state) {
    uint8_t tmp[AES_BLOCK_SIZE];

    for (int i = 0; i < AES_BLOCK_SIZE; i += 4) {
        tmp[i] = (uint8_t)(multiply(0x0e, state[i]) ^ multiply(0x0b, state[i + 1]) ^ multiply(0x0d, state[i + 2]) ^ multiply(0x09, state[i + 3]));
        tmp[i + 1] = (uint8_t)(multiply(0x09, state[i]) ^ multiply(0x0e, state[i + 1]) ^ multiply(0x0b, state[i + 2]) ^ multiply(0x0d, state[i + 3]));
        tmp[i + 2] = (uint8_t)(multiply(0x0d, state[i]) ^ multiply(0x09, state[i + 1]) ^ multiply(0x0e, state[i + 2]) ^ multiply(0x0b, state[i + 3]));
        tmp[i + 3] = (uint8_t)(multiply(0x0b, state[i]) ^ multiply(0x0d, state[i + 1]) ^ multiply(0x09, state[i + 2]) ^ multiply(0x0e, state[i + 3]));
    }

    memcpy(state, tmp, AES_BLOCK_SIZE);
}


void addRoundKey(uint8_t *state, const uint8_t *roundKey) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] ^= roundKey[i];
    }
}

void aesEncryptBlock(const uint8_t *input, const uint8_t *key, uint8_t *output) {
    uint8_t roundKeys[(AES_ROUNDS + 1) * AES_BLOCK_SIZE];
    keyExpansion(key, roundKeys);

    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);

    addRoundKey(state, key);

    for (int round = 1; round < AES_ROUNDS; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys + AES_ROUNDS * AES_BLOCK_SIZE);

    memcpy(output, state, AES_BLOCK_SIZE);
}

void aesDecryptBlock(const uint8_t *input, const uint8_t *key, uint8_t *output) {
    uint8_t roundKeys[(AES_ROUNDS + 1) * AES_BLOCK_SIZE];
    keyExpansion(key, roundKeys);

    uint8_t state[AES_BLOCK_SIZE];
    memcpy(state, input, AES_BLOCK_SIZE);

    addRoundKey(state, roundKeys + AES_ROUNDS * AES_BLOCK_SIZE);

    for (int round = AES_ROUNDS - 1; round >= 1; --round) {
        shiftRows(state);
        subBytes(state);
        mixColumnsInv(state);
        addRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);

    }

    shiftRows(state);
    subBytes(state);
    addRoundKey(state, roundKeys);

    memcpy(output, state, AES_BLOCK_SIZE);
}


void readKeyFromFile(const char *keyFileName, uint8_t *key) {
    FILE *keyFile = fopen(keyFileName, "rb");
    if (keyFile == NULL) {
        printf("Eroare la deschiderea fisierului cu cheia de criptare.\n");
        exit(EXIT_FAILURE);
    }
    if (fread(key, sizeof(uint8_t), KEY_SIZE, keyFile) != KEY_SIZE) {
        printf("Eroare la citirea cheii de criptare din fisier.\n");
        fclose(keyFile);
        exit(EXIT_FAILURE);
    }
    fclose(keyFile);
}

void aesEncryptFile(const char *inputFileName, const char *outputFileName, const char *keyFileName) {
    uint8_t key[KEY_SIZE];
    readKeyFromFile(keyFileName, key);

    FILE *inputFile = fopen(inputFileName, "rb");
    if (inputFile == NULL) {
        printf("Eroare la deschiderea fisierului de intrare.\n");
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(outputFileName, "wb");
    if (outputFile == NULL) {
        printf("Eroare la deschiderea fisierului de iesire.\n");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    uint8_t inputBlock[AES_BLOCK_SIZE];
    uint8_t outputBlock[AES_BLOCK_SIZE];

    while (fread(inputBlock, sizeof(uint8_t), AES_BLOCK_SIZE, inputFile) == AES_BLOCK_SIZE) {
        aesEncryptBlock(inputBlock, key, outputBlock);
        fwrite(outputBlock, sizeof(uint8_t), AES_BLOCK_SIZE, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);
}

void aesDecryptFile(const char *inputFileName, const char *outputFileName, const char *keyFileName) {
    uint8_t key[KEY_SIZE];
    readKeyFromFile(keyFileName, key);

    FILE *inputFile = fopen(inputFileName, "rb");
    if (inputFile == NULL) {
        printf("Eroare la deschiderea fisierului de intrare.\n");
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(outputFileName, "wb");
    if (outputFile == NULL) {
        printf("Eroare la deschiderea fisierului de iesire.\n");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    uint8_t inputBlock[AES_BLOCK_SIZE];
    uint8_t outputBlock[AES_BLOCK_SIZE];

    while (fread(inputBlock, sizeof(uint8_t), AES_BLOCK_SIZE, inputFile) == AES_BLOCK_SIZE) {
        aesDecryptBlock(inputBlock, key, outputBlock);
        fwrite(outputBlock, sizeof(uint8_t), AES_BLOCK_SIZE, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);
}
