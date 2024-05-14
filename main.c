#include <stdio.h>
#include <stdlib.h>
#include "DES.h" // Include toate fișierele header ale algoritmilor
#include "AES.h"
#include "RSA.h"
#include "sBox.h"

#define AESKEY_SIZE 16
#define DESKEY_SIZE 8

// Funcție pentru afișarea meniului
void displayMenu() {
    printf("====================\n");
    printf("\n");
    printf("1. DES (Criptare)\n");
    printf("2. DES (Decriptare)\n");
    printf("3. AES (Criptare)\n");
    printf("4. AES (Decriptare)\n");
    printf("5. RSA (Criptare)\n");
    printf("6. RSA (Decriptare)\n");
    printf("0. Iesire\n");
    printf("\n");
    printf("====================\n");
    printf("Selectati optiunea: ");
}


void generateAndStoreKeyAES(const char *fileName) {
    FILE *AESkeyFile = fopen(fileName, "wb");
    if (AESkeyFile == NULL) {
        printf("Eroare la deschiderea fisierului pentru cheie.\n");
        exit(EXIT_FAILURE);
    }

    unsigned char AESkey[AESKEY_SIZE];
    for (int i = 0; i < AESKEY_SIZE; i++) {
        AESkey[i] = rand() % 256;
    }

    fwrite(AESkey, sizeof(unsigned char), AESKEY_SIZE, AESkeyFile);
    fclose(AESkeyFile);
}

void generateAndStoreKeyDES(const char *filename) {
    FILE *DESKeyFile = fopen(filename, "wb");
    if (DESKeyFile == NULL) {
        printf("Eroare la deschiderea fisierului pentru cheie.\n");
        exit(EXIT_FAILURE);
    }

    unsigned char DESKey[DESKEY_SIZE]; // Corrected declaration
    for (int i = 0; i < DESKEY_SIZE; i++) {
        DESKey[i] = rand() % 256;
    }

    fwrite(DESKey, sizeof(unsigned char), DESKEY_SIZE, DESKeyFile); // Corrected variable name
    fclose(DESKeyFile);
}

int main() {
    int option;
    char inputFile[100], outputFile[100];
    const char *DESKeyFileName = "DESKey.bin";
    const char *keyFileName = "AESkey.bin";
    generateAndStoreKeyAES("AESkey.bin");
    generateAndStoreKeyDES("DESKey.bin");
    generate_and_save_RSA_keys();
    do {
        displayMenu();
        scanf("%d", &option);
        switch(option) {
            case 1:
                printf("Fisierul de intrare: ");
                scanf("%s", inputFile);
                printf("Fisierul de iesire: ");
                scanf("%s", outputFile);
                DESEncrypt(inputFile, outputFile, DESKeyFileName);
                break;
            case 2:
                printf("Fisierul de intrare: ");
                scanf("%s", inputFile);
                printf("Fisierul de iesire: ");
                scanf("%s", outputFile);
                DESDecrypt(inputFile, outputFile, DESKeyFileName);
                break;
            case 3:
                printf("Fisierul de intrare: ");
                scanf("%s", inputFile);
                printf("Fisierul de iesire: ");
                scanf("%s", outputFile);
                aesEncryptFile(inputFile, outputFile, keyFileName);
                break;
            case 4:
                printf("Fisierul de intrare: ");
                scanf("%s", inputFile);
                printf("Fisierul de iesire: ");
                scanf("%s", outputFile);
                aesDecryptFile(inputFile, outputFile, keyFileName);
                break;
            case 5:
                printf("Fisierul de intrare: ");
                scanf("%s", inputFile);
                printf("Fisierul de iesire: ");
                scanf("%s", outputFile);
                rsaEncrypt(inputFile, outputFile);
                break;
            case 6:
                printf("Fisierul de intrare: ");
                scanf("%s", inputFile);
                printf("Fisierul de iesire: ");
                scanf("%s", outputFile);
                rsaDecrypt(inputFile, outputFile);
    break;
            case 0:
                printf("La revedere!\n");
                break;
            default:
                printf("Optiune invalida.\n");
        }
    } while(option != 0);

    return 0;
}
