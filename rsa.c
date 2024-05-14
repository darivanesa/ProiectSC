#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

int gcd(int a, int b) {
    int temp;
    while (1) {
        temp = a % b;
        if (temp == 0)
            return b;
        a = b;
        b = temp;
    }
}

void generate_and_save_RSA_keys() {
    srand(time(NULL));
    int p = rand() % 100 + 100;
    int q = rand() % 100 + 100;

    int n = p * q;
    int phi = (p - 1) * (q - 1);

    int e;
    for (e = 2; e < phi; e++) {
        if (gcd(e, phi) == 1)
            break;
    }

    int d;
    for (d = 2; d < phi; d++) {
        if ((e * d) % phi == 1)
            break;
    }

    FILE *public_key_file = fopen("public_key.txt", "w");
    if (public_key_file == NULL) {
        perror("Nu s-a putut crea fisierul pentru cheia publica");
        exit(EXIT_FAILURE);
    }
    fprintf(public_key_file, "%d %d", e, n);
    fclose(public_key_file);

    FILE *private_key_file = fopen("private_key.txt", "w");
    if (private_key_file == NULL) {
        perror("Nu s-a putut crea fisierul pentru cheia privata");
        exit(EXIT_FAILURE);
    }
    fprintf(private_key_file, "%d %d", d, n);
    fclose(private_key_file);
}

void rsaEncrypt(const char *inputFile, const char *outputFile) {
    FILE *input = fopen(inputFile, "r");
    if (input == NULL) {
        perror("Eroare la deschiderea fisierului de intrare");
        exit(EXIT_FAILURE);
    }

    FILE *output = fopen(outputFile, "w");
    if (output == NULL) {
        perror("Eroare la deschiderea fisierului de iesire");
        exit(EXIT_FAILURE);
    }

    FILE *public_key_file = fopen("public_key.txt", "r");
    if (public_key_file == NULL) {
        perror("Nu s-a putut deschide fisierul cu cheile publice");
        exit(EXIT_FAILURE);
    }

    int e, n;
    fscanf(public_key_file, "%d %d", &e, &n);
    fclose(public_key_file);

    int character;
    while ((character = fgetc(input)) != EOF) {
        int encrypted_character = 1;
        for (int i = 0; i < e; i++) {
            encrypted_character = (encrypted_character * character) % n;
        }
        fprintf(output, "%d ", encrypted_character);
    }

    fclose(input);
    fclose(output);
}

void rsaDecrypt(const char *inputFile, const char *outputFile) {
    FILE *input = fopen(inputFile, "r");
    if (input == NULL) {
        perror("Eroare la deschiderea fisierului de intrare");
        exit(EXIT_FAILURE);
    }

    FILE *output = fopen(outputFile, "w");
    if (output == NULL) {
        perror("Eroare la deschiderea fisierului de iesire");
        exit(EXIT_FAILURE);
    }

    FILE *private_key_file = fopen("private_key.txt", "r");
    if (private_key_file == NULL) {
        perror("Nu s-a putut deschide fisierul cu cheia privata");
        exit(EXIT_FAILURE);
    }

    int d, n;
    fscanf(private_key_file, "%d %d", &d, &n);
    fclose(private_key_file);

    int encrypted_character;
    while (fscanf(input, "%d", &encrypted_character) != EOF) {
        int decrypted_character = 1;
        for (int i = 0; i < d; i++) {
            decrypted_character = (decrypted_character * encrypted_character) % n;
        }
        fputc(decrypted_character, output);
    }

    fclose(input);
    fclose(output);
}

