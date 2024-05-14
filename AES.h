#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include <stdint.h>

void aesEncryptFile(const char *inputFileName, const char *outputFileName, const char *keyFileName);
void aesDecryptFile(const char *inputFileName, const char *outputFileName, const char *keyFileName);

#endif // AES_H_INCLUDED
