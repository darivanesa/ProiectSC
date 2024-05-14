#ifndef DES_H_INCLUDED
#define DES_H_INCLUDED

#include <stdint.h>

void DESEncrypt(const char *inputFile, const char *outputFile, const char *keyFileName);
void DESDecrypt(const char *inputFile, const char *outputFile, const char *keyFileName);


#endif
