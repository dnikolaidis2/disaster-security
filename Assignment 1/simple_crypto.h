#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include <stdint.h>


void GenerateSecretKey(uint32_t Size, uint8_t * SecretKey);

void OTP(uint32_t Size, char * Input, char * SecretKey, char * Output);
void CeasarsCipher(uint32_t Size, char * Input, int32_t ShiftAmount, char * Output);
void VigenereCipher(uint32_t Size, char * Input, char * SecretKey, char * Output);

#endif