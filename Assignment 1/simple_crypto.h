#ifndef SIMPLE_CRYPTO_H_
#define SIMPLE_CRYPTO_H_

#include <stdint.h>


void GenerateSecretKey(uint32_t Size, uint8_t * SecretKey);

void OTPEncrypt(uint32_t Size, char * PlainText, char * SecretKey, char * EncryptedText);
void OTPDecrypt(uint32_t Size, char * EncryptedText, char * SecretKey, char * PlainText);

#endif