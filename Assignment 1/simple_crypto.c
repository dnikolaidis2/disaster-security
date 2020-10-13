#include <stdio.h>
#include "simple_crypto.h"

void GenerateSecretKey(uint32_t Size, uint8_t * SecretKey)
{
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(SecretKey, 1, Size, fp);
    fclose(fp);
}

void OTPEncrypt(uint32_t Size, char * PlainText, char * SecretKey, char * EncryptedText)
{

}

void OTPDecrypt(uint32_t Size, char * EncryptedText, char * SecretKey, char * PlainText)
{

}