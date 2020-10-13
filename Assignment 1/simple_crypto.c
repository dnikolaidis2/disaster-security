#include <stdio.h>

#include "simple_crypto.h"

void GenerateSecretKey(uint32_t Size, uint8_t * SecretKey)
{
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(SecretKey, 1, Size, fp);
    fclose(fp);
}

void OTP(uint32_t Size, char * Input, char * SecretKey, char * Output)
{
    for (uint32_t i = 0; i < Size; i++)
    {
        Output[i] = Input[i] ^ SecretKey[i];
    }
}

void CeasarsCipher(uint32_t Size, char * Input, int32_t ShiftAmount, char * Output)
{
    for (uint32_t i = 0; i < Size; i++)
    {
        Output[i] = Input[i] + ShiftAmount;
    }
}

void VigenereCipher(uint32_t Size, char * Input, uint32_t SecretSize, char * SecretKey, char * Output)
{
    for (uint32_t i = 0; i < Size; i++)
    {
        Output[i] = Input[i] + (SecretKey[i % SecretSize] - 'A');
        
        if (Output[i] > 'Z') {
            Output[i] = 'A' + (Output[i] % 'Z') - 1;
        }
    }
}