#include <stdio.h>

#include "simple_crypto.h"

static const char CeasarsAlphabet [] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z',
};

void GenerateSecretKey(size_t Size, char * SecretKey)
{
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(SecretKey, 1, Size, fp);
    fclose(fp);
}

void OTP(size_t Size, char * Input, char * SecretKey, char * Output)
{
    for (size_t i = 0; i < Size; i++)
    {
        Output[i] = Input[i] ^ SecretKey[i];
    }

    Output[Size] = 0; 
}

void CeasarsCipher(size_t Size, char * Input, int ShiftAmount, char * Output)
{
    int AlphabetSize = sizeof(CeasarsAlphabet)/sizeof(CeasarsAlphabet[0]);

    for (size_t i = 0; i < Size; i++)
    {
        int j = 0;
        for (; j < AlphabetSize; j++)
        {
            if (Input[i] == CeasarsAlphabet[j])
            {
                break;
            }
        }
        
        if (j + (ShiftAmount % AlphabetSize) < 0)
        {
            Output[i] = CeasarsAlphabet[AlphabetSize + (j + (ShiftAmount % AlphabetSize))];
        }
        else
        {
            Output[i] = CeasarsAlphabet[(j + (ShiftAmount % AlphabetSize)) % AlphabetSize];
        }
    }

    Output[Size] = 0;
}

void VigenereEncrypt(size_t Size, char * Input, size_t SecretSize, char * SecretKey, char * Output)
{
    for (size_t i = 0; i < Size; i++)
    {
        Output[i] = Input[i] + (SecretKey[i % SecretSize] - 'A');
        
        if (Output[i] > 'Z') 
        {
            Output[i] = 'A' + (Output[i] % 'Z') - 1;
        }
    }

    Output[Size] = 0;
}

void VigenereDecrypt(size_t Size, char * Input, size_t SecretSize, char * SecretKey, char * Output)
{
    for (size_t i = 0; i < Size; i++)
    {
        Output[i] = Input[i] - (SecretKey[i % SecretSize] - 'A');
        
        if (Output[i] < 'A') 
        {
            Output[i] = 'Z' - ('A' - Output[i]) + 1;
        }
    }

    Output[Size] = 0;
}