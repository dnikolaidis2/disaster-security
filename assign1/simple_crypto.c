/* ========================================================================
   $File: simple_crypto.c $
   $Date: 18/10/2020 $
   $Creator: Dimitrios Nikolaidis $
   $AM: 2015030100 $
   ======================================================================== */

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
        // Search for character in alphabet array and retrieve index.
        int j = 0;
        for (; j < AlphabetSize; j++)
        {
            if (Input[i] == CeasarsAlphabet[j])
            {
                break;
            }
        }
        
        // Caclulate cipher result by shifting the index of the alphabet array.
        if (j + (ShiftAmount % AlphabetSize) < 0)
        {
            // New index is negative. Start from end and subtract.
            Output[i] = CeasarsAlphabet[AlphabetSize + (j + (ShiftAmount % AlphabetSize))];
        }
        else
        {
            // New index is positive. Bound it to AlphabetSize.
            Output[i] = CeasarsAlphabet[(j + (ShiftAmount % AlphabetSize)) % AlphabetSize];
        }
    }

    Output[Size] = 0;
}

void VigenereEncrypt(size_t Size, char * Input, size_t SecretSize, char * SecretKey, char * Output)
{
    for (size_t i = 0; i < Size; i++)
    {
        // Secret can be <= input so we bound the index using % SecretSize to repeat it when its smaller.
        Output[i] = Input[i] + (SecretKey[i % SecretSize] - 'A');
        
        // Exceded end of range. Caclulate again based on 'A'.
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
        // Secret can be <= input so we bound the index using % SecretSize to repeat it when its smaller.
        Output[i] = Input[i] - (SecretKey[i % SecretSize] - 'A');
        
        // Ended up before start of range. Caclulate again based on 'Z'.
        if (Output[i] < 'A') 
        {
            Output[i] = 'Z' - ('A' - Output[i]) + 1;
        }
    }

    Output[Size] = 0;
}