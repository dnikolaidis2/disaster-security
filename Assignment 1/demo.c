#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "simple_crypto.h"

size_t SanitizeInputText(size_t Size, char * InputText, bool OnlyCapitalLetters)
{
    size_t ActualSize = 0;
    char * Buffer = (char *)malloc(Size * sizeof(char));

    for (size_t i = 0; i < Size; i++)
    {
        if (!OnlyCapitalLetters)
        {
            if ((InputText[i] >= '0' && InputText[i] <= '9')
            || (InputText[i] >= 'A' && InputText[i] <= 'Z')
            || (InputText[i] >= 'a' && InputText[i] <= 'z'))
            {
                Buffer[ActualSize] = InputText[i];
                ActualSize++;
            }
        }
        else
        {
            if (InputText[i] >= 'A' && InputText[i] <= 'Z')
            {
                Buffer[ActualSize] = InputText[i];
                ActualSize++;
            }
        }
    }

    if(ActualSize < Size && ActualSize != 0)
    {
        memcpy(InputText, Buffer, ActualSize);
        InputText[ActualSize] = 0;
    }

    free(Buffer);
    return ActualSize;
}

int main()
{
    // ------------------ OTP ---------------------

    {
        printf("[OTP] input: ");

        size_t Size = 0;
        char * UserInput = NULL;
        Size = getline(&UserInput, &Size, stdin);
        Size = SanitizeInputText(Size, UserInput, false);
        
        char * Secret = (char *)malloc(Size * sizeof(char));
        GenerateSecretKey(Size, Secret);

        char * Output = (char *)malloc(Size * sizeof(char) + 1);
        OTP(Size, UserInput, Secret, Output);

        printf("[OTP] encrypted: ");
        for (size_t i = 0; i < Size; i++)
            printf("%02X", Output[i]);
        printf("\n");
        
        char * DecryptedOutput = (char *)malloc(Size * sizeof(char) + 1);
        OTP(Size, Output, Secret, DecryptedOutput);
        printf("[OTP] decrypted: ");
        printf("%s\n", DecryptedOutput);
        
        free(UserInput);
        free(Secret);
        free(Output);
        free(DecryptedOutput);
    }

    // ------------------ Ceasars ---------------------

    {
        printf("[Ceasars] input: ");

        size_t Size = 0;
        char * UserInput = NULL;
        Size = getline(&UserInput, &Size, stdin);
        Size = SanitizeInputText(Size, UserInput, false);

        printf("[Ceasars] key: ");
        size_t KeySize = 0;
        char * KeyInput = NULL;
        KeySize = getline(&KeyInput, &KeySize, stdin);
        int32_t Key = 0;
        sscanf(KeyInput, "%d", &Key);
        
        char * Output = (char *)malloc(Size * sizeof(char) + 1);
        CeasarsCipher(Size, UserInput, Key, Output);
        printf("[Ceasars] encrypted: %s\n", Output);

        char * DecryptedOutput = (char *)malloc(Size * sizeof(char) + 1);
        CeasarsCipher(Size, Output, -Key, DecryptedOutput);
        printf("[Ceasars] decrypted: %s\n", DecryptedOutput);

        free(UserInput);
        free(KeyInput);
        free(Output);
        free(DecryptedOutput);
    }

    // ------------------ Vigenere ---------------------

    {
        printf("[Vigenere] input: ");
        size_t Size = 0;
        char * UserInput = NULL;
        Size = getline(&UserInput, &Size, stdin);
        Size = SanitizeInputText(Size, UserInput, true);
        
        printf("[Vigenere] key: ");
        size_t KeySize = 0;
        char * Key = NULL;
        KeySize = getline(&Key, &KeySize, stdin);
        KeySize = SanitizeInputText(KeySize, Key, true);

        char * Output = (char *)malloc(Size * sizeof(char) + 1);
        VigenereEncrypt(Size, UserInput, KeySize, Key, Output);
        printf("[Vigenere] encrypted: %s\n", Output);

        char * DecryptedOutput = (char *)malloc(Size * sizeof(char) + 1);
        VigenereDecrypt(Size, Output, KeySize, Key, DecryptedOutput);
        printf("[Vigenere] decrypted: %s\n", DecryptedOutput);

        free(UserInput);
        free(Key);
        free(Output);
        free(DecryptedOutput);
    }
}