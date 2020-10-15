#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#include "simple_crypto.h"

#define BUFFER_SIZE 512

void ReadInput(uint32_t * SizeRead, char ** ReadInput)
{
    *SizeRead = 0;

    char Buffer[BUFFER_SIZE];
    while (fgets(Buffer, BUFFER_SIZE, stdin) != NULL)
    {
        *ReadInput = (char *)realloc(*ReadInput, (*SizeRead + strlen(Buffer) + 1) * sizeof(char));
        strcpy(*ReadInput + *SizeRead, Buffer);
        *SizeRead += strlen(Buffer);

        if (strlen(Buffer) < BUFFER_SIZE - 1 || Buffer[BUFFER_SIZE - 2] == '\n')
        {
            break;
        }
    }
}

uint32_t SanitizeInputText(uint32_t Size, char * InputText, bool OnlyCapitalLetters)
{
    uint32_t ActualSize = 0;
    char * Buffer = (char *)malloc(Size * sizeof(char));

    for (uint32_t i = 0; i < Size; i++)
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

// https://stackoverflow.com/a/29477687
void PrintByteArray(uint32_t Size, uint8_t * Array, bool AppendNewLine)
{
    setlocale(LC_ALL, "C");
    uint8_t c;

    for(uint32_t i = 0; i < Size; i++)
    {
        c = Array[i];

        if (isprint(c) && c != '\\')
            putchar(c);
        else
            printf("\\x%02x", c);
    }

    if (AppendNewLine)
        printf("\n");
}

int main()
{
    // ------------------ OTP ---------------------

    {
        printf("[OTP] input: ");

        uint32_t Size = 0;
        char * UserInput = NULL;
        ReadInput(&Size, &UserInput);
        Size = SanitizeInputText(Size, UserInput, false);
        
        char * Secret = (char *)malloc(Size * sizeof(char));
        GenerateSecretKey(Size, Secret);

        char * Output = (char *)malloc(Size * sizeof(char) + 1);
        OTP(Size, UserInput, Secret, Output);

        printf("[OTP] encrypted: ");
        PrintByteArray(Size, Output, true);

        char * DecryptedOutput = (char *)malloc(Size * sizeof(char) + 1);
        OTP(Size, Output, Secret, DecryptedOutput);
        printf("[OTP] decrypted: ");
        PrintByteArray(Size, DecryptedOutput, true);
        
        free(UserInput);
        free(Secret);
        free(Output);
        free(DecryptedOutput);
    }

    // ------------------ Ceasars ---------------------

    {
        printf("[Ceasars] input: ");

        uint32_t Size = 0;
        char * UserInput = NULL;
        ReadInput(&Size, &UserInput);
        Size = SanitizeInputText(Size, UserInput, false);

        printf("[Ceasars] key: ");
        uint32_t KeySize = 0;
        char * KeyInput = NULL;
        ReadInput(&KeySize, &KeyInput);
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
        uint32_t Size = 0;
        char * UserInput = NULL;
        ReadInput(&Size, &UserInput);
        Size = SanitizeInputText(Size, UserInput, true);
        
        printf("[Vigenere] key: ");
        uint32_t KeySize = 0;
        char * Key = NULL;
        ReadInput(&KeySize, &Key);
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