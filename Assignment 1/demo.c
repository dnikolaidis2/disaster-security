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
        *SizeRead += strlen(Buffer);
        *ReadInput = (char *)realloc(*ReadInput, (*SizeRead + 1) * sizeof(char));
        strcpy(*ReadInput, Buffer);

        if (strlen(Buffer) < BUFFER_SIZE - 1 || Buffer[BUFFER_SIZE - 2] == '\n')
        {
            break;
        }   
    }
}

uint32_t SanitizeInputText(uint32_t Size, char * InputText, bool OnlyCapital)
{
    uint32_t ActualSize = 0;
    char * Buffer = (char *)malloc(Size * sizeof(char));

    for (uint32_t i = 0; i < Size; i++)
    {
        if (!OnlyCapital)
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
void PrintByteArray(uint32_t Size, uint8_t * Array)
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
}

int main()
{
    // uint32_t Size = 0;
    // char * UserInput = NULL;
    // ReadInput(&Size, &UserInput);
    // Size = SanitizeInputText(Size, UserInput, false);
    
    // char * Secret = (char *)malloc(Size * sizeof(char));
    // GenerateSecretKey(Size, Secret);

    // char * Output = (char *)malloc(Size * sizeof(char));
    // OTP(Size, UserInput, Secret, Output);

    // PrintByteArray(Size, Secret);
    // printf("\n");
    // PrintByteArray(Size, Output);
    // printf("\n");

    // char * DecryptedOutput = (char *)malloc(Size * sizeof(char));
    // OTP(Size, Output, Secret, DecryptedOutput);
    // PrintByteArray(Size, DecryptedOutput);
    // printf("\n");
    
    uint32_t Size = 0;
    char * UserInput = NULL;
    ReadInput(&Size, &UserInput);
    Size = SanitizeInputText(Size, UserInput, false);
    
    char * Output = (char *)malloc(Size * sizeof(char));
    CeasarsCipher(Size, UserInput, 4, Output);
    printf("%s", Output);

    // uint32_t Size = 0;
    // char * UserInput = NULL;
    // ReadInput(&Size, &UserInput);
    // Size = SanitizeInputText(Size, UserInput, true);
    
    // uint32_t SecretSize = 0;
    // char * Secret = NULL;
    // ReadInput(&SecretSize, &Secret);
    // SecretSize = SanitizeInputText(SecretSize, Secret, true);

    // char * Output = (char *)malloc(Size * sizeof(char) + 1);
    // VigenereEncrypt(Size, UserInput, SecretSize, Secret, Output);
    // printf("%s\n", Output);

    // char * DecryptedOutput = (char *)malloc(Size * sizeof(char) + 1);    
    // VigenereDecrypt(Size, Output, SecretSize, Secret, DecryptedOutput);
    // printf("%s\n", DecryptedOutput);
}