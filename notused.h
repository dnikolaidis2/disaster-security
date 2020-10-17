#include <stdint.h>
#include <stdio.h>
#include <locale.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

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