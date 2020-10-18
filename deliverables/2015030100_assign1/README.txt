Assignment 1 - ΗΡΥ414
Dimitrios Nikolaidis
AM 2015030100

For this Assignment three cryptographic algorithms were implemented composing a small cryptographic 
library. The project consists of two parts: the demo program and the simple_crypto library.

To run:
make && ./demo

Simple_crypto

The library consists of five functions:
    1) void GenerateSecretKey(size_t Size, char * SecretKey)
    This function generates a secret key of size Size and stores it in a preallocated buffer SecretKey.
    This function generated the key by reading /dev/urandom.
    
    2) void OTP(size_t Size, char * Input, char * SecretKey, char * Output)
    This function runs the OTP algorithm on Input using the SecretKey as a secret and outputting to the 
    preallocated Output buffer of size Size. This algorithm goes through the Input and SecretKey and xor’s 
    them byte by byte and outputs the results to Output. This function works as both an encryption and 
    decryption function because of the way XOR works. Giving the encrypted output as input and keeping the 
    SecretKey constant will decrypt the original message.
    
    3) void CeasarsCipher(size_t Size, char * Input, int ShiftAmount, char * Output)
    This function runs the Ceasar Cipher on Input shifting it by ShiftAmount and outputting to preallocated 
    Output buffer of size Size. This algorithm shifts every character by shift amount in the 0-9A-Za-z range. 
    The ShiftAmmount variable is signed and this function also works in reverse to decrypt the message by 
    providing -ShiftAmmount. To shift the input more easily this function uses an alphabet array instead of 
    calculating ascii codes it calculates the new index on the alphabet array.
    
    4) void VigenereEncrypt(size_t Size, char * Input, size_t SecretSize, char * SecretKey, char * Output)
    This function encrypts the Input using the SecretKey with the Vigenere cipher and returns the output 
    to the Output buffer. This function simply shifts the input along the A-Z range by an amount calculated 
    by the character in the SecretKey at the corresponding position. The SecretKey is repeated if it’s 
    smaller than the Input.
    
    5) void VigenereDecrypt(size_t Size, char * Input, size_t SecretSize, char * SecretKey, char * Output)
    This function performs the reverse operation to VigenereEncrypt.

Demo

This is a simple demo program and it has two functions:
    1) size_t SanitizeInputText(size_t Size, char * InputText, bool OnlyCapitalLetters)
    This function sanitizes InputText and returns the sanitized text in InputText and the resulting size 
    as the return. This function keeps either 0-9A-Za-z or only A-Z if OnlyCapitalLetters is true.
    
    2) int main()
    The standard main function that calls all other functions and runs the demo as presented in the assignment example.

