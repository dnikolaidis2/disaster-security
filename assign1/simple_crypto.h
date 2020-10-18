/* ========================================================================
   $File: simple_crypto.h $
   $Date: 18/10/2020 $
   $Creator: Dimitrios Nikolaidis $
   $AM: 2015030100 $
   ======================================================================== */

#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

/**
 * generated a secret key of a give size by reading /dev/urandom
 * @param Size of secret key to generate.
 * @param SecretKey preallcated byte array of size Size to read data to.
 */
void GenerateSecretKey(size_t Size, char * SecretKey);


/**
 * Encrypts and decrypts a message(Input) using a secret key(SecretKey) using the OTP algorith.
 * @param Size the size of Input, Output and SecretKey strings.
 * @param Input string with data to encrypt/decrypt.
 * @param SecretKey string with the secret key.
 * @param Output preallocated buffer to ouput results to.
 */
void OTP(size_t Size, char * Input, char * SecretKey, char * Output);

/**
 * Encrypts and Decrypts message using Ceasars Cipher.
 * @param Size size of Input and Output strings.
 * @param ShiftAmmount ammount to shift Input by to encrypt the message. Can be negative to decrypt Input message.
 * @param Output preallocated buffer of size Size to output result of function to. 
 */
void CeasarsCipher(size_t Size, char * Input, int ShiftAmount, char * Output);

/**
 * Encrypts a message based on a secret key using the Vigenere algorithm.
 * @param Size the size of the Input and Output strings given.
 * @param Input string with message to encrypt.
 * @param SecretSize size of SecretKey.
 * @param SecretKey the key to use to encrypt the message.
 * @param Output pre allocated buffer of size Size used to return encrypted message.
 */
void VigenereEncrypt(size_t Size, char * Input, size_t SecretSize, char * SecretKey, char * Output);

/**
 * Decrypts a message based on a secret key using the Vigenere algorithm.
 * @param Size the size of the Input and Output strings given.
 * @param Input string with message to decrypt.
 * @param SecretSize size of SecretKey.
 * @param SecretKey the key to use to decrypt the message.
 * @param Output pre allocated buffer of size Size used to return decrypted message.
 */
void VigenereDecrypt(size_t Size, char * Input, size_t SecretSize, char * SecretKey, char * Output);

#endif