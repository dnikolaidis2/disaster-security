#include "rsa.h"
#include "utils.h"

#include <stdbool.h>
#include <math.h>

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes = (size_t *)malloc(limit*sizeof(size_t));

	bool * A = (bool *)malloc((limit+1)*sizeof(bool));
	memset(A+2, true, limit-1);

	for (size_t i = 2; i < sqrt(limit); i++)
	{
		if (A[i])
		{	
			int inc = 1;
			for (size_t j = pow(i, 2); j < limit; j = pow(i, 2)+inc*i)
			{
				inc++;
				A[j] = false;
			}
		}
	}

	int prime_inc = 0;
	for (size_t i = 2; i < limit-1; i++)
	{
		if (A[i])
		{
			primes[prime_inc] = i;
			prime_inc++;
		}
	}

	primes = (size_t *)realloc(primes, prime_inc*sizeof(size_t));
	*primes_sz = prime_inc;
	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{

	/* TODO */

}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e;

	/* TODO */

	return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{

	/* TODO */

}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	/* TODO */

}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */

}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */

}
