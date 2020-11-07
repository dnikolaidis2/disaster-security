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
 * https://en.wikipedia.org/wiki/Greatest_common_divisor#Euclid's_algorithm
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	if (a == 0)
	{
		return b;
	}

	if (b == 0)
	{
		return a;
	}
	
	if (a == b)
	{
		return a;
	}
	
	if (a > b)
	{
		return gcd(a-b, b);
	}
	
	return gcd(a, b-a);
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
	size_t e = 0;

	for (size_t i = fi_n - 1; i > 1; i--)
	{
		if (gcd(i, fi_n) == 1)
		{
			e = i;
		}	
	}
	
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
	a = a%b;
	for (size_t x = 1; x < b; x++)
	{
		if ((a*x)%b==1)
		{
			return x;
		}
	}

	return 0;
}


size_t mod_exp(size_t base, size_t exp, size_t mod)
{
	size_t c = 1;

	for (size_t i = 1; i <= exp; i++)
	{
		c = (base*c)%mod;
	}

	return c;
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

	int prime_size = 0;
	size_t * primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &prime_size);

	int p_ind = rand() % prime_size;
	int q_ind = 0;
	
	do
	{
		q_ind = rand() % prime_size;
	} while (q_ind == p_ind);
	
	p = primes[p_ind];
	q = primes[q_ind];

	n = p*q;

	fi_n = (p-1)*(q-1);

	e = choose_e(fi_n);

	d = mod_inverse(e, fi_n);

	write_key_file("public.key", n, d);
    write_key_file("private.key", n, e);
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
    size_t n, d;
    read_key_file(key_file, &n, &d);
    
    unsigned char * input_content = NULL;
    int input_size = 0;
    ReadEntireFile(input_file, &input_content, &input_size);

    size_t * ciphertext = (size_t *)malloc(input_size*sizeof(size_t));
    for (size_t i = 0; i < input_size; i++)
    {
        ciphertext[i] = mod_exp(input_content[i], d, n);
    }
    
    WriteEntireFile(output_file, ciphertext, input_size*sizeof(size_t));
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
	size_t n, e;
    read_key_file(key_file, &n, &e);
    
    size_t * input_content = NULL;
    int input_size = 0;
    ReadEntireFile(input_file, (unsigned char **)&input_content, &input_size);

	size_t decrypted_size = (input_size/sizeof(size_t))*sizeof(unsigned char);
    unsigned char* decrypted = (unsigned char *)malloc(decrypted_size);
    for (size_t i = 0; i < input_size/sizeof(size_t); i++)
    {
        decrypted[i] = (unsigned char)mod_exp(input_content[i], e, n);
    }
    
    WriteEntireFile(output_file, decrypted, decrypted_size);

}
