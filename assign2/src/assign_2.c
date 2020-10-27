#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);


/* TODO Declare your function prototypes here... */

void GenerateSecretKey(size_t Size, unsigned char * SecretKey)
{
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(SecretKey, 1, Size, fp);
    fclose(fp);
}

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
	/* TODO Task A */
	
	int size = 0;
	if (bit_mode == 128)
	{
		size = EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), NULL, password, strlen(password), 1000, key, iv);
	}
	else
	{
		size = EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, password, strlen(password), 1000, key, iv);
	}

	if(!size) ERR_print_errors_fp(stderr);
}

/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	/* TODO Task B */
	
}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len;

	plaintext_len = 0;

	/*TODO Task C */

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
	/* TODO Task D */
	size_t mactlen = 0;

	CMAC_CTX *ctx = CMAC_CTX_new();
	if (bit_mode == 128)
	{
		if (CMAC_Init(ctx, key, bit_mode/8, EVP_aes_128_cbc(), NULL) != 1) ERR_print_errors_fp(stderr);
	}
	else
	{
		if (CMAC_Init(ctx, key, bit_mode/8, EVP_aes_256_cbc(), NULL) != 1) ERR_print_errors_fp(stderr);
	}

	if (CMAC_Update(ctx, data, data_len) != 1) ERR_print_errors_fp(stderr);
	
	size_t size_read = 0;
	do
	{
		if (CMAC_Final(ctx, cmac+size_read, &mactlen) != 1) ERR_print_errors_fp(stderr);
		size_read += mactlen;
	} while (size_read != bit_mode/8);

	CMAC_CTX_cleanup(ctx);
	CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	for (size_t i = 0; i < BLOCK_SIZE; i++)
	{
		if (cmac1[i] != cmac2[i]) return verify;
	}

	verify = 1;
	return verify;
}



/* TODO Develop your functions here... */



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	// check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */




	/* Initialize the library */
	ERR_load_crypto_strings();

	/* Keygen from password */
	
	bit_mode = 256;

	// unsigned char password [] = "test";
	// unsigned char iv [] = "12345673";
	// unsigned char * derived_key = (unsigned char *)malloc((bit_mode/8)*sizeof(unsigned char));
	// keygen(password, derived_key, iv, bit_mode);


	/* Operate on the data according to the mode */
	/* encrypt */

	/* decrypt */

	/* sign */

	unsigned char data [] = "dleonhsoghsilstqjiinynsounewekavfkxnekdmfmatdswpsekhvkzkxaridyeewzbljlmpaorskvkyqgufdkouynjtpdjtwxcmzuadxckjqwbyjugczgchsyqvddncmpgztqabrvcddtzusatkficrsksotzupnctkxpblk";
	unsigned char key [] = "kifnhefpoesxsxofkifnhefpoesxsxof";

	unsigned char * test = (unsigned char *)malloc((bit_mode/8)*sizeof(unsigned char));
	gen_cmac(data, sizeof(data), key, test, bit_mode);

	print_hex(test, bit_mode/8);

	/* verify */
	unsigned char hmac [] = {
		0x08, 0x7A, 0x1C, 0x78, 0x84, 0x85, 0xD1, 0x52,
		0x68, 0xB7, 0x0C, 0xBD, 0x7E, 0x23, 0x56, 0xA1,
		0xA2, 0x67, 0x19, 0x8A, 0x55, 0x01, 0xA7, 0x18,
		0x79, 0x7A, 0x98, 0xEE, 0xC2, 0x0F, 0xF8, 0xAF
	};
	verify_cmac(test, hmac);
	

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	ERR_free_strings();

	/* END */
	return 0;
}
