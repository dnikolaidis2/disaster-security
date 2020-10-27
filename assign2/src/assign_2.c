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
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
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
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	/* TODO Task B */
	EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) ERR_print_errors_fp(stderr);

	if (bit_mode == 128)
	{
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) ERR_print_errors_fp(stderr);
	}
	else
	{
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) ERR_print_errors_fp(stderr);
	}
	
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) ERR_print_errors_fp(stderr);
	ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) ERR_print_errors_fp(stderr);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
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
	EVP_CIPHER_CTX *ctx;

    int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) ERR_print_errors_fp(stderr);

	if (bit_mode == 128)
	{
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv)) ERR_print_errors_fp(stderr);
	}
	else
	{
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv)) ERR_print_errors_fp(stderr);
	}
	
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) ERR_print_errors_fp(stderr);
	plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) ERR_print_errors_fp(stderr);
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

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
		if (CMAC_Init(ctx, key, bit_mode/8, EVP_aes_128_ecb(), NULL) != 1) ERR_print_errors_fp(stderr);
	}
	else
	{
		if (CMAC_Init(ctx, key, bit_mode/8, EVP_aes_256_ecb(), NULL) != 1) ERR_print_errors_fp(stderr);
	}

	if (CMAC_Update(ctx, data, data_len) != 1) ERR_print_errors_fp(stderr);
	
	if (CMAC_Final(ctx, cmac, &mactlen) != 1) ERR_print_errors_fp(stderr);

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
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */




	/* Initialize the library */
	ERR_load_crypto_strings();

	/* Keygen from password */
	
	int bit_mode = 128;

	unsigned char password [] = "TUC2015030100";
	unsigned char iv [EVP_MAX_IV_LENGTH] = {0};
	unsigned char key[EVP_MAX_KEY_LENGTH] = {0};
	keygen(password, key, iv, bit_mode);


	/* Operate on the data according to the mode */
	/* encrypt */
	unsigned char plaintext [] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc aliquet nibh ante, at ultricies odio ornare et. Nam mollis libero orci, id finibus metus ultricies ullamcorper. Nullam feugiat vel ipsum at imperdiet. Mauris laoreet viverra enim vitae dictum. Sed tristique placerat felis ut ullamcorper. Etiam gravida fermentum dolor, vel venenatis ante finibus non. Duis at feugiat purus. ";
	unsigned char * ciphetext = (unsigned char *)malloc(strlen(plaintext)*2*sizeof(unsigned char));
	int ciphertext_len = encrypt(plaintext, strlen(plaintext), key, iv, ciphetext, bit_mode);

	/* decrypt */
	unsigned char * plaintext_decrypted = (unsigned char *)malloc(ciphertext_len*sizeof(unsigned char));
	int plaintext_len = decrypt(ciphetext, ciphertext_len, key, iv, plaintext_decrypted, bit_mode);
	
	/* sign */
	unsigned char * cmac = (unsigned char *)malloc((BLOCK_SIZE)*sizeof(unsigned char));
	gen_cmac(plaintext, strlen(plaintext), key, cmac, bit_mode);

	/* verify */
	unsigned char * cmac2 = (unsigned char *)malloc((BLOCK_SIZE)*sizeof(unsigned char));
	gen_cmac(plaintext_decrypted, plaintext_len, key, cmac2, bit_mode);
	if(verify_cmac(cmac, cmac2)) printf("SUCCESS!\n");
	

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	ERR_free_strings();

	/* END */
	return 0;
}
