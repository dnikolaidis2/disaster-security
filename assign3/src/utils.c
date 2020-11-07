#include "utils.h"

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
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
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
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
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_3 -g \n" 
	    "    assign_3 -i in_file -o out_file -k key_file [-d | -e]\n" 
	    "    assign_3 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -k    path    Path to key file\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -g            Generates a keypair and saves to 2 files\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2)) {
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2)) {
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2)) {
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}

bool read_key_file(char * filename, size_t* a, size_t* b)
{
	FILE* fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        return false;
    }

	fread(a, sizeof(a), 1, fp);
	fread(b, sizeof(b), 1, fp);
    
    fclose(fp);

	return true;
}

bool write_key_file(char * filename, size_t a, size_t b)
{
	FILE* fp = fopen(filename, "w+");
    if (fp == NULL)
    {
        return false;
    }

	fwrite(&a, sizeof(a), 1, fp);
	fwrite(&b, sizeof(b), 1, fp);
    
    fclose(fp);

	return true;
}

// https://stackoverflow.com/a/14002993
bool ReadEntireFile(char * filename, unsigned char ** content, int * content_size)
{
	FILE *f = fopen(filename, "rb");
	if (f == NULL)
	{
		return false;
	}
	

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

	*content = (unsigned char *)malloc((fsize + 1)*sizeof(unsigned char));
	fread(*content, 1, fsize, f);
	fclose(f);

	(*content)[fsize] = 0;
	*content_size = fsize;

	return true;
}

// https://github.com/DimitrisKas/disastertools/blob/master/project3/util.h
// Code written by me for a different project.

/**
 * Create a file if it does not exist or truncate existing file and write entire buffer intoo it.
 * @param Filename off file to be created.
 * @param Content buffer with data to write to file.
 * @param Size number of bytes in buffer to write to file.
 * @return true if successful otherwise false.
 */
bool WriteEntireFile(char * Filename, void * Content, unsigned int Size)
{
    FILE* File = fopen(Filename, "w+");
    if (File == NULL)
    {
        // DebugPrint("Could not open file for writing\n");
        return false;
    }

    if (Content != NULL && Size != 0)
    {
        fwrite(Content, 1, Size, File);
    }
    
    fclose(File);

    return true;
}