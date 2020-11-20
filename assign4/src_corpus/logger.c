#define _GNU_SOURCE

#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#define LOGFILE "file_logging.log"

// https://stackoverflow.com/a/14002993
bool ReadEntireFile(FILE * f, unsigned char ** content, int * content_size)
{
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

	*content = (unsigned char *)malloc((fsize + 1)*sizeof(unsigned char));
	fread(*content, 1, fsize, f);

	(*content)[fsize] = 0;
	*content_size = fsize;

	return true;
}


FILE * fopen(const char *path, const char *mode)
{
	bool file_exists = false;
	if (access(path, F_OK) == 0)
	{
		file_exists = true;
	}

	bool will_create = false;
	if (strpbrk(mode, "wa") != NULL && file_exists == false)
	{
		will_create = true;
	}

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* add your code here */
	FILE *log_file = (*original_fopen)(LOGFILE, "a+");

	// bool fopen_failed = false;
	bool access_denied = false;
	unsigned char fingerprint [MD5_DIGEST_LENGTH] = {0};

	if (original_fopen_ret == 0)
	{
		// fopen_failed = true;
		if (errno == EACCES)
		{
			access_denied = true;
		}
		else
		{
			printf("Unnown error!\ncode: %d\n", errno);
		}
	}
	else
	{
		fclose(original_fopen_ret);

		original_fopen_ret = (*original_fopen)(path, "r");

		unsigned char * file_content;
		int content_length = 0;
		ReadEntireFile(original_fopen_ret, &file_content, &content_length);
		MD5(file_content, content_length, fingerprint);
		
		fclose(original_fopen_ret);
		original_fopen_ret = (*original_fopen)(path, mode);
		free(file_content);
	}

	char full_path [PATH_MAX] = {0};
	realpath(path, full_path);

	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	fprintf(log_file, "%u \"%s\" %d-%02d-%02d %lu %d %d ",
			getuid(),
			full_path,
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			(unsigned long)t,
			!will_create,
			access_denied);

	for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		fprintf(log_file, "%02X", fingerprint[i]);
	}
	fprintf(log_file, "\n");
	
	fclose(log_file);
	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	fflush(stream);

	FILE *(*original_fopen)(const char*, const char*);

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	FILE *log_file = (*original_fopen)(LOGFILE, "a+");

    char proclnk [PATH_MAX];
    char full_path [PATH_MAX];
    int fno;
    ssize_t r;

	fno = fileno(stream);
	sprintf(proclnk, "/proc/self/fd/%d", fno);
	r = readlink(proclnk, full_path, PATH_MAX);
	if (r < 0)
	{
		printf("failed to readlink\n");
	}
	full_path[r] = '\0';

	bool access_denied = false;
	if (access(full_path, W_OK) != 0)
	{
		access_denied = true;
	}

	unsigned char fingerprint [MD5_DIGEST_LENGTH] = {0};
	FILE* tmp = (*original_fopen)(full_path, "r");

	unsigned char * file_content;
	int content_length = 0;
	ReadEntireFile(tmp, &file_content, &content_length);
	MD5(file_content, content_length, fingerprint);
	
	fclose(tmp);
	free(file_content);

	/* add your code here */
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	fprintf(log_file, "%u \"%s\" %d-%02d-%02d %lu %d %d ",
			getuid(),
			full_path,
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			(unsigned long)t,
			2,
			access_denied);

	for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		fprintf(log_file, "%02X", fingerprint[i]);
	}
	fprintf(log_file, "\n");

	fclose(log_file);
	return original_fwrite_ret;
}
