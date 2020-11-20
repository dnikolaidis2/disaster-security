#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <linux/limits.h>
#include <stdbool.h>

#define LOGFILE "file_logging.log"

typedef struct entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t time; /* file access time */

	char path [PATH_MAX]; /* filename (string) */
	char filename [PATH_MAX];
	char fingerprint [MD5_DIGEST_LENGTH * 2]; /* file fingerprint */

	/* add here other fields if necessary */
} entry;


void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

entry * log_parseline(char *line)
{
	entry * ent = (entry *)malloc(sizeof(entry));

	{
		strtok(line, "\"");
		char * start = strtok(NULL, "\"");
		char * end = strtok(NULL, "\"");

		strcpy(&(ent->path), start);

		memmove(start - 1, end + 1, end-start);

		start = strrchr(ent->path, '/');
		strcpy(&(ent->filename), start + 1);
	}

	{
		char *start = strrchr(line, ' ');
		memmove(&(ent->fingerprint), start + 1, MD5_DIGEST_LENGTH*2);

		*start = 0;
	}

	sscanf(line, "%d %*d-%*d-%*d %lu %d %d",
					  &(ent->uid), &(ent->time), &(ent->access_type), &(ent->action_denied));

	return ent;
}

void log_parse(FILE *log, entry ***entries, int *count)
{
	*entries = NULL;
	*count = 0;

	char * line = NULL;
	size_t size = 0;
	while(getline(&line, &size, log) > 0)
	{
		(*count)++;
		*entries = realloc(*entries, (*count)*sizeof(entry *));
		(*entries)[*count - 1] = log_parseline(line);
	}

	free(line);
}

void list_unauthorized_accesses(FILE *log)
{
	/* add your code here */
	entry ** entries;
	int count;
	log_parse(log, &entries, &count);

	int * uid_list = NULL;
	int * illegal_access = NULL;
	int uid_count = 0;

	for (size_t i = 0; i < count; i++)
	{
		// Check if access was illegal
		if (entries[i]->action_denied != 0)
		{
			// Is the uid in uid list?
			int index = -1;
			for (size_t j = 0; j < uid_count; j++)
			{
				if (uid_list[j] == entries[i]->uid)
				{
					index = j;
				}
			}
			
			// Increment illegal access counter
			if (index >= 0)
			{
				illegal_access[index]++;
			}
			else	// else enlarge arrays and add the id to the list
			{
				uid_count++;
				uid_list = realloc(uid_list, uid_count*sizeof(int));
				illegal_access = realloc(illegal_access, uid_count*sizeof(int));
				
				uid_list[uid_count - 1] = entries[i]->uid;
				illegal_access[uid_count - 1] = 1;
			}
		}
	}

	bool first = true;
	for (size_t i = 0; i < uid_count; i++)
	{
		if (illegal_access[i] >= 7)
		{
			if (first)
			{
				printf("uid\taccess count\n");
				first = false;
			}
			
			printf("%d\t%d\n", uid_list[i], illegal_access[i]);
		}
	}
	
	
	for (size_t i = 0; i < count; i++)
	{
		free(entries[count]);
	}
	
	free(entries);
	free(uid_list);
	free(illegal_access);
	
	return;
}


void list_file_modifications(FILE *log, char *file_to_scan)
{
	/* add your code here */
	entry ** entries;
	int count;
	log_parse(log, &entries, &count);

	int * uid_list = NULL;
	int * modification_count = NULL;
	int user_count = 0;

	char fingerprint [MD5_DIGEST_LENGTH * 2] = {0};
	bool first_file_log = true;

	for (size_t i = 0; i < count; i++)
	{
		// check that we are looking at a log of the file
		if (strcmp(file_to_scan, entries[i]->filename) == 0)
		{
			// have we seen the file before?
			if (!first_file_log)
			{
				// Yes: check if the fingerprint has changed
				// log user that made the modification
				// update the fingerprint of the file
				if (strcmp(fingerprint, entries[i]->fingerprint) != 0)
				{
					int index = -1;
					for (size_t j = 0; j < user_count; j++)
					{
						if (uid_list[j] == entries[i]->uid)
						{
							index = j;	
						}
					}

					if (index >= 0)
					{
						modification_count[index]++;
					}
					else
					{
						user_count++;
						uid_list = realloc(uid_list, user_count*sizeof(int));
						modification_count = realloc(modification_count, user_count*sizeof(int));
						
						uid_list[user_count - 1] = entries[i]->uid;
						modification_count[user_count - 1] = 1;
					}

					memcpy(fingerprint, entries[i]->fingerprint, MD5_DIGEST_LENGTH * 2);
				}
			}
			else
			{
				// No:
				// Initialize the files fingerprint
				memcpy(fingerprint, entries[i]->fingerprint, MD5_DIGEST_LENGTH * 2);

				first_file_log = false;
			}	
		}
	}

	bool first = true;
	for (size_t i = 0; i < user_count; i++)
	{
		if (first)
		{
			printf("uid\tmodification count\n");
			first = false;
		}
		
		printf("%d\t%d\n", uid_list[i], modification_count[i]);
	}

	for (size_t i = 0; i < count; i++)
	{
		free(entries[count]);
	}
	free(entries);
	free(uid_list);
	free(modification_count);

	return;
}


int main(int argc, char *argv[])
{
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen(LOGFILE, "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;
	
	return 0;
}
