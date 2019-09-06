/*
	Guy Levin 2019 (c)

	Program that logs when + from where + by who it was run.

	Useful to test Privilege Escalation vulnerabilities via weak permissions on executable files

	Compile: gcc runmeasroot.c
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <time.h>
#include <string.h>

#define LOG_PATH ("/home/user/Desktop/execution_log.txt")
#define LOG_PATH_BACKUP ("/tmp/execution_log.txt")
#define PATH_NAME_SIZE (0x100)
#define UNKNOWN_VALUE_AS_STRING ("<unknown>")

int main()
{
	register struct passwd *pw;
	register uid_t uid;
	char path_name[PATH_NAME_SIZE] = {0};
	char * running_as = NULL;
	FILE* log_file;
	time_t time_now;
	char * time_str = UNKNOWN_VALUE_AS_STRING;

	log_file = fopen(LOG_PATH, "a");


	// get log file
	if (NULL == log_file)
	{
		log_file = fopen(LOG_PATH_BACKUP, "a");
		if (NULL == log_file)
		{
			// can't log anything. no point in running.
			goto end;
		}
	}

	// get exe path
	if (-1 == readlink("/proc/self/exe", path_name, PATH_NAME_SIZE-1))
	{
		snprintf(path_name, PATH_NAME_SIZE, UNKNOWN_VALUE_AS_STRING);
	}

	// get running user
	uid = geteuid();
	pw = getpwuid(uid);
	if (NULL != pw)
	{
		running_as = pw->pw_name;
	}
	else
	{
		running_as = UNKNOWN_VALUE_AS_STRING;
	}

	// get time
	time_now = time(0);
	if (-1 != time_now)
	{
		time_str = ctime(&time_now);
		// remove new line from time_str
		time_str[strlen(time_str)-1] = '\0';
	}

	fprintf(log_file, "on '%s' running from '%s' running as '%s'\n", time_str, path_name, running_as);

end:
	if (log_file)
	{		
		fclose(log_file);
	}
	return 0;
}
