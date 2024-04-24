#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void
die(int error_code, char *fmt, ...)
{
    va_list p;
    char *msg;

    fflush(NULL);
    msg = NULL;

    va_start(p, fmt);
    if (vasprintf(&msg, fmt,  p) >= 0) {
	fprintf(stderr, "error: %s\n", msg);
	free(msg);
    }
    va_end(p);

    exit(error_code);
}

void
info(char *fmt, ...)
{
    va_list p;
    char *msg;

    fflush(NULL);
    msg = NULL;

    va_start(p, fmt);
    if(vasprintf(&msg, fmt, p) >= 0) {
	printf("[+] %s\n", msg);
	free(msg);
    }
    va_end(p);
}
