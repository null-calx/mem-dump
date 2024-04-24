#include <unistd.h>

int
parse_args(int argc, char *argv[], char **outfname)
{
    int opt;
    char *optstring = "+o:h";

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'o':
            *outfname = optarg;
            break;
        case 'h':
            printf("USAGE: ./mem-dump [-h] [-o OUTPUT-FILENAME] PROC [ARGS...]\n");
            printf("\n");
            printf("When no output filename specified, use \"mem.dump\" as the default value.\n");
            printf("\n");
            printf("Examples:\n");
            printf("  ./mem-dump echo nice   Load and dump /usr/bin/echo binary\n");
            printf("                         with \"nice\" as the argument\n");
            printf("  ./mem-dump ./mem-dump  Load and dump ./mem-dump binary\n");
            printf("                         with no arguments\n");
            exit(1);
        default:
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", opt);
        }
    }

    return optind;
}
