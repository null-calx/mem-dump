#include <unistd.h>

int
parse_args(int argc, char *argv[], char **outfname)
{
    int opt;
    char *optstring = "+o:";

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'o':
            *outfname = optarg;
            break;
        default:
            fprintf(stderr, "?? getopt returned character code 0%o ??\n", opt);
        }
    }

    return optind;
}
