#include <string.h>
#include <sys/stat.h>

void
find_binary(const char *filename, char *pathname, size_t path_len)
{
    size_t filename_len;
    struct stat statbuf;

    filename_len = strlen(filename);
    if (filename_len > path_len - 1)
        die(1, "filename too long");

    if (strchr(filename, '/')) {
        strcpy(pathname, filename);
    } else {
        const char *path;
        size_t m, n, len;

        for (path = getenv("PATH"); path && *path; path += m) {
            const char *colon = strchr(path, ':');

            if (colon) {
                n = colon - path;
                m = n + 1;
            } else {
                m = n = strlen(path);
            }

            if (n == 0) {
                if (!getcwd(pathname, path_len))
                    continue;

                len = strlen(pathname);
            } else if (n > path_len - 1) {
                continue;
            } else {
                strncpy(pathname, path, n);
                len = n;
            }

            if (len && pathname[len - 1] != '/')
                pathname[len++] = '/';

            if (filename_len + len > path_len - 1)
                continue;

            strcpy(pathname + len, filename);

            if (stat(pathname, &statbuf) == 0 &&
                /* Accept only regular files
                   with some execute bits set.
                   XXX not perfect, might still fail */
                S_ISREG(statbuf.st_mode) &&
                (statbuf.st_mode & 0111))
                break;
        }

        if (!path || !*path)
            pathname[0] = '\0';

        if (filename && !*pathname)
            die(1, "couldn't find executable '%s'", filename);

        if (stat(pathname, &statbuf) < 0)
            die(1, "couldn't stat '%s'", pathname);
    }
}
