#include <fcntl.h>
#include <stdint.h>

typedef struct {
    uint8_t   e_ident[16];
    uint16_t  e_type;
    uint16_t  e_machine;
    uint32_t  e_version;
    uint64_t  e_entry;
} elf64_header;

uint64_t
binary_entrypoint(const char *pathname)
{
    elf64_header header;
    int binary;

    binary = open(pathname, O_RDONLY, NULL);
    if (binary < 0)
        die(1, "couldn't open '%s'", pathname);

    if (read(binary, &header, sizeof(header)) < (long int) sizeof(header))
        die(1, "unable to read binary entrypoint");

    close(binary);

    return header.e_entry;
}
