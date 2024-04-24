typedef struct {
    uint64_t  addr_begin;
    uint64_t  addr_end;
    char      *perms;
    off_t     offset;
    dev_t     dev_major;
    dev_t     dev_minor;
    ino_t     inode;
    char      *pathname;
} procmaps_row;

typedef procmaps_row* procmaps_table;

procmaps_row*
parse_procmaps_line(char *line)
{
    procmaps_row *row;
    char *perms_token, *pathname_token;

    row = malloc(sizeof(procmaps_row));

    if (row == NULL)
        return NULL;

    row->addr_begin = strtoull(strtok(line, "-"), NULL, 16);
    row->addr_end   = strtoull(strtok(NULL, " "), NULL, 16);
    perms_token     = strtok(NULL, " ");
    row->offset     = strtoull(strtok(NULL, " "), NULL, 16);
    row->dev_major  = atoi(strtok(NULL, ":"));
    row->dev_minor  = atoi(strtok(NULL, " "));
    row->inode      = atoi(strtok(NULL, " "));
    pathname_token  = strtok(NULL, " \n");

    row->perms = strdup(perms_token);
    if (row->perms == NULL) {
        free(row);
        return NULL;
    }

    if (pathname_token != NULL) {
        row->pathname = strdup(pathname_token);
        if (row->pathname == NULL) {
            free(row->perms);
            free(row);
            return NULL;
        }
    } else {
        row->pathname = NULL;
    }

    return row;
}

procmaps_table*
parse_procmaps(pid_t pid)
{
    procmaps_table *table;
    size_t array_size;
    char *filename, *line;
    size_t i, size;
    FILE *map_file;

    array_size = 32;
    table = calloc(array_size, sizeof(*table));
    if (table == NULL)
        die(1, "calloc failed");

    i = 0;

    line = NULL;
    size = 0;

    if (asprintf(&filename, "/proc/%d/maps", (int) pid) < 0)
        die(1, "malloc failed");

    map_file = fopen(filename, "r");
    if (map_file == NULL)
        die(1, "couldn't open '%s'", filename);

    while (getline(&line, &size, map_file) != -1) {
        if (line != NULL)
            table[i] = parse_procmaps_line(line);
        if (table[i] == NULL)
            die(1, "couldn't parse procmaps row");
        ++i;

        if (i == array_size) {
            table = realloc(table, (array_size + 16) * sizeof(*table));
            if (table == NULL)
                die(1, "realloc failed");
            memset(table + array_size, 0, 16 * sizeof(*table));
            array_size += 16;
        }
        free(line), line = NULL;
    }

    fclose(map_file);
    free(filename);

    return table;
}

void
destroy_procmaps_table(procmaps_table *table)
{
    size_t i;

    i = 0;
    while (table[i]) {
        free(table[i]->perms);
        if (table[i]->pathname)
            free(table[i]->pathname);
        free(table[i]);
        ++ i;
    }
    free(table);
}

static inline
uint64_t
loading_offset(procmaps_table *table)
{
    return table[0]->addr_begin;
}
