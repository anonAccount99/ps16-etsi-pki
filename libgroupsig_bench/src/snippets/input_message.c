
#include <stdio.h>
#include <stdlib.h>

char *input_message(const char *path, size_t *size)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t read = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[read] = '\0';
    if (size) *size = read;
    return buf;
}