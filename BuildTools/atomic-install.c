// SPDX-License-Identifier: GPL-3.0-only

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int report_error(const char *operation, const char *source, const char *destination)
{
    fprintf(stderr, "%s '%s' -> '%s': %s\n", operation, source, destination, strerror(errno));
    return 1;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: atomic-install source destination\n");
        return 64;
    }

    const char *source = argv[1];
    const char *destination = argv[2];
    struct stat destination_status;

    if (lstat(destination, &destination_status) == -1) {
        if (errno != ENOENT) {
            return report_error("inspect", source, destination);
        }
        if (rename(source, destination) == -1) {
            return report_error("install", source, destination);
        }
        return 0;
    }

    if (renamex_np(source, destination, RENAME_SWAP) == -1) {
        return report_error("atomic swap", source, destination);
    }
    return 0;
}
