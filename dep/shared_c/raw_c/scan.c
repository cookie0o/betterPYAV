#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_LEN 32 // MD5 hash length

int check_hash_in_file(const char *hash_file, const char *hash) {
    FILE *file = fopen(hash_file, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file: %s\n", hash_file);
        exit(EXIT_FAILURE);
    }

    char line[HASH_LEN + 1];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // Remove newline character
        if (strcmp(line, hash) == 0) {
            fclose(file);
            return 1; // Hash found
        }
    }

    fclose(file);
    return 0; // Hash not found
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <md5_hash>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *md5_hash = argv[1];

    // Check hash in hash files
    int hash_found = 0;
    for (int i = 1; i <= 2; i++) {
        char hash_file_path[256];
        sprintf(hash_file_path, "/hashes/hashList_%d.txt", i);
        if (check_hash_in_file(hash_file_path, md5_hash)) {
            hash_found = 1;
            break;
        }
    }

    printf("%s\n", hash_found ? "true" : "false");

    return EXIT_SUCCESS;
}
