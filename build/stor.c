/*
 * stor.c — Starter skeleton for BiBiFi secure file store.
 *
 * This is a STUB that compiles and links but does NOT implement any
 * functionality.  Every action prints "invalid" and exits 255.
 *
 * Your job: replace the TODOs with a real, secure implementation.
 *
 * CLI:
 *   ./stor -u <user> [-k <key>] [-f <file>] [-i <infile>] [-o <outfile>] <action> [text]
 *
 *   actions: register | create | write | read
 *
 * Rules:
 *   - On ANY error, print exactly "invalid" (no newline required) and exit 255.
 *   - On success, exit 0.
 *   - State is persisted in "enc.db" (current directory).
 *   - The win() function MUST remain — do not remove it.
 *   - You MUST link against the provided malloc-2.7.2.c (dlmalloc).
 *   - Build flags: -O0 -g -m32 -fno-stack-protector + execstack
 *   - Available libraries: libssl, libsodium (see Makefile).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Required: do not remove ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

/* Print "invalid" and return 255 — use this for ALL error paths. */
static int invalid(void) {
    printf("invalid");
    return 255;
}

int main(int argc, char **argv) {
    char *user = NULL, *key = NULL, *file = NULL;
    char *infile = NULL, *outfile = NULL;
    int c;

    while ((c = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (c) {
            case 'u': user    = optarg; break;
            case 'k': key     = optarg; break;
            case 'f': file    = optarg; break;
            case 'i': infile  = optarg; break;
            case 'o': outfile = optarg; break;
            default:  return invalid();
        }
    }

    if (!user) return invalid();
    if (optind >= argc) return invalid();

    const char *action  = argv[optind];
    const char *content = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    /*
     * TODO: Load state from enc.db (if it exists).
     */

    if (strcmp(action, "register") == 0) {
        /*
         * TODO: Register a new user (or re-register with a new key).
         *  - Requires: -u and -k
         *  - Store credentials so write/read can verify the key later.
         *  - Persist state to enc.db.
         */
        return invalid();  /* STUB — replace me */
    }

    if (strcmp(action, "create") == 0) {
        /*
         * TODO: Create a new (empty) file owned by this user.
         *  - Requires: -u and -f
         *  - Does NOT require -k.
         *  - If the file already exists, this is a no-op (exit 0).
         *  - Persist state to enc.db.
         */
        return invalid();  /* STUB — replace me */
    }

    if (strcmp(action, "write") == 0) {
        int ok = 0;
        char *plaintext = NULL;
        size_t len = 0;
        size_t user_len, file_len, key_len;

        if (!key || !file)
            return invalid();

        user_len = strlen(user);
        if (user_len == 0 || user_len > 255)
            return invalid();
        if (strcmp(user, ".") == 0 || strcmp(user, "..") == 0)
            return invalid();

        file_len = strlen(file);
        if (file_len == 0 || file_len > 255)
            return invalid();
        if (strcmp(file, ".") == 0 || strcmp(file, "..") == 0)
            return invalid();

        key_len = strlen(key);
        if (key_len == 0 || key_len > 1024)
            return invalid();

        if (!lock_db("enc.db"))
            return invalid();
    
        if (!load_db("enc.db"))
            goto cleanup;
    
        User *u = find_user(db, user);
        if (!u || !verify_key_constant_time(u, key))
            goto cleanup;
    
        FileEntry *f = find_file(db, user, file);
        if (!f)
            goto cleanup;
    
        if (infile) {
            if (!read_regular_file_limited(infile, &plaintext, &len, MAX_CONTENT_LEN))
                goto cleanup;
        } else if (content) {
            len = strlen(content);
    
            if (len > MAX_CONTENT_LEN || len == SIZE_MAX - 1)
                goto cleanup;
    
            plaintext = malloc(len + 1);
            if (!plaintext)
                goto cleanup;
    
            memcpy(plaintext, content, len + 1);
        } else {
            plaintext = strdup("");
            if (!plaintext)
                goto cleanup;
            len = 0;
        }
    
        if (!encrypt_and_store_aead(f, plaintext, len, key))
            goto cleanup;
    
        if (!save_db_atomic("enc.db"))
            goto cleanup;
    
        ok = 1;
    
    cleanup:
        if (plaintext) {
            secure_bzero(plaintext, len);
            free(plaintext);
        }
    
        unlock_db("enc.db");
    
        return ok ? 0 : invalid();
    }

    if (strcmp(action, "read") == 0) {
        int ok = 0;
        char *plaintext = NULL;
        size_t len = 0;
        size_t user_len, file_len, key_len;

        if (!key || !file)
            return invalid();

        user_len = strlen(user);
        if (user_len == 0 || user_len > 255)
            return invalid();
        if (strcmp(user, ".") == 0 || strcmp(user, "..") == 0)
            return invalid();

        file_len = strlen(file);
        if (file_len == 0 || file_len > 255)
            return invalid();
        if (strcmp(file, ".") == 0 || strcmp(file, "..") == 0)
            return invalid();

        key_len = strlen(key);
        if (key_len == 0 || key_len > 1024)
            return invalid();

        if (!lock_db("enc.db"))
            return invalid();

        if (!load_db("enc.db"))
            goto read_cleanup;

        User *u = find_user(db, user);
        if (!u || !verify_key_constant_time(u, key))
            goto read_cleanup;

        FileEntry *f = find_file(db, user, file);
        if (!f)
            goto read_cleanup;

        if (!decrypt_and_load_aead(f, key, &plaintext, &len))
            goto read_cleanup;

        if (outfile) {
            if (!write_regular_file(outfile, plaintext, len))
                goto read_cleanup;
        } else if (len > 0 && fwrite(plaintext, 1, len, stdout) != len) {
            goto read_cleanup;
        }

        ok = 1;

    read_cleanup:
        if (plaintext) {
            secure_bzero(plaintext, len);
            free(plaintext);
        }

        unlock_db("enc.db");

        return ok ? 0 : invalid();
    }

    return invalid();
}
