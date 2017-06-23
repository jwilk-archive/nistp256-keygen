/* Copyright © 2017 Jakub Wilk <jwilk@jwilk.net>
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#define PROGRAM_NAME "nistp256-keygen"

#define xgcry_control(cmd...) \
    do { \
        gcry_error_t ge = gcry_control(cmd); \
        if (ge) { \
            fprintf(stderr, PROGRAM_NAME ": gcry_control(%s) failed: %s\n", #cmd, gcry_strerror(ge)); \
            exit(1); \
        } \
    } while (0)

int main(int argc, char **argv)
{
    long long i, n = 0;
    if (argc == 2) {
        char *endptr;
        errno = 0;
        n = strtoll(argv[1], &endptr, 10);
        if (errno != 0 || *endptr != '\0' || n < 0)
            n = 0;
    }
    if (n == 0) {
        fprintf(stderr, "Usage: " PROGRAM_NAME "<n>\n");
        exit(1);
    }
    char buffer[BUFSIZ];
    int rc = snprintf(buffer, sizeof buffer, "%lld", n);
    if (rc < 0) {
        perror(PROGRAM_NAME ": snprintf() failed");
        exit(1);
    }
    int ndigits = (int) strlen(buffer);
    xgcry_control(GCRYCTL_SET_VERBOSITY, 1);
    xgcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    xgcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
    xgcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    gcry_sexp_t keyparm;
    gcry_error_t ge = gcry_sexp_build(&keyparm, NULL, "(genkey(ecc(curve %s)))", "NIST P-256");
    if (ge) {
        fprintf(stderr, PROGRAM_NAME ": creating S-expression failed: %s\n", gcry_strerror(ge));
        exit(1);
    }
    for (i = 1; i < n; i++) {
        gcry_sexp_t key, kprivate;
        ge = gcry_pk_genkey (&key, keyparm);
        if (ge) {
            fprintf(stderr, PROGRAM_NAME ": key generation key failed: %s\n", gcry_strerror(ge));
            exit(1);
        }
        kprivate = gcry_sexp_find_token(key, "private-key", 0);
        if (!kprivate) {
            fprintf(stderr, PROGRAM_NAME ": key generation failed: invalid return value\n");
            exit(1);
        }
        gcry_sexp_release(key);
        {
            FILE *fp;
            char path[BUFSIZ];
            size_t size = gcry_sexp_sprint(kprivate, GCRYSEXP_FMT_CANON, buffer, sizeof buffer);
            sprintf(path, "%0*lld.key", ndigits, i);
            fp = fopen(path, "wb");
            if (fp == NULL) {
                perror(PROGRAM_NAME ": fopen() failed");
                exit(1);
            }
            fwrite(buffer, 1, size, fp);
            if (fclose(fp) != 0) {
                perror(PROGRAM_NAME ": fclose() failed");
                exit(1);
            }
        }
        gcry_sexp_release(kprivate);
    }
    return 0;
}

/* vim:set ts=4 sw=4 sts=4 et:*/
