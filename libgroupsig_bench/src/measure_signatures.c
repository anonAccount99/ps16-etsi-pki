#include <stdio.h>
#include <stdlib.h>
#include <groupsig/groupsig.h>

#include "include/bbs04_bench.h"
#include "include/dl21_seq_bench.h"
#include "include/gl19_bench.h"
#include "include/klap20_bench.h"
#include "include/ps16_bench.h"

size_t get_signature_size(groupsig_signature_t *sig) {
    byte_t *bytes = NULL;
    uint32_t size = 0;

    if (groupsig_signature_export(&bytes, &size, sig) != IOK) {
        fprintf(stderr, "Error exporting signature\n");
        return 0;
    }

    if (bytes) free(bytes);

    return (size_t)size;
}

void print_signature_sizes(const char *scheme_name, size_t size) {
    printf("| %-15s | %8zu bytes |\n", scheme_name, size);
}

int main(void) {
    size_t sig_size;

    printf("\n");
    printf("+----------------+---------------+\n");
    printf("| Signature      | Size          |\n");
    printf("| Scheme         |               |\n");
    printf("+----------------+---------------+\n");

    {
        bbs04_bench_ctx_t *ctx = bbs04_bench_setup();
        if (ctx) {
            bbs04_bench_sign(ctx);
            sig_size = get_signature_size(ctx->sig);
            print_signature_sizes("BBS04", sig_size);
            bbs04_bench_teardown(ctx);
        }
    }

    {
        dl21_seq_bench_ctx_t *ctx = dl21_seq_bench_setup();
        if (ctx) {
            dl21_seq_bench_sign(ctx);
            sig_size = get_signature_size(ctx->sig);
            print_signature_sizes("DL21_SEQ", sig_size);
            dl21_seq_bench_teardown(ctx);
        }
    }

    {
        gl19_bench_ctx_t *ctx = gl19_bench_setup();
        if (ctx) {
            gl19_bench_sign(ctx);
            sig_size = get_signature_size(ctx->sig);
            print_signature_sizes("GL19", sig_size);
            gl19_bench_teardown(ctx);
        }
    }

    {
        klap20_bench_ctx_t *ctx = klap20_bench_setup();
        if (ctx) {
            klap20_bench_sign(ctx);
            sig_size = get_signature_size(ctx->sig);
            print_signature_sizes("KLAP20", sig_size);
            klap20_bench_teardown(ctx);
        }
    }

    {
        ps16_bench_ctx_t *ctx = ps16_bench_setup();
        if (ctx) {
            ps16_bench_sign(ctx);
            sig_size = get_signature_size(ctx->sig);
            print_signature_sizes("PS16", sig_size);
            ps16_bench_teardown(ctx);
        }
    }

    printf("+----------------+---------------+\n");

    return 0;
}
