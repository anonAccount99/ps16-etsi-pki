#include "include/bbs04_bench.h"
#include "include/gl19_bench.h"
#include "include/klap20_bench.h"
#include "include/ps16_bench.h"
#include <stdio.h>


int main (void) {
    printf("Initializing group signature contexts...\n");

    printf("Setting up BBS04...\n");
    bbs04_bench_ctx_t *bbs04_ctx = bbs04_bench_setup();
    if (!bbs04_ctx) printf("BBS04 setup failed!\n");

    printf("Setting up GL19...\n");
    gl19_bench_ctx_t *gl19_ctx = gl19_bench_setup();
    if (!gl19_ctx) printf("GL19 setup failed!\n");

    printf("Setting up KLAP20...\n");
    klap20_bench_ctx_t *klap20_ctx = klap20_bench_setup();
    if (!klap20_ctx) printf("KLAP20 setup failed!\n");

    printf("Setting up PS16...\n");
    ps16_bench_ctx_t *ps16_ctx = ps16_bench_setup();
    if (!ps16_ctx) printf("PS16 setup failed!\n");

    if (!bbs04_ctx || !gl19_ctx || !klap20_ctx || !ps16_ctx) {
        fprintf(stderr, "Failed to initialize contexts.\n");
        if (bbs04_ctx) bbs04_bench_teardown(bbs04_ctx);
        if (gl19_ctx) gl19_bench_teardown(gl19_ctx);
        if (klap20_ctx) klap20_bench_teardown(klap20_ctx);
        if (ps16_ctx) ps16_bench_teardown(ps16_ctx);
        return 1;
    }

    printf("All contexts initialized successfully!\n");
    printf("Running signature operations...\n");

    printf("Signing with BBS04...\n");
    bbs04_bench_sign(bbs04_ctx);
    printf("Signing with GL19...\n");
    gl19_bench_sign(gl19_ctx);
    printf("Signing with KLAP20...\n");
    klap20_bench_sign(klap20_ctx);
    printf("Signing with PS16...\n");
    ps16_bench_sign(ps16_ctx);

    uint8_t bbs04_ok, gl19_ok, klap20_ok, ps16_ok;

    printf("Verifying BBS04 signature...\n");
    bbs04_ok = bbs04_bench_verify(bbs04_ctx);
    printf("BBS04 verification result: %s\n", bbs04_ok ? "VALID" : "INVALID");

    printf("Verifying GL19 signature...\n");
    gl19_ok = gl19_bench_verify(gl19_ctx);
    printf("GL19 verification result: %s\n", gl19_ok ? "VALID" : "INVALID");

    printf("Verifying KLAP20 signature...\n");
    klap20_ok = klap20_bench_verify(klap20_ctx);
    printf("KLAP20 verification result: %s\n", klap20_ok ? "VALID" : "INVALID");

    printf("Verifying PS16 signature...\n");
    ps16_ok = ps16_bench_verify(ps16_ctx);
    printf("PS16 verification result: %s\n", ps16_ok ? "VALID" : "INVALID");

    printf("Cleaning up...\n");

    bbs04_bench_teardown(bbs04_ctx);
    gl19_bench_teardown(gl19_ctx);
    klap20_bench_teardown(klap20_ctx);
    ps16_bench_teardown(ps16_ctx);

    return 0;
}