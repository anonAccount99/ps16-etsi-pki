#ifndef GROUPSIG_KLAP20_BENCH_H
#define GROUPSIG_KLAP20_BENCH_H
#include <groupsig/groupsig.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        groupsig_key_t       *grpkey;
        groupsig_key_t       *memkey;
        message_t            *msg;
        groupsig_signature_t *sig;
    } klap20_bench_ctx_t;

    klap20_bench_ctx_t *klap20_bench_setup(void);
    void               klap20_bench_sign   (klap20_bench_ctx_t *);
    uint8_t            klap20_bench_verify (klap20_bench_ctx_t *);
    void               klap20_bench_teardown(klap20_bench_ctx_t *);

#ifdef __cplusplus
}
#endif
#endif