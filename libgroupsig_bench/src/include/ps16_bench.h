#ifndef GROUPSIG_PS16_BENCH_H
#define GROUPSIG_PS16_BENCH_H
#include <groupsig/groupsig.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        groupsig_key_t       *grpkey;
        groupsig_key_t       *memkey;
        message_t            *msg;
        groupsig_signature_t *sig;
    } ps16_bench_ctx_t;

    ps16_bench_ctx_t *ps16_bench_setup(void);
    void              ps16_bench_sign(ps16_bench_ctx_t *);
    uint8_t           ps16_bench_verify(ps16_bench_ctx_t *);
    void              ps16_bench_teardown(ps16_bench_ctx_t *);

#ifdef __cplusplus
}
#endif
#endif
