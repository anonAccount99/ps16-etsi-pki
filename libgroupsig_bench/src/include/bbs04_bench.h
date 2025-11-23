#ifndef GROUPSIG_BBS04_BENCH_H
#define GROUPSIG_BBS04_BENCH_H
#include <groupsig/groupsig.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        groupsig_key_t       *grpkey;
        groupsig_key_t       *memkey;
        message_t            *msg;
        groupsig_signature_t *sig;
    } bbs04_bench_ctx_t;

    bbs04_bench_ctx_t *bbs04_bench_setup(void);
    void               bbs04_bench_sign(bbs04_bench_ctx_t *);
    uint8_t            bbs04_bench_verify(bbs04_bench_ctx_t *);
    void               bbs04_bench_teardown(bbs04_bench_ctx_t *);

#ifdef __cplusplus
}
#endif
#endif
