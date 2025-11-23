#ifndef GROUPSIG_GL19_BENCH_H
#define GROUPSIG_GL19_BENCH_H

#include <groupsig/groupsig.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        groupsig_key_t       *grpkey;
        groupsig_key_t       *memkey;
        message_t            *msg;
        groupsig_signature_t *sig;
    } gl19_bench_ctx_t;

    gl19_bench_ctx_t *gl19_bench_setup(void);
    void              gl19_bench_sign(gl19_bench_ctx_t *);
    uint8_t           gl19_bench_verify(gl19_bench_ctx_t *);
    void              gl19_bench_teardown(gl19_bench_ctx_t *);

#ifdef __cplusplus
}
#endif
#endif /* GROUPSIG_GL19_BENCH_H */

