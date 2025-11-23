#ifndef GROUPSIG_DL21_SEQ_BENCH_H
#define GROUPSIG_DL21_SEQ_BENCH_H
#include <groupsig/groupsig.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        groupsig_key_t       *grpkey;
        groupsig_key_t       *memkey;
        message_t            *msg;
        groupsig_signature_t *sig;
    } dl21_seq_bench_ctx_t;

    dl21_seq_bench_ctx_t *dl21_seq_bench_setup(void);
    void               dl21_seq_bench_sign   (dl21_seq_bench_ctx_t *);
    uint8_t            dl21_seq_bench_verify (dl21_seq_bench_ctx_t *);
    void               dl21_seq_bench_teardown(dl21_seq_bench_ctx_t *);

#ifdef __cplusplus
}
#endif
#endif