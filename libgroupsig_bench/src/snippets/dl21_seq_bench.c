#include "../include/dl21_seq_bench.h"
#include "../include/input_message.h"

dl21_seq_bench_ctx_t *dl21_seq_bench_setup(void) {

    int rc;
    dl21_seq_bench_ctx_t *ctx = (dl21_seq_bench_ctx_t *) malloc(sizeof(dl21_seq_bench_ctx_t));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(dl21_seq_bench_ctx_t));

    rc = groupsig_init(GROUPSIG_DL21SEQ_CODE, time(NULL));
    if (rc != IOK) { free(ctx); return NULL; }

    groupsig_key_t *isskey = groupsig_mgr_key_init(GROUPSIG_DL21SEQ_CODE);
    if (!isskey) { free(ctx); return NULL; }

    ctx->grpkey = groupsig_grp_key_init(GROUPSIG_DL21SEQ_CODE);
    if (!ctx->grpkey) { groupsig_mgr_key_free(isskey); free(ctx); return NULL; }

    rc = groupsig_setup(GROUPSIG_DL21SEQ_CODE, ctx->grpkey, isskey, NULL);
    if (rc != IOK) { groupsig_grp_key_free(ctx->grpkey); groupsig_mgr_key_free(isskey); free(ctx); return NULL; }

    ctx->memkey = groupsig_mem_key_init(GROUPSIG_DL21SEQ_CODE);
    if (!ctx->memkey) { groupsig_grp_key_free(ctx->grpkey); groupsig_mgr_key_free(isskey); free(ctx); return NULL; }

    message_t *m1 = message_init();
    rc = groupsig_join_mgr(&m1, NULL, isskey, 0, NULL, ctx->grpkey);

    message_t *m2 = message_init();
    if (rc == IOK) rc = groupsig_join_mem(&m2, ctx->memkey, 1, m1, ctx->grpkey);

    message_t *m3 = message_init();
    if (rc == IOK) rc = groupsig_join_mgr(&m3, NULL, isskey, 2, m2, ctx->grpkey);

    message_t *m4 = NULL;
    if (rc == IOK) rc = groupsig_join_mem(&m4, ctx->memkey, 3, m3, ctx->grpkey);

    if (m1) message_free(m1);
    if (m2) message_free(m2);
    if (m3) message_free(m3);
    if (m4) message_free(m4);

    groupsig_mgr_key_free(isskey);

    if (rc != IOK) { dl21_seq_bench_teardown(ctx); return NULL; }

    size_t msg_size;
    char *msg = input_message("cleaned.log", &msg_size);
    if (!msg) {
        perror("input_message");
       return NULL;
    }

    const char *prefix = "{ \"scope\": \"scp\", \"message\": \"";
    const char *suffix = "\" }";

    size_t total = strlen(prefix) + msg_size + strlen(suffix) + 1;
    char *input_str = malloc(total);
    if (!input_str) {
        free(input_str);
        free(msg);
        fputs("Allocation failed\n", stderr);
        return NULL;
    }
    ctx->msg = message_from_string((char *) "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }");
    if (!ctx->msg) { dl21_seq_bench_teardown(ctx); return NULL; }

    ctx->sig = groupsig_signature_init(GROUPSIG_DL21SEQ_CODE);
    if (!ctx->sig) { dl21_seq_bench_teardown(ctx); return NULL; }

    return ctx;
}

void dl21_seq_bench_sign(dl21_seq_bench_ctx_t *ctx) {
    if (!ctx) return;
    groupsig_sign(ctx->sig, ctx->msg, ctx->memkey, ctx->grpkey, UINT_MAX);
}

uint8_t dl21_seq_bench_verify(dl21_seq_bench_ctx_t *ctx) {
    if (!ctx) return 0;
    uint8_t b = 0;
    groupsig_verify(&b, ctx->sig, ctx->msg, ctx->grpkey);
    return b;
}

void dl21_seq_bench_teardown(dl21_seq_bench_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->sig)     groupsig_signature_free(ctx->sig);
    if (ctx->msg)     message_free(ctx->msg);
    if (ctx->memkey)  groupsig_mem_key_free(ctx->memkey);
    if (ctx->grpkey)  groupsig_grp_key_free(ctx->grpkey);
    groupsig_clear(GROUPSIG_DL21SEQ_CODE);
    free(ctx);
}
