#include <stdlib.h>
#include <time.h>
#include "../include/input_message.h"
#include "../include/ps16_bench.h"

ps16_bench_ctx_t *ps16_bench_setup(void)
{
    ps16_bench_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (groupsig_init(GROUPSIG_PS16_CODE, time(NULL)) != IOK) {
        free(ctx); return NULL;
    }

    groupsig_key_t *grp = groupsig_grp_key_init(GROUPSIG_PS16_CODE);
    groupsig_key_t *mgr = groupsig_mgr_key_init(GROUPSIG_PS16_CODE);
    gml_t          *gml = gml_init(GROUPSIG_PS16_CODE);
    if (groupsig_setup(GROUPSIG_PS16_CODE, grp, mgr, gml) != IOK)
        goto err_keys;

    groupsig_key_t *mem = groupsig_mem_key_init(GROUPSIG_PS16_CODE);
    message_t *m1 = NULL, *m2 = NULL, *m3 = NULL, *m4 = NULL;

    if (groupsig_join_mgr(&m1, gml, mgr, 0, NULL, grp) != IOK) goto err_join;
    if (groupsig_join_mem(&m2, mem, 1,  m1,   grp) != IOK) goto err_join;
    if (groupsig_join_mgr(&m3, gml, mgr, 2,  m2,   grp) != IOK) goto err_join;
    if (groupsig_join_mem(&m4, mem, 3,  m3,   grp) != IOK) goto err_join;

    size_t size = 0;

    ctx->msg    = message_from_string(input_message("cleaned.log", &size));
    ctx->sig    = groupsig_signature_init(GROUPSIG_PS16_CODE);
    ctx->grpkey = grp;
    ctx->memkey = mem;

    groupsig_mgr_key_free(mgr);
    gml_free(gml);
    message_free(m1); message_free(m2); message_free(m3); message_free(m4);
    return ctx;

err_join:
    groupsig_mem_key_free(mem);
err_keys:
    groupsig_grp_key_free(grp);
    groupsig_mgr_key_free(mgr);
    gml_free(gml);
    free(ctx);
    return NULL;
}


void ps16_bench_sign(ps16_bench_ctx_t *ctx)
{
    ctx->sig->scheme = GROUPSIG_PS16_CODE;
    groupsig_sign(ctx->sig, ctx->msg, ctx->memkey, ctx->grpkey, 0);
}


uint8_t ps16_bench_verify(ps16_bench_ctx_t *ctx)
{
    uint8_t ok = 0;
    groupsig_verify(&ok, ctx->sig, ctx->msg, ctx->grpkey);
    return ok;
}



void ps16_bench_teardown(ps16_bench_ctx_t *ctx)
{
    if (!ctx) return;
    groupsig_grp_key_free(ctx->grpkey);
    groupsig_mem_key_free(ctx->memkey);
    groupsig_signature_free(ctx->sig);
    message_free(ctx->msg);
    free(ctx);
}


#ifdef PS16_BENCH_SELFTEST
int main(void)
{
    ps16_bench_ctx_t *ctx = ps16_bench_setup();
    if (!ctx) { fprintf(stderr, "setup failed\n"); return 1; }

    ps16_bench_sign(ctx);
    uint8_t ok = ps16_bench_verify(ctx);

    printf("PS16 sign-verify %s\n", ok ? "VALID" : "WRONG");
    ps16_bench_teardown(ctx);
    return ok ? 0 : 1;
}
#endif
