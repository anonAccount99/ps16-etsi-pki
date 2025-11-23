#include <groupsig/groupsig.h>
#include "../include/input_message.h"

#include "../include/bbs04_bench.h"


bbs04_bench_ctx_t *bbs04_bench_setup(void)
{
    bbs04_bench_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (groupsig_init(GROUPSIG_BBS04_CODE, time(NULL)) != IOK) {
        free(ctx); return NULL;
    }

    groupsig_key_t *grp = groupsig_grp_key_init(GROUPSIG_BBS04_CODE);
    groupsig_key_t *mgr = groupsig_mgr_key_init(GROUPSIG_BBS04_CODE);
    gml_t          *gml = gml_init(GROUPSIG_BBS04_CODE);

    if (groupsig_setup(GROUPSIG_BBS04_CODE, grp, mgr, gml) != IOK)
        goto err;


    groupsig_key_t *mem = groupsig_mem_key_init(GROUPSIG_BBS04_CODE);
    message_t *m1 = message_init();
    message_t *m2 = message_init();

    if (groupsig_join_mgr(&m1, gml, mgr, 0, NULL, grp) != IOK) goto err;
    if (groupsig_join_mem(&m2, mem, 1,  m1,   grp) != IOK) goto err;

    size_t size = 0;

    ctx->msg    = message_from_string(input_message("cleaned.log", &size));
    ctx->sig    = groupsig_signature_init(GROUPSIG_BBS04_CODE);
    ctx->grpkey = grp;
    ctx->memkey = mem;

    groupsig_mgr_key_free(mgr);
    gml_free(gml);
    message_free(m1); message_free(m2);
    return ctx;

err:
    groupsig_mgr_key_free(mgr);
    gml_free(gml);
    groupsig_grp_key_free(grp);
    free(ctx);
    return NULL;
}

void bbs04_bench_sign(bbs04_bench_ctx_t *ctx)
{
    ctx->sig->scheme = GROUPSIG_BBS04_CODE;
    groupsig_sign(ctx->sig, ctx->msg, ctx->memkey, ctx->grpkey, 0);
}


uint8_t bbs04_bench_verify(bbs04_bench_ctx_t *ctx)
{
    uint8_t ok = 0;
    groupsig_verify(&ok, ctx->sig, ctx->msg, ctx->grpkey);
    return ok;
}


void bbs04_bench_teardown(bbs04_bench_ctx_t *ctx)
{
    if (!ctx) return;
    groupsig_grp_key_free(ctx->grpkey);
    groupsig_mem_key_free(ctx->memkey);
    groupsig_signature_free(ctx->sig);
    message_free(ctx->msg);
    free(ctx);
}
