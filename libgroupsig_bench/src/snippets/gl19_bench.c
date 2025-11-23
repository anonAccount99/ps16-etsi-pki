#include "../include/gl19_bench.h"
#include "../include/input_message.h"

gl19_bench_ctx_t *gl19_bench_setup(void)
{
    gl19_bench_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (groupsig_init(GROUPSIG_GL19_CODE, 0) != IOK) { free(ctx); return NULL; }


    groupsig_key_t *grp = groupsig_grp_key_init(GROUPSIG_GL19_CODE);
    groupsig_key_t *iss = groupsig_mgr_key_init(GROUPSIG_GL19_CODE);
    groupsig_key_t *cnv = groupsig_mgr_key_init(GROUPSIG_GL19_CODE);

    if (groupsig_setup(GROUPSIG_GL19_CODE, grp, iss, NULL) != IOK) goto err;
    if (groupsig_setup(GROUPSIG_GL19_CODE, grp, cnv, NULL) != IOK) goto err;


    groupsig_key_t *mem = groupsig_mem_key_init(GROUPSIG_GL19_CODE);
    message_t *m1=NULL,*m2=NULL,*m3=NULL,*m4=NULL;

    if (groupsig_join_mgr(&m1, NULL, iss, 0, NULL, grp) != IOK) goto err_join;
    if (groupsig_join_mem(&m2,  mem, 1,  m1,   grp) != IOK) goto err_join;
    if (groupsig_join_mgr(&m3, NULL, iss, 2,  m2,   grp) != IOK) goto err_join;
    if (groupsig_join_mem(&m4,  mem, 3,  m3,   grp) != IOK) goto err_join;

    size_t size = 0;

    ctx->msg    = message_from_string(input_message("cleaned.log", &size));
    ctx->sig    = groupsig_signature_init(GROUPSIG_GL19_CODE);
    ctx->grpkey = grp;
    ctx->memkey = mem;

    groupsig_mgr_key_free(iss);
    groupsig_mgr_key_free(cnv);
    message_free(m1); message_free(m2); message_free(m3); message_free(m4);
    return ctx;

err_join:
    groupsig_mem_key_free(mem);
err:
    groupsig_grp_key_free(grp);
    groupsig_mgr_key_free(iss);
    groupsig_mgr_key_free(cnv);
    free(ctx);
    return NULL;
}

void gl19_bench_sign(gl19_bench_ctx_t *ctx)
{
    ctx->sig->scheme = GROUPSIG_GL19_CODE;
    groupsig_sign(ctx->sig, ctx->msg, ctx->memkey, ctx->grpkey, 0);
}

uint8_t gl19_bench_verify(gl19_bench_ctx_t *ctx)
{
    uint8_t ok = 0;
    groupsig_verify(&ok, ctx->sig, ctx->msg, ctx->grpkey);
    return ok;
}

void gl19_bench_teardown(gl19_bench_ctx_t *ctx)
{
    if (!ctx) return;
    groupsig_grp_key_free(ctx->grpkey);
    groupsig_mem_key_free(ctx->memkey);
    groupsig_signature_free(ctx->sig);
    message_free(ctx->msg);
    free(ctx);
}
