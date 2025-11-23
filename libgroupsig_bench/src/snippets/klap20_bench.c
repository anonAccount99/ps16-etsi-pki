#include "../include/klap20_bench.h"
#include "../include/input_message.h"

klap20_bench_ctx_t *klap20_bench_setup(void) {

    int rc;
    klap20_bench_ctx_t *ctx = malloc(sizeof(klap20_bench_ctx_t));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(klap20_bench_ctx_t));

    rc = groupsig_init(GROUPSIG_KLAP20_CODE, time(NULL));
    if (rc != IOK) { free(ctx); return NULL; }

    groupsig_key_t *isskey = groupsig_mgr_key_init(GROUPSIG_KLAP20_CODE);
    groupsig_key_t *opnkey = groupsig_mgr_key_init(GROUPSIG_KLAP20_CODE);
    gml_t          *gml    = gml_init(GROUPSIG_KLAP20_CODE);

    ctx->grpkey = groupsig_grp_key_init(GROUPSIG_KLAP20_CODE);

    if (!isskey || !opnkey || !gml || !ctx->grpkey) { klap20_bench_teardown(ctx); if (isskey) groupsig_mgr_key_free(isskey); if (opnkey) groupsig_mgr_key_free(opnkey); if (gml) gml_free(gml); return NULL; }

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, ctx->grpkey, isskey, gml);
    if (rc != IOK) { klap20_bench_teardown(ctx); groupsig_mgr_key_free(isskey); groupsig_mgr_key_free(opnkey); gml_free(gml); return NULL; }

    rc = groupsig_setup(GROUPSIG_KLAP20_CODE, ctx->grpkey, opnkey, gml);
    if (rc != IOK) { klap20_bench_teardown(ctx); groupsig_mgr_key_free(isskey); groupsig_mgr_key_free(opnkey); gml_free(gml); return NULL; }

    ctx->memkey = groupsig_mem_key_init(GROUPSIG_KLAP20_CODE);
    if (!ctx->memkey) { klap20_bench_teardown(ctx); groupsig_mgr_key_free(isskey); groupsig_mgr_key_free(opnkey); gml_free(gml); return NULL; }

    message_t *m1 = message_init();
    rc = groupsig_join_mgr(&m1, gml, isskey, 0, NULL, ctx->grpkey);

    message_t *m2 = message_init();
    if (rc == IOK) rc = groupsig_join_mem(&m2, ctx->memkey, 1, m1, ctx->grpkey);

    message_t *m3 = message_init();
    if (rc == IOK) rc = groupsig_join_mgr(&m3, gml, isskey, 2, m2, ctx->grpkey);

    message_t *m4 = NULL;
    if (rc == IOK) rc = groupsig_join_mem(&m4, ctx->memkey, 3, m3, ctx->grpkey);

    if (m1) message_free(m1);
    if (m2) message_free(m2);
    if (m3) message_free(m3);
    if (m4) message_free(m4);

    groupsig_mgr_key_free(isskey);
    groupsig_mgr_key_free(opnkey);
    gml_free(gml);

    if (rc != IOK) { klap20_bench_teardown(ctx); return NULL; }

    size_t size = 0;

    ctx->msg = message_from_string(input_message("cleaned.log", &size));
    if (!ctx->msg) { klap20_bench_teardown(ctx); return NULL; }

    ctx->sig = groupsig_signature_init(GROUPSIG_KLAP20_CODE);
    if (!ctx->sig) { klap20_bench_teardown(ctx); return NULL; }

    return ctx;
}

void klap20_bench_sign(klap20_bench_ctx_t *ctx) {
    if (!ctx) return;
    groupsig_sign(ctx->sig, ctx->msg, ctx->memkey, ctx->grpkey, UINT_MAX);
}

uint8_t klap20_bench_verify(klap20_bench_ctx_t *ctx) {
    if (!ctx) return 0;
    uint8_t b = 0;
    groupsig_verify(&b, ctx->sig, ctx->msg, ctx->grpkey);
    return b;
}

void klap20_bench_teardown(klap20_bench_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->sig)     groupsig_signature_free(ctx->sig);
    if (ctx->msg)     message_free(ctx->msg);
    if (ctx->memkey)  groupsig_mem_key_free(ctx->memkey);
    if (ctx->grpkey)  groupsig_grp_key_free(ctx->grpkey);
    groupsig_clear(GROUPSIG_KLAP20_CODE);
    free(ctx);
}
