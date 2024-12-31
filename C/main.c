/*
   compile with:
   gcc -lm -lgcrypt main.c external.c internal.c fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c -o main
*/

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "external.h"

int main(void)
{
    // init variables
    Parameters prm;
    setup_parameter_set(&prm, "SLH-DSA-SHAKE-128f");

    unsigned char SK[prm.n * 4];
    unsigned char PK[prm.n * 2];
    memset(SK, 0, prm.n * 4);
    memset(PK, 0, prm.n * 2);

    unsigned char M[10];
    unsigned char ctx[1];
    unsigned int sig_len = prm.n + (prm.k * (1 + prm.a) * prm.n) + ((prm.h + prm.d * prm.len) * prm.n);
    unsigned char SIG[sig_len];
    memset(M, 0, sizeof M);
    memset(ctx, 0, sizeof ctx);
    memset(SIG, 0, sizeof SIG);

    // generate keys
    slh_keygen(&prm, SK, PK);

    // test signing M
    slh_sign(&prm, M, sizeof M, ctx, sizeof ctx, SK, SIG);

    bool result = slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, PK);

    if (result == 0) printf("Signature verification successful\n");
    else printf("Signature invalid\n");

    // test signing hash of M
    memset(M, 0, sizeof M);
    memset(ctx, 0, sizeof ctx);
    memset(SIG, 0, sizeof SIG);

    hash_slh_sign(&prm, M, sizeof M, ctx, sizeof ctx, "SHA-256", SK, SIG);
    result = hash_slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, "SHA-256", PK);

    if (result == 0) printf("Signature verification successful\n");
    else printf("Signature invalid\n");

    return 0;
}
