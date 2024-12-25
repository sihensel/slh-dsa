/*
   compile with:
   gcc -lm -lgcrypt main.c wots.c adrs.c shake.c params.c -o main
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wots.h"

int main(void)
{
    Parameters prm;
    setup_parameter_set(&prm, "SLH-DSA-SHAKE-128s");

    ADRS adrs;
    initADRS(&adrs);
    unsigned char pk[8 * prm.n];
    unsigned char sk_seed[8 * prm.n];
    unsigned char pk_seed[8 * prm.n];

    memset(pk, 0, 8 * prm.n);
    memset(sk_seed, 0, 8 * prm.n);
    memset(pk_seed, 0, 8 * prm.n);

    wots_pkGen(&prm, sk_seed, pk_seed, adrs, pk);
    /*for (int i = 0; i < 8 * prm.n; i++) {*/
    /*    printf("%02x", pk[i]);*/
    /*}*/
    /*printf("\n");*/

    unsigned char M[128];
    memset(M, 0, 128);
    unsigned char **sig = malloc(prm.len * sizeof(unsigned char *));
    for (int i = 0; i < prm.len; i++) {
        sig[i] = malloc(8 * prm.n * sizeof *sig[i]);
    }
    wots_sign(&prm, M, sk_seed, pk_seed, adrs, sig);
    printf("%d\n", sig[0][0]);

    unsigned char pksig[8 * prm.n];
    wots_pkFromSig(&prm, sig, M, pk_seed, adrs, pksig);
    printf("%d\n", pksig[0]);

    for (int i = 0; i < prm.len; i++) {
        free(sig[i]);
    }
    free(sig);

    return 0;
}
