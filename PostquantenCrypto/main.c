/*
   compile with:
   gcc -lm -lgcrypt main.c xmss.c wots.c adrs.c shake.c params.c -o main
*/

#include <stdio.h>
#include <string.h>
#include "wots.h"
#include "xmss.h"

int main(void)
{
    Parameters prm;
    setup_parameter_set(&prm, "SLH-DSA-SHAKE-128s");

    ADRS adrs;
    initADRS(&adrs);
    unsigned char pk[prm.n];
    unsigned char sk_seed[prm.n];
    unsigned char pk_seed[prm.n];

    memset(pk, 0, prm.n);
    memset(sk_seed, 0, prm.n);
    memset(pk_seed, 0, prm.n);

    wots_pkGen(&prm, sk_seed, pk_seed, adrs, pk);
    for (int i = 0; i < prm.n; i++) {
        printf("%02x", pk[i]);
    }
    printf("\n");

    unsigned char M[128];
    unsigned char sig[prm.len * prm.n];
    memset(M, 0, 128);
    memset(sig, 0, prm.len * prm.n);

    wots_sign(&prm, M, sk_seed, pk_seed, adrs, sig);
    for (int i = 0; i < prm.len * prm.n; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");

    unsigned char pksig[prm.n];
    memset(pksig, 0, prm.n);
    wots_pkFromSig(&prm, sig, M, pk_seed, adrs, pksig);
    for (int i = 0; i < prm.n; i++) {
        printf("%02x", pksig[i]);
    }
    printf("\n");

    unsigned char node[prm.n];
    memset(node, 0 , prm.n);
    xmss_node(&prm, sk_seed, 0, 0, pk_seed, adrs, node);
    for (int i = 0; i < prm.n; i++) {
        printf("%02x", node[i]);
    }
    printf("\n");

    unsigned char sig_xmss[(prm.len + prm.h_) * prm.n];
    xmss_sign(&prm, M, sk_seed, 0, pk_seed, adrs, sig_xmss);
    for (int i = 0; i < (prm.len + prm.h_) * prm.n; i++) {
        printf("%02x", sig_xmss[i]);
    }
    printf("\n");

    unsigned char pksig_new[prm.n];
    memset(pksig_new, 0, prm.n);
    xmss_pkFromSig(&prm, 0, sig_xmss, M, pk_seed, adrs, pksig_new);
    for (int i = 0; i < prm.n; i++) {
        printf("%02x", pksig_new[i]);
    }
    printf("\n");

    return 0;
}
