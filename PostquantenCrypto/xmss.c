#include <math.h>
#include <string.h>
#include "wots.h"
#include "shake.h"
#include "xmss.h"

// algorithm 9
void xmss_node(Parameters *prm, const unsigned char* sk_seed, int i, int z, const unsigned char* pk_seed, ADRS adrs, unsigned char *buffer)
{
    unsigned char node[prm->n];

    if (z == 0) {
        setTypeAndClear(&adrs, prm->WOTS_HASH);
        setKeyPairAddress(&adrs, i);
        wots_pkGen(prm, sk_seed, pk_seed, adrs, node);
    } else {
        unsigned char lnode[prm->n];
        unsigned char rnode[prm->n];
        xmss_node(prm, sk_seed, i * 2,     z - 1, pk_seed, adrs, lnode);
        xmss_node(prm, sk_seed, i * 2 + 1, z - 1, pk_seed, adrs, rnode);

        setTypeAndClear(&adrs, prm->TREE);
        setTreeHeight(&adrs, z);
        setTreeIndex(&adrs, i);

        // Concatenate lnode and rnode
        unsigned char combined[prm->n * 2];
        memcpy(combined, lnode, prm->n);
        memcpy(combined + prm->n, rnode, prm->n);

        H(prm, pk_seed, &adrs, combined, node);
    }
    memcpy(buffer, node, prm->n);
}

// algorithm 10
void xmss_sign(Parameters *prm, const unsigned char *M, const unsigned char *sk_seed, int idx, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer)
{
    unsigned char AUTH[prm->h_ * prm->n];
    for (int j = 0; j < prm->h_; j++) {
        int k = (int) floor(idx / pow(2, j)) ^ 1;
        // Alternative: int k = (idx >> j) ^ 1;
        xmss_node(prm, sk_seed, k, j, pk_seed, adrs, AUTH + j * prm->n);
    }

    setTypeAndClear(&adrs, prm->WOTS_HASH);
    setKeyPairAddress(&adrs, idx);
    unsigned char sig[prm->len * prm->n];
    wots_sign(prm, M, sk_seed, pk_seed, adrs, sig);

    memcpy(buffer, sig, prm->len * prm->n);
    memcpy(buffer + prm->len * prm->n, AUTH, prm->h_ * prm->n);
}

// algorithm 11
void xmss_pkFromSig(Parameters *prm, int idx, const unsigned char *sig_xmss, const unsigned char *M, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer)
{
    unsigned char node_0[prm->n];
    unsigned char node_1[prm->n];

    setTypeAndClear(&adrs, prm->WOTS_HASH);
    setKeyPairAddress(&adrs, idx);

    unsigned char sig[prm->len * prm->n];
    unsigned char AUTH[prm->h_ * prm->n];
    // NOTE this replaces getWOTSSig and getXMSSAUTH
    memcpy(sig, sig_xmss, prm->len * prm->n);
    memcpy(AUTH, sig_xmss + prm->len * prm->n, prm->h_ * prm->n);

    wots_pkFromSig(prm, sig, M, pk_seed, adrs, node_0);
    setTypeAndClear(&adrs, prm->TREE);
    setTreeIndex(&adrs, idx);

    unsigned char combined[2 * prm->n];
    for (int k = 0; k < prm->h_; k++) {
        setTreeHeight(&adrs, k + 1);
        if ((int) floor(idx / pow(2, k)) % 2 == 0) {
            setTreeIndex(&adrs, getTreeIndex(&adrs) / 2);
            memcpy(combined, node_0, prm->n);
            memcpy(combined + prm->n, AUTH + k * prm->n, prm->n);
            H(prm, pk_seed, &adrs, combined, node_1);
        } else {
            setTreeIndex(&adrs, (getTreeIndex(&adrs) - 1) / 2);
            memcpy(combined, AUTH + k * prm->n, prm->n);
            memcpy(combined + prm->n, node_0, prm->n);
            H(prm, pk_seed, &adrs, combined, node_1);
        }
        memcpy(node_0, node_1, prm->n);
    }
    memcpy(buffer, node_0, prm->n);
}
