#include <math.h>
#include "params.h"
#include "adrs.h"
#include "shake.h"
#include "wots.h"

// algorithm 9
unsigned char* xmss_node(unsigned char* sk_seed, int i, int z,
                        unsigned char* pk_seed, ADRS* adrs) {
    unsigned char* node;

    if (z == 0) {
        adrs_setTypeAndClear(adrs, params.WOTS_HASH);
        adrs_setKeyPairAddress(adrs, i);
        node = wots_pkGen(sk_seed, pk_seed, adrs);
    } else {
        unsigned char* lnode = xmss_node(sk_seed, i * 2, z - 1, pk_seed, adrs);
        unsigned char* rnode = xmss_node(sk_seed, i * 2 + 1, z - 1, pk_seed, adrs);

        adrs_setTypeAndClear(adrs, params.TREE);
        adrs_setTreeHeight(adrs, z);
        adrs_setTreeIndex(adrs, i);

        // Concatenate lnode and rnode
        unsigned char combined[2 * N];
        memcpy(combined, lnode, N);
        memcpy(combined + N, rnode, N);

        node = H(pk_seed, adrs, combined);

        free(lnode);
        free(rnode);
    }
    return node;
}

// algorithm 10
unsigned char** xmss_sign(unsigned char* M, unsigned char* sk_seed,
                         int idx, unsigned char* pk_seed, ADRS* adrs) {
    unsigned char** AUTH = (unsigned char**)malloc(params.h_ * sizeof(unsigned char*));
    for (int j = 0; j < params.h_; j++) {
        int k = (int)floor(idx / pow(2, j)) ^ 1;
        // Alternative: int k = (idx >> j) ^ 1;
        AUTH[j] = xmss_node(sk_seed, k, j, pk_seed, adrs);
    }

    adrs_setTypeAndClear(adrs, params.WOTS_HASH);
    adrs_setKeyPairAddress(adrs, idx);
    unsigned char** sig = wots_sign(M, sk_seed, pk_seed, adrs);

    // Combine sig and AUTH into sig_xmss
    unsigned char** sig_xmss = (unsigned char**)malloc((params.len + params.h_) * sizeof(unsigned char*));
    memcpy(sig_xmss, sig, params.len * sizeof(unsigned char*));
    memcpy(sig_xmss + params.len, AUTH, params.h_ * sizeof(unsigned char*));

    free(AUTH);
    free(sig);
    return sig_xmss;
}

// algorithm 11
unsigned char* xmss_pkFromSig(int idx, unsigned char** sig_xmss,
                             unsigned char* M, unsigned char* pk_seed, ADRS* adrs) {
    unsigned char* node[2];
    node[0] = (unsigned char*)malloc(N * sizeof(unsigned char));
    node[1] = (unsigned char*)malloc(N * sizeof(unsigned char));

    adrs_setTypeAndClear(adrs, params.WOTS_HASH);
    adrs_setKeyPairAddress(adrs, idx);

    unsigned char** sig = getWOTSSig(sig_xmss);
    unsigned char** AUTH = getXMSSAUTH(sig_xmss);

    memcpy(node[0], wots_pkFromSig(sig, M, pk_seed, adrs), N);
    adrs_setTypeAndClear(adrs, params.TREE);
    adrs_setTreeIndex(adrs, idx);

    for (int k = 0; k < params.h_; k++) {
        adrs_setTreeHeight(adrs, k + 1);
        if ((int)floor(idx / pow(2, k)) % 2 == 0) {
            adrs_setTreeIndex(adrs, adrs_getTreeIndex(adrs) / 2);
            unsigned char combined[2 * N];
            memcpy(combined, node[0], N);
            memcpy(combined + N, AUTH[k], N);
            memcpy(node[1], H(pk_seed, adrs, combined), N);
        } else {
            adrs_setTreeIndex(adrs, (adrs_getTreeIndex(adrs) - 1) / 2);
            unsigned char combined[2 * N];
            memcpy(combined, AUTH[k], N);
            memcpy(combined + N, node[0], N);
            memcpy(node[1], H(pk_seed, adrs, combined), N);
        }
        memcpy(node[0], node[1], N);
    }

    unsigned char* result = (unsigned char*)malloc(N * sizeof(unsigned char));
    memcpy(result, node[0], N);
    free(node[1]);
    return result;
}

unsigned char** getWOTSSig(unsigned char** sig_xmss) {
    unsigned char** wots_sig = (unsigned char**)malloc(params.len * sizeof(unsigned char*));
    memcpy(wots_sig, sig_xmss, params.len * sizeof(unsigned char*));
    return wots_sig;
}

unsigned char** getXMSSAUTH(unsigned char** sig_xmss) {
    unsigned char** auth = (unsigned char**)malloc(params.h_ * sizeof(unsigned char*));
    memcpy(auth, sig_xmss + params.len, params.h_ * sizeof(unsigned char*));
    return auth;
}

