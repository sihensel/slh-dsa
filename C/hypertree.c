#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "params.h"
#include "adrs.h"
#include "xmss.h"

// algorithm 12
// Generates a hypertree signature
void ht_sign(Parameters *prm, const uint8_t *M, const uint8_t *sk_seed, const uint8_t *pk_seed, uint32_t idx_tree, uint32_t idx_leaf, unsigned char *buffer)
{
    // length of one XMSS signature
    unsigned int xmss_sig_len = (prm->len + prm->h_) * prm->n;

    ADRS adrs;
    initADRS(&adrs);
    setTreeAddress(&adrs, idx_tree);

    unsigned char sig_tmp[xmss_sig_len];
    unsigned char sig_ht[xmss_sig_len * prm->d];
    xmss_sign(prm, M, sk_seed, idx_leaf, pk_seed, adrs, sig_tmp);
    memcpy(sig_ht, sig_tmp, xmss_sig_len);

    unsigned char root[prm->n];
    xmss_pkFromSig(prm, idx_leaf, sig_tmp, M, pk_seed, adrs, root);

    for (int j = 1; j < prm->d; j++) {
        idx_leaf = idx_tree % (int) pow(2, prm->h_);
        idx_tree = idx_tree >> prm->h_;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);

        xmss_sign(prm, root, sk_seed, idx_leaf, pk_seed, adrs, sig_tmp);
        memcpy(sig_ht + j * xmss_sig_len, sig_tmp, xmss_sig_len);

        if (j < prm->d - 1) {
            xmss_pkFromSig(prm, idx_leaf, sig_tmp, root, pk_seed, adrs, root);
        }
    }
    /*
    for (int i = 0; i < prm->n; i++) {
        printf("%02x", root[i]);
    }
    printf("\n");
    */
    memcpy(buffer, sig_ht, xmss_sig_len * prm->d);
}

// algorithm 13
// Verifies a hypertree signature
bool ht_verify(Parameters *prm, const uint8_t *M, const uint8_t *sig_ht, const uint8_t *pk_seed, uint32_t idx_tree, uint32_t idx_leaf, const uint8_t *pk_root)
{
    // length of one XMSS signature
    unsigned int xmss_sig_len = (prm->len + prm->h_) * prm->n;

    ADRS adrs;
    initADRS(&adrs);
    setTreeAddress(&adrs, idx_tree);

    unsigned char node[prm->n];
    unsigned char sig_tmp[xmss_sig_len];
    // NOTE this replaces getXMSSSignature
    memcpy(sig_tmp, sig_ht, xmss_sig_len);
    xmss_pkFromSig(prm, idx_leaf, sig_tmp, M, pk_seed, adrs, node);

    for (int j = 1; j < prm->d; j++) {
        idx_leaf = idx_tree % (int) pow(2, prm->h_);
        idx_tree = idx_tree >> prm->h_;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);
        // NOTE this replaces getXMSSSignature
        memcpy(sig_tmp, sig_ht + j * xmss_sig_len, xmss_sig_len);
        xmss_pkFromSig(prm, idx_leaf, sig_tmp, node, pk_seed, adrs, node);
    }

    bool result = memcmp(node, pk_root, prm->n);
    return result;
}
