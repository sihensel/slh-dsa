#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "adrs.h"
#include "xmss.h"

// Get one XMSS signature (WOTS+ sig and authentication path) from a hypertree signature
// Params:
//     sig_ht: hypertree signature
//     idx:    index of the XMSS signature in sig_ht
uint8_t* getXMSSSignature(uint8_t* sig_ht, int idx) {
    // hypertree signatures contain d XMSS signatures
    // each XMSS signature is h' + len elements
    int start = idx * (params.h_ + params.len);
    int end = (idx + 1) * (params.h_ + params.len);

    size_t sig_size = end - start;
    uint8_t* result = (uint8_t*)malloc(sig_size);
    memcpy(result, sig_ht + start, sig_size);

    return result;
}

// algorithm 12
// Generates a hypertree signature
uint8_t* ht_sign(const uint8_t* M, const uint8_t* sk_seed, const uint8_t* pk_seed,
                 uint32_t idx_tree, uint32_t idx_leaf) {
    ADRS adrs;
    initADRS(&adrs);
    setTreeAddress(&adrs, idx_tree);

    uint8_t* sig_tmp = xmss_sign(M, sk_seed, idx_leaf, pk_seed, &adrs);
    size_t sig_size = (params.h_ + params.len) * params.d;
    uint8_t* sig_ht = (uint8_t*)malloc(sig_size);
    memcpy(sig_ht, sig_tmp, params.h_ + params.len);

    uint8_t* root = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, &adrs);
    free(sig_tmp);

    for (int j = 1; j < params.d; j++) {
        idx_leaf = idx_tree % (1 << params.h_);
        idx_tree = idx_tree >> params.h_;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);

        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, &adrs);
        memcpy(sig_ht + j * (params.h_ + params.len), sig_tmp, params.h_ + params.len);

        if (j < params.d - 1) {
            uint8_t* new_root = xmss_pkFromSig(idx_leaf, sig_tmp, root, pk_seed, &adrs);
            free(root);
            root = new_root;
        }
        free(sig_tmp);
    }
    free(root);
    return sig_ht;
}

// algorithm 13
// Verifies a hypertree signature
bool ht_verify(const uint8_t* M, const uint8_t* sig_ht, const uint8_t* pk_seed,
               uint32_t idx_tree, uint32_t idx_leaf, const uint8_t* pk_root) {
    ADRS adrs;
    initADRS(&adrs);
    setTreeAddress(&adrs, idx_tree);

    uint8_t* sig_tmp = getXMSSSignature(sig_ht, 0);
    uint8_t* node = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, &adrs);
    free(sig_tmp);

    for (int j = 1; j < params.d; j++) {
        idx_leaf = idx_tree % (1 << params.h_);
        idx_tree = idx_tree >> params.h_;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);

        sig_tmp = getXMSSSignature(sig_ht, j);
        uint8_t* new_node = xmss_pkFromSig(idx_leaf, sig_tmp, node, pk_seed, &adrs);
        free(node);
        node = new_node;
        free(sig_tmp);
    }

    bool result = (memcmp(node, pk_root, params.n) == 0);
    free(node);
    return result;
}

