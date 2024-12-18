#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "params.h"
#include "adrs.h"
#include "fors.h"
#include "hypertree.h"
#include "shake.h"
#include "xmss.h"

// Structure to hold key pairs
typedef struct {
    unsigned char *sk_seed;
    unsigned char *sk_prf;
    unsigned char *pk_seed;
    unsigned char *pk_root;
} KeyPair;

// algorithm 18
KeyPair* slh_keygen_internal(unsigned char *sk_seed, unsigned char *sk_prf,
                            unsigned char *pk_seed) {
    ADRS adrs;
    KeyPair *result = malloc(sizeof(KeyPair));

    adrs_setLayerAddress(&adrs, params.d - 1);
    unsigned char *pk_root = xmss_node(sk_seed, 0, params.h_, pk_seed, &adrs);

    // Allocate and copy values
    result->sk_seed = malloc(SK_SEED_SIZE);
    result->sk_prf = malloc(SK_PRF_SIZE);
    result->pk_seed = malloc(PK_SEED_SIZE);
    result->pk_root = pk_root;

    memcpy(result->sk_seed, sk_seed, SK_SEED_SIZE);
    memcpy(result->sk_prf, sk_prf, SK_PRF_SIZE);
    memcpy(result->pk_seed, pk_seed, PK_SEED_SIZE);

    return result;
}

// algorithm 19
unsigned char** slh_sign_internal(unsigned char *M, size_t M_len, KeyPair *SK,
                                unsigned char *addrnd) {
    int param1 = ceil(params.k * params.a / 8.0);
    int param2 = ceil((params.h - params.h / params.d) / 8.0);
    ADRS adrs;

    // Allocate signature array
    unsigned char **SIG = malloc(sizeof(unsigned char*) *
                               (1 + params.k * (1 + params.a) + params.h + params.d * params.len));

    // Generate R using PRF
    unsigned char *R = PRF_msg(SK->sk_prf, addrnd, M, M_len);
    SIG[0] = R;

    // Generate message digest
    unsigned char *digest = H_msg(R, SK->pk_seed, SK->pk_root, M, M_len);
    unsigned char *md = malloc(param1);
    memcpy(md, digest, param1);

    unsigned char *tmp_idx_tree = malloc(param2);
    memcpy(tmp_idx_tree, digest + param1, param2);

    int leaf_bytes = ceil(params.h / (params.d * 8.0));
    unsigned char *tmp_idx_leaf = malloc(leaf_bytes);
    memcpy(tmp_idx_leaf, digest + param1 + param2, leaf_bytes);

    uint64_t idx_tree = toInt(tmp_idx_tree, param2) %
                        (1ULL << (params.h - params.h / params.d));
    uint64_t idx_leaf = toInt(tmp_idx_leaf, leaf_bytes) %
                        (1ULL << (params.h / params.d));

    adrs_setTreeAddress(&adrs, idx_tree);
    adrs_setTypeAndClear(&adrs, params.FORS_TREE);
    adrs_setKeyPairAddress(&adrs, idx_leaf);

    // Generate FORS signature
    unsigned char **SIG_FORS = fors_sign(md, SK->sk_seed, SK->pk_seed, &adrs);

    // Copy FORS signature to main signature
    for(int i = 0; i < params.k * (1 + params.a); i++) {
        SIG[i + 1] = SIG_FORS[i];
    }

    unsigned char *PK_FORS = fors_pkFromSig(SIG_FORS, md, SK->pk_seed, &adrs);

    // Generate and append HT signature
    unsigned char **SIG_HT = ht_sign(PK_FORS, SK->sk_seed, SK->pk_seed,
                                    idx_tree, idx_leaf);

    int ht_start = 1 + params.k * (1 + params.a);
    for(int i = 0; i < params.h + params.d * params.len; i++) {
        SIG[ht_start + i] = SIG_HT[i];
    }

    free(digest);
    free(tmp_idx_tree);
    free(tmp_idx_leaf);
    free(PK_FORS);
    free(SIG_FORS);
    free(SIG_HT);

    return SIG;
}

// algorithm 20
bool slh_verify_internal(unsigned char *M, size_t M_len, unsigned char **SIG,
                        KeyPair *PK) {
    int param1 = ceil(params.k * params.a / 8.0);
    int param2 = ceil((params.h - params.h / params.d) / 8.0);

    if (SIG == NULL || PK == NULL) return false;

    // Verify signature length
    size_t expected_len = 1 + params.k * (1 + params.a) + params.h +
                         params.d * params.len;

    ADRS adrs;
    unsigned char *R = SIG[0];

    // Extract FORS and HT signatures
    unsigned char **SIG_FORS = malloc(sizeof(unsigned char*) *
                                    (params.k * (1 + params.a)));
    for(int i = 0; i < params.k * (1 + params.a); i++) {
        SIG_FORS[i] = SIG[i + 1];
    }

    unsigned char **SIG_HT = malloc(sizeof(unsigned char*) *
                                  (params.h + params.d * params.len));
    int ht_start = 1 + params.k * (1 + params.a);
    for(int i = 0; i < params.h + params.d * params.len; i++) {
        SIG_HT[i] = SIG[ht_start + i];
    }

    unsigned char *digest = H_msg(R, PK->pk_seed, PK->pk_root, M, M_len);
    unsigned char *md = malloc(param1);
    memcpy(md, digest, param1);

    unsigned char *tmp_idx_tree = malloc(param2);
    memcpy(tmp_idx_tree, digest + param1, param2);

    int leaf_bytes = ceil(params.h / (8.0 * params.d));
    unsigned char *tmp_idx_leaf = malloc(leaf_bytes);
    memcpy(tmp_idx_leaf, digest + param1 + param2, leaf_bytes);

    uint64_t idx_tree = toInt(tmp_idx_tree, param2) %
                        (1ULL << (params.h - params.h / params.d));
    uint64_t idx_leaf = toInt(tmp_idx_leaf, leaf_bytes) %
                        (1ULL << (params.h / params.d));

    adrs_setTreeAddress(&adrs, idx_tree);
    adrs_setTypeAndClear(&adrs, params.FORS_TREE);
    adrs_setKeyPairAddress(&adrs, idx_leaf);

    unsigned char *PK_FORS = fors_pkFromSig(SIG_FORS, md, PK->pk_seed, &adrs);

    bool result = ht_verify(PK_FORS, SIG_HT, PK->pk_seed, idx_tree, idx_leaf,
                           PK->pk_root);

    // Cleanup
    free(digest);
    free(md);
    free(tmp_idx_tree);
    free(tmp_idx_leaf);
    free(PK_FORS);
    free(SIG_FORS);
    free(SIG_HT);

    return result;
}

