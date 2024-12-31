#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "adrs.h"
#include "fors.h"
#include "hypertree.h"
#include "params.h"
#include "shake.h"
#include "xmss.h"

// algorithm 18
void slh_keygen_internal(Parameters *prm, unsigned char *sk_seed, unsigned char *sk_prf, unsigned char *pk_seed, unsigned char *SK, unsigned char *PK)
{
    ADRS adrs;
    initADRS(&adrs);

    setLayerAddress(&adrs, prm->d - 1);
    unsigned char pk_root[prm->n];
    xmss_node(prm, sk_seed, 0, prm->h_, pk_seed, adrs, pk_root);

    memcpy(SK + 0 * prm->n, sk_seed, prm->n);
    memcpy(SK + 1 * prm->n, sk_prf,  prm->n);
    memcpy(SK + 2 * prm->n, pk_seed, prm->n);
    memcpy(SK + 3 * prm->n, pk_root, prm->n);

    memcpy(PK + 0 * prm->n, pk_seed, prm->n);
    memcpy(PK + 1 * prm->n, pk_root, prm->n);
}

// algorithm 19
void slh_sign_internal(Parameters *prm, unsigned char *M, size_t M_len, const unsigned char *SK, const unsigned char *addrnd, unsigned char *buffer)
{
    // NOTE precompute these values to make the code cleaner
    unsigned int param1 = (int) ceil(prm->k * prm->a / 8.0);
    unsigned int param2 = (int) ceil((prm->h - (float)prm->h / prm->d) / 8.0);
    unsigned int param3 = (int) ceil(prm->h / (prm->d * 8.0));

    ADRS adrs;
    initADRS(&adrs);

    unsigned char sk_seed[prm->n];
    unsigned char sk_prf[prm->n];
    unsigned char pk_seed[prm->n];
    unsigned char pk_root[prm->n];
    memcpy(sk_seed, SK + 0 * prm->n, prm->n);
    memcpy(sk_prf,  SK + 1 * prm->n, prm->n);
    memcpy(pk_seed, SK + 2 * prm->n, prm->n);
    memcpy(pk_root, SK + 3 * prm->n, prm->n);

    unsigned int sig_fors_len = prm->k * (1 + prm->a) * prm->n;
    unsigned int sig_ht_len = (prm->h + prm->d * prm->len) * prm->n;
    // signature = Randomness + FORS signature + HT signature
    unsigned char SIG[prm->n + sig_fors_len + sig_ht_len];

    // Generate R using PRF
    unsigned char R[prm->n];
    PRF_msg(prm, sk_prf, addrnd, M, M_len, R);
    memcpy(SIG, R, prm->n);

    // Generate message digest
    unsigned char digest[prm->m];
    H_msg(prm, R, pk_seed, pk_root, M, M_len, digest);
    unsigned char md[param1];
    memcpy(md, digest, param1);

    unsigned char tmp_idx_tree[param2];
    unsigned char tmp_idx_leaf[param3];
    memcpy(tmp_idx_tree, digest + param1, param2);
    memcpy(tmp_idx_leaf, digest + param1 + param2, param3);

    uint64_t idx_tree = toInt(tmp_idx_tree, param2) % (int) pow(2, prm->h - (float)prm->h / prm->d);
    uint64_t idx_leaf = toInt(tmp_idx_leaf, param3) % (int) pow(2, (float)prm->h / prm->d);

    setTreeAddress(&adrs, idx_tree);
    setTypeAndClear(&adrs, prm->FORS_TREE);
    setKeyPairAddress(&adrs, idx_leaf);

    // Generate FORS signature
    unsigned char SIG_FORS[sig_fors_len];
    fors_sign(prm, md, sk_seed, pk_seed, adrs, SIG_FORS);

    // Copy FORS signature to main signature
    memcpy(SIG + prm->n, SIG_FORS, sig_fors_len);

    unsigned char PK_FORS[prm->n];
    fors_pkFromSig(prm, SIG_FORS, md, pk_seed, adrs, PK_FORS);

    // Generate and append HT signature
    unsigned char SIG_HT[sig_ht_len];
    ht_sign(prm, PK_FORS, sk_seed, pk_seed, idx_tree, idx_leaf, SIG_HT);
    memcpy(SIG + prm->n + sig_fors_len, SIG_HT, sig_ht_len);
    memcpy(buffer, SIG, prm->n + sig_fors_len + sig_ht_len);
}

// algorithm 20
bool slh_verify_internal(Parameters *prm, unsigned char *M, size_t M_len, unsigned char *SIG, size_t SIG_len, const unsigned char *PK)
{
    unsigned int param1 = (int) ceil(prm->k * prm->a / 8.0);
    unsigned int param2 = (int) ceil((prm->h - (float)prm->h / prm->d) / 8.0);
    unsigned int param3 = (int) ceil(prm->h / (prm->d * 8.0));

    unsigned int sig_fors_len = prm->k * (1 + prm->a) * prm->n;
    unsigned int sig_ht_len = (prm->h + prm->d * prm->len) * prm->n;
    unsigned int sig_len = prm->n + sig_fors_len + sig_ht_len;

    unsigned char pk_seed[prm->n];
    unsigned char pk_root[prm->n];
    memcpy(pk_seed, PK + 0 * prm->n, prm->n);
    memcpy(pk_root, PK + 1 * prm->n, prm->n);

    if (SIG_len != sig_len) {
        printf("Signature has invalid length\n");
        return false;
    }

    ADRS adrs;
    initADRS(&adrs);

    unsigned char R[prm->n];
    memcpy(R, SIG, prm->n);

    // Extract FORS and HT signatures
    unsigned char SIG_FORS[sig_fors_len];
    memcpy(SIG_FORS, SIG + prm->n, sig_fors_len);

    unsigned char SIG_HT[sig_ht_len];
    memcpy(SIG_HT, SIG + prm->n + sig_fors_len, sig_ht_len);

    unsigned char digest[prm->m];
    H_msg(prm, R, pk_seed, pk_root, M, M_len, digest);
    unsigned char md[param1];
    memcpy(md, digest, param1);

    unsigned char tmp_idx_tree[param2];
    unsigned char tmp_idx_leaf[param3];
    memcpy(tmp_idx_tree, digest + param1, param2);
    memcpy(tmp_idx_leaf, digest + param1 + param2, param3);

    uint64_t idx_tree = toInt(tmp_idx_tree, param2) % (int) pow(2, prm->h - (float)prm->h / prm->d);
    uint64_t idx_leaf = toInt(tmp_idx_leaf, param3) % (int) pow(2, (float)prm->h / prm->d);

    setTreeAddress(&adrs, idx_tree);
    setTypeAndClear(&adrs, prm->FORS_TREE);
    setKeyPairAddress(&adrs, idx_leaf);

    unsigned char PK_FORS[prm->n];
    fors_pkFromSig(prm, SIG_FORS, md, pk_seed, adrs, PK_FORS);

    return ht_verify(prm, PK_FORS, SIG_HT, pk_seed, idx_tree, idx_leaf, pk_root);
}
