#include <string.h>
#include <math.h>
#include "params.h"
#include "adrs.h"
#include "shake.h"
#include "wots.h"

// algorithm 14
void fors_skGen(Parameters *prm, const unsigned char *sk_seed, const unsigned char *pk_seed, ADRS adrs, int idx, unsigned char *buffer)
{
    ADRS sk_adrs;
    sk_adrs = adrs;
    setTypeAndClear(&sk_adrs, prm->FORS_PRF);
    setKeyPairAddress(&sk_adrs, getKeyPairAddress(&adrs));
    setTreeIndex(&sk_adrs, idx);
    PRF(prm, pk_seed, sk_seed, &sk_adrs, buffer);
}

// Algorithm 15 (Computes the root of a Merkle subtree of FORS public values)
void fors_node(Parameters *prm, const unsigned char *sk_seed, int i, int z, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer)
{
    unsigned char node[prm->n];

    if (z == 0) {
        unsigned char sk[prm->n];
        fors_skGen(prm, sk_seed, pk_seed, adrs, i, sk);
        setTreeHeight(&adrs, 0);
        setTreeIndex(&adrs, i);
        F(prm, pk_seed, &adrs, sk, node);
    } else {
        unsigned char lnode[prm->n];
        unsigned char rnode[prm->n];
        unsigned char combined[2 * prm->n];

        fors_node(prm, sk_seed, 2 * i,     z - 1, pk_seed, adrs, lnode);
        fors_node(prm, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, rnode);

        setTreeHeight(&adrs, z);
        setTreeIndex(&adrs, i);

        memcpy(combined, lnode, prm->n);
        memcpy(combined + prm->n, rnode, prm->n);

        H(prm, pk_seed, &adrs, combined, node);
    }
    memcpy(buffer, node, prm->n);
}

// Algorithm 16 (Generates a FORS signature)
void fors_sign(Parameters *prm, const unsigned char *md, const unsigned char *sk_seed, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer)
{
    unsigned int sig_len = prm->n + prm->a * prm->n;
    unsigned char sig_fors[sig_len * prm->k];
    unsigned char indices[prm->k];
    unsigned char auth[prm->a * prm->n];
    base_2b(md, prm->a, prm->k, indices);

    for (int i = 0; i < prm->k; i++) {
        fors_skGen(prm, sk_seed, pk_seed, adrs, i * (int) pow(2, prm->a) + indices[i], sig_fors + i * sig_len);

        memset(auth, 0, prm->a * prm->n);
        for (int j = 0; j < prm->a; j++) {
            int s = (int) floor(indices[i] / pow(2, j)) ^ 1;
            fors_node(prm, sk_seed, i * (int) pow(2, prm->a - j) + s, j, pk_seed, adrs, auth + j * prm->n);
        }
        memcpy(sig_fors + i * sig_len + prm->n, auth, prm->a * prm->n);
    }
    memcpy(buffer, sig_fors, sig_len * prm->k);
}

// Algorithm 17 (Computes a FORS public key from a FORS signature)
void fors_pkFromSig(Parameters *prm, unsigned char *sig_fors, const unsigned char *md, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer)
{
    unsigned int sig_len = prm->n + prm->a * prm->n;
    unsigned char indices[prm->k];
    base_2b(md, prm->a, prm->k, indices);

    unsigned char sk[prm->n];
    unsigned char root[prm->k * prm->n];
    unsigned char node_0[prm->n];
    unsigned char node_1[prm->n];
    unsigned char auth[prm->a * prm->n];
    unsigned char combined[2 * prm->n];

    for (int i = 0; i < prm->k; i++) {
        memcpy(sk, sig_fors + i * sig_len, prm->n);
        setTreeHeight(&adrs, 0);
        setTreeIndex(&adrs, i * (int) pow(2, prm->a) + indices[i]);
        F(prm, pk_seed, &adrs, sk, node_0);
        memcpy(auth, sig_fors + i * sig_len + prm->n, prm->a * prm->n);

        for (int j = 0; j < prm->a; j++) {

            setTreeHeight(&adrs, j + 1);
            if ((indices[i] / (int) pow(2, j)) % 2 == 0) {
                setTreeIndex(&adrs, getTreeIndex(&adrs) / 2);
                memcpy(combined, node_0, prm->n);
                memcpy(combined + prm->n, auth + j * prm->n, prm->n);
                H(prm, pk_seed, &adrs, combined, node_1);
            } else {
                setTreeIndex(&adrs, (getTreeIndex(&adrs) - 1) / 2);
                memcpy(combined, auth + j * prm->n, prm->n);
                memcpy(combined + prm->n, node_0, prm->n);
                H(prm, pk_seed, &adrs, combined, node_1);
            }
            memcpy(node_0, node_1, prm->n);
        }
        memcpy(root + i * prm->n, node_0, prm->n);
    }
    ADRS forspkadrs;
    forspkadrs = adrs;
    setTypeAndClear(&forspkadrs, prm->FORS_ROOTS);
    setKeyPairAddress(&forspkadrs, getKeyPairAddress(&adrs));
    Tlen(prm, pk_seed, &forspkadrs, root, prm->k * prm->n, buffer);
}
