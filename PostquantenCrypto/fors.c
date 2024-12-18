#include <string.h>
#include <math.h>
#include <stdlib.h>
#include "params.h"
#include "adrs.h"
#include "shake.h"
#include "wots.h"

// algorithm 14
unsigned char* fors_skGen(const unsigned char* sk_seed, const unsigned char* pk_seed,
                         ADRS* adrs, int idx) {
    /*
    Generates a FORS private-key value

    Params:
        sk_seed     secret seed
        pk_seed     public seed
        ADRS        address
        idx         secret key index
    Returns:
        n-byte FORS private key
    */
    ADRS sk_adrs;
    memcpy(&sk_adrs, adrs, sizeof(ADRS));
    setTypeAndClear(&sk_adrs, FORS_PRF);
    setKeyPairAddress(&sk_adrs, getKeyPairAddress(adrs));
    setTreeIndex(&sk_adrs, idx);
    return PRF(pk_seed, sk_seed, &sk_adrs);
}

// Algorithm 15 (Computes the root of a Merkle subtree of FORS public values)
unsigned char* fors_node(const unsigned char* SK_seed, int i, int z,
                        const unsigned char* PK_seed, ADRS* ADRS) {
    unsigned char* node;
    node = malloc(N_BYTES);  // Assuming N_BYTES is the size of hash output

    if (z == 0) {
        unsigned char* sk = fors_skGen(SK_seed, PK_seed, ADRS, i);
        setTreeHeight(ADRS, 0);
        setTreeIndex(ADRS, i);
        F(PK_seed, ADRS, sk, node);
        free(sk);
    } else {
        unsigned char* lnode;
        unsigned char* rnode;
        unsigned char* concatenated_nodes;

        setTreeHeight(ADRS, z - 1);
        lnode = fors_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS);

        setTreeHeight(ADRS, z - 1);
        rnode = fors_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS);

        setTreeHeight(ADRS, z);
        setTreeIndex(ADRS, i);

        concatenated_nodes = malloc(2 * N_BYTES);
        memcpy(concatenated_nodes, lnode, N_BYTES);
        memcpy(concatenated_nodes + N_BYTES, rnode, N_BYTES);

        H(PK_seed, ADRS, concatenated_nodes, node);

        free(lnode);
        free(rnode);
        free(concatenated_nodes);
    }

    return node;
}

// Algorithm 16 (Generates a FORS signature)
unsigned char** fors_sign(const unsigned char* md, const unsigned char* SK_seed,
                         const unsigned char* PK_seed, ADRS* ADRS) {
    unsigned char** SIG_FORS;
    int* indices;
    int total_elements = K * (A + 1);  // K and A from params

    SIG_FORS = malloc(total_elements * sizeof(unsigned char*));
    indices = base_2b(md, A, K);

    for (int i = 0; i < K; i++) {
        SIG_FORS[i * (A + 1)] = fors_skGen(SK_seed, PK_seed, ADRS,
                                          i * (1 << A) + indices[i]);

        for (int j = 0; j < A; j++) {
            int s = (floor(indices[i] / pow(2, j))) ^ 1;
            SIG_FORS[i * (A + 1) + j + 1] = fors_node(SK_seed,
                                                     i * (1 << (A - j)) + s,
                                                     j, PK_seed, ADRS);
        }
    }

    free(indices);
    return SIG_FORS;
}

// Algorithm 17 (Computes a FORS public key from a FORS signature)
unsigned char* fors_pkFromSig(unsigned char** SIG_FORS, const unsigned char* md,
                            const unsigned char* PK_seed, ADRS* ADRS) {
    int* indices = base_2b(md, A, K);
    unsigned char** root = malloc(K * sizeof(unsigned char*));
    unsigned char* node[2];
    unsigned char* pk;

    node[0] = malloc(N_BYTES);
    node[1] = malloc(N_BYTES);

    for (int i = 0; i < K; i++) {
        unsigned char* sk = SIG_FORS[i * (A + 1)];
        setTreeHeight(ADRS, 0);
        setTreeIndex(ADRS, i * (1 << A) + indices[i]);
        F(PK_seed, ADRS, sk, node[0]);

        for (int j = 0; j < A; j++) {
            unsigned char* auth = SIG_FORS[i * (A + 1) + j + 1];
            unsigned char* concatenated_input = malloc(2 * N_BYTES);

            setTreeHeight(ADRS, j + 1);

            if ((indices[i] / (1 << j)) % 2 == 0) {
                setTreeIndex(ADRS, getTreeIndex(ADRS) / 2);
                memcpy(concatenated_input, node[0], N_BYTES);
                memcpy(concatenated_input + N_BYTES, auth, N_BYTES);
            } else {
                setTreeIndex(ADRS, (getTreeIndex(ADRS) - 1) / 2);
                memcpy(concatenated_input, auth, N_BYTES);
                memcpy(concatenated_input + N_BYTES, node[0], N_BYTES);
            }

            H(PK_seed, ADRS, concatenated_input, node[1]);
            memcpy(node[0], node[1], N_BYTES);

            free(concatenated_input);
        }

        root[i] = malloc(N_BYTES);
        memcpy(root[i], node[0], N_BYTES);
    }

    ADRS forspkADRS;
    memcpy(&forspkADRS, ADRS, sizeof(ADRS));
    setTypeAndClear(&forspkADRS, FORS_ROOTS);
    setKeyPairAddress(&forspkADRS, getKeyPairAddress(ADRS));

    pk = Tlen(PK_seed, &forspkADRS, root);

    // Cleanup
    free(node[0]);
    free(node[1]);
    for (int i = 0; i < K; i++) {
        free(root[i]);
    }
    free(root);
    free(indices);

    return pk;
}
