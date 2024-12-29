#include <math.h>
#include <string.h>
#include "params.h"
#include "shake.h"
#include "wots.h"

// Algorithm 1 (Computes len2)
// NOTE: we don't need this algorithm since len2 = 3 for all parameter sets
int gen_len2(int n, int lg_w)
{
    int w = 1 << lg_w;                          // Compute w: w = 2^lg_w
    int len1 = floor((8.0 * n + lg_w - 1) / lg_w); // Compute len1
    int max_checksum = len1 * (w - 1);          // Compute maximum possible checksum value
    int len2 = 1;                               // Initialize len2
    int capacity = w;                           // Initialize capacity

    while (capacity <= max_checksum) {          // Loop until capacity exceeds max_checksum
        len2++;
        capacity *= w;
    }

    return len2;
}

// Algorithm 4 (Computes the base 2^b representation of X)
void base_2b(const unsigned char *X, int b, int out_len, unsigned char *baseb)
{
    int in_index = 0;                           // Equivalent to `in` in pseudocode
    int bits = 0;                               // Number of bits currently in `total`
    unsigned long long total = 0;               // Accumulates the bit representation

    for (int out = 0; out < out_len; out++) {
        while (bits < b) {                      // Fill `total` with bits until it has at least `b` bits
            total = (total << 8) + X[in_index]; // Add 8 bits from X[in_index]
            in_index += 1;
            bits += 8;
        }

        baseb[out] = (total >> (bits - b)) & ((1ULL << b) - 1); // Extract the `b` least significant bits
        bits -= b;                              // Reduce `bits` by `b` as we've used them
    }
}

// Algorithm 5 (Chaining function used in WOTS+)
void chain(Parameters *prm, const unsigned char *X, int i, int s, const unsigned char *PK_seed, ADRS *adrs, unsigned char *buffer)
{
    unsigned char tmp[prm->n];
    memcpy(tmp, X, prm->n);

    for (int j = i; j < i + s; j++) {
        setHashAddress(adrs, j);
        F(PK_seed, adrs, tmp, tmp, prm->n);
    }
    memcpy(buffer, tmp, prm->n);
}

// Algorithm 6 (Generates a WOTS+ public key)
void wots_pkGen(Parameters *prm, const unsigned char *SK_seed, const unsigned char *PK_seed, ADRS adrs, unsigned char *pk)
{
    ADRS skADRS;
    skADRS = adrs;
    setTypeAndClear(&skADRS, prm->WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(&adrs));

    unsigned char sk[prm->n];
    unsigned char tmp[prm->len * prm->n];
    for (int i = 0; i < prm->len; i++) {
        setChainAddress(&skADRS, i);
        PRF(PK_seed, SK_seed, &skADRS, sk, prm->n);
        setChainAddress(&adrs, i);
        chain(prm, sk, 0, prm->w - 1, PK_seed, &adrs, tmp + i * prm->n);
    }

    ADRS wotspkADRS;
    wotspkADRS = adrs;
    setTypeAndClear(&wotspkADRS, prm->WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(&adrs));
    Tlen(PK_seed, &wotspkADRS, tmp, pk, prm->n);
}

// Algorithm 7 (Generates a WOTS+ signature on an n-byte message)
void wots_sign(Parameters *prm, const unsigned char *M, const unsigned char *SK_seed, const unsigned char *PK_seed, ADRS adrs, unsigned char *sig) {
    unsigned int csum = 0;
    unsigned char msg[prm->len];

    base_2b(M, prm->lg_w, prm->len1, msg);       // Convert message to base w
    for (int i = 0; i < prm->len1; i++) {
        csum += prm->w - 1 - msg[i];            // Compute checksum
    }

    csum <<= 4;

    // csum_bytes has length ceil((prm->len2 * prm->lg_w) / 8.0), which is always 2
    // since len2 and lg_w are static across all parameter sets
    unsigned char csum_bytes[2];
    toByte(csum, 2, csum_bytes);
    base_2b(csum_bytes, prm->lg_w, prm->len2, msg + prm->len1); // Convert to base w

    ADRS skADRS;
    skADRS = adrs;
    setTypeAndClear(&skADRS, prm->WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(&adrs));

    unsigned char sk[prm->n];
    for (int i = 0; i < prm->len; i++) {
        setChainAddress(&skADRS, i);
        PRF(PK_seed, SK_seed, &skADRS, sk, prm->n);
        setChainAddress(&adrs, i);
        chain(prm, sk, 0, msg[i], PK_seed, &adrs, sig + i * prm->n);
    }
}

// Algorithm 8 (Computes a WOTS+ public key from a message and its signature)
void wots_pkFromSig(Parameters *prm, unsigned char *sig, const unsigned char *M, const unsigned char *PK_seed, ADRS adrs, unsigned char *pksig) {
    unsigned int csum = 0;
    unsigned char msg[prm->len];

    base_2b(M, prm->lg_w, prm->len1, msg);       // Convert message to base w
    for (int i = 0; i < prm->len1; i++) {
        csum += prm->w - 1 - msg[i];            // Compute checksum
    }

    csum <<= 4;
    unsigned char csum_bytes[2];
    toByte(csum, 2, csum_bytes);
    base_2b(csum_bytes, prm->lg_w, prm->len2, msg + prm->len1); // Convert to base w

    unsigned char tmp[prm->len * prm->n];
    for (int i = 0; i < prm->len; i++) {
        setChainAddress(&adrs, i);
        chain(prm, sig + i * prm->n, msg[i], prm->w - 1 - msg[i], PK_seed, &adrs, tmp + i * prm->n);
    }

    ADRS wotspkADRS;
    wotspkADRS = adrs;
    setTypeAndClear(&wotspkADRS, prm->WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(&adrs));

    Tlen(PK_seed, &wotspkADRS, tmp, pksig, prm->n);
}
