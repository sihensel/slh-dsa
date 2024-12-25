#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

#include "adrs.h"
/*#include "params.h"*/

/*
// Helper function to perform SHAKE256 hash
static unsigned char* shake256_hash(const void** data, size_t* data_lengths,
                                  size_t num_elements, size_t out_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char* output = (unsigned char*)malloc(out_len);

    if (!ctx || !output) {
        return NULL;
    }

    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);

    for (size_t i = 0; i < num_elements; i++) {
        if (data[i]) {
            EVP_DigestUpdate(ctx, data[i], data_lengths[i]);
        }
    }

    EVP_DigestFinalXOF(ctx, output, out_len);
    EVP_MD_CTX_free(ctx);

    return output;
}

// Convert integer to bytes
static unsigned char* int_to_bytes(int value) {
    unsigned char* bytes = (unsigned char*)malloc(16);
    if (!bytes) return NULL;

    for (int i = 15; i >= 0; i--) {
        bytes[i] = value & 0xFF;
        value >>= 8;
    }
    return bytes;
}

unsigned char* H_msg(const unsigned char* R, const unsigned char* pk_seed,
                    const unsigned char* pk_root, const unsigned char* M, size_t M_len) {
    const void* data[] = {R, pk_seed, pk_root, M};
    size_t lengths[] = {R_LEN, PK_SEED_LEN, PK_ROOT_LEN, M_len};

    return shake256_hash(data, lengths, 4, 8 * params.m);
}

unsigned char* PRF_msg(const unsigned char* sk_prf, const unsigned char* opt_rand,
                      const unsigned char* M, size_t M_len) {
    const void* data[] = {sk_prf, opt_rand, M};
    size_t lengths[] = {SK_PRF_LEN, OPT_RAND_LEN, M_len};

    return shake256_hash(data, lengths, 3, 8 * params.n);
}


unsigned char* H(const unsigned char* pk_seed, const ADRS* adrs,
                const unsigned char* M2, size_t M2_len) {
    unsigned char* adrs_bytes = getADRS(adrs);
    const void* data[] = {pk_seed, adrs_bytes, M2};
    size_t lengths[] = {PK_SEED_LEN, ADRS_LEN, M2_len};

    unsigned char* result = shake256_hash(data, lengths, 3, 8 * params.n);
    free(adrs_bytes);
    return result;
}
*/

void F(const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M1, unsigned char *buffer, int out_len)
{
    // copy shake256 hash value into buff with len out_len

    /*unsigned char digest[out_len];*/
    // initialize hash context
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    // add data to context
    gcry_md_write(h, pk_seed, strlen((char *) pk_seed));
    gcry_md_write(h, adrs->adrs, ADRS_SIZE);
    gcry_md_write(h, M1, sizeof M1 / sizeof M1[0]);

    // get the result
    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, out_len);
    gcry_md_close(h);
}

void Tlen(const unsigned char *pk_seed, const ADRS *adrs, unsigned char **Ml, int len, unsigned char *buffer, int out_len)
{
    // initialize hash context
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    // add data to context
    gcry_md_write(h, pk_seed, sizeof pk_seed / sizeof pk_seed[0]);
    gcry_md_write(h, adrs->adrs, ADRS_SIZE);
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < 8 * 16; j++) {
            gcry_md_putc(h, Ml[i][j]);
        }
    }

    // get the result
    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, out_len);
    gcry_md_close(h);
}

void PRF(const unsigned char* pk_seed, const unsigned char* sk_seed, const ADRS* adrs, unsigned char *buffer, int out_len)
{
    // initialize hash context
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    // add data to context
    gcry_md_write(h, pk_seed, sizeof pk_seed / sizeof pk_seed[0]);
    gcry_md_write(h, sk_seed, sizeof sk_seed / sizeof sk_seed[0]);
    gcry_md_write(h, adrs->adrs, ADRS_SIZE);

    // get the result
    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, out_len);
    gcry_md_close(h);
}

