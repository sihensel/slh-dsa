#include <gcrypt.h>
#include "params.h"
#include "adrs.h"

void H_msg(Parameters *prm, const unsigned char *R, const unsigned char *pk_seed, const unsigned char *pk_root, const unsigned char *M, size_t M_len, unsigned char *buffer)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, pk_seed, prm->n);
    gcry_md_write(h, pk_root, prm->n);
    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->m);
    gcry_md_close(h);
}

void PRF_msg(Parameters *prm, const unsigned char *sk_prf, const unsigned char *opt_rand, const unsigned char *M, size_t M_len, unsigned char *buffer)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, sk_prf, prm->n);
    gcry_md_write(h, opt_rand, prm->n);
    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->n);
    gcry_md_close(h);
}

void H(Parameters *prm, const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M2, unsigned char *buffer)
{
    // copy shake256 hash value into buff with len out_len
    // initialize hash context
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    // add data to context
    gcry_md_write(h, pk_seed, prm->n);
    gcry_md_write(h, adrs->adrs, ADRS_SIZE);
    gcry_md_write(h, M2, 2 * prm->n);

    // get the result
    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->n);
    gcry_md_close(h);
}

void F(Parameters *prm, const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M1, unsigned char *buffer)
{
    // copy shake256 hash value into buff with len out_len
    // initialize hash context
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    // add data to context
    gcry_md_write(h, pk_seed, prm->n);
    gcry_md_write(h, adrs->adrs, ADRS_SIZE);
    gcry_md_write(h, M1, prm->n);

    // get the result
    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->n);
    gcry_md_close(h);
}

void Tlen(Parameters *prm, const unsigned char *pk_seed, const ADRS *adrs, unsigned char *Ml, size_t Ml_len, unsigned char *buffer)
{
    // initialize hash context
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    // add data to context
    gcry_md_write(h, pk_seed, prm->n);
    gcry_md_write(h, adrs->adrs, ADRS_SIZE);
    gcry_md_write(h, Ml, Ml_len);

    // get the result
    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->n);
    gcry_md_close(h);
}

void PRF(Parameters *prm, const unsigned char *pk_seed, const unsigned char *sk_seed, const ADRS *adrs, unsigned char *buffer)
{
    // initialize hash context
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    // add data to context
    gcry_md_write(h, pk_seed, prm->n);
    gcry_md_write(h, sk_seed, prm->n);
    gcry_md_write(h, adrs->adrs, ADRS_SIZE);

    // get the result
    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->n);
    gcry_md_close(h);
}

void SHA_256(const unsigned char *M, size_t M_len, unsigned char *buffer)
{
    unsigned char *digest;
    unsigned int digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);

    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    digest = gcry_md_read(h, GCRY_MD_SHA256);
    memcpy(buffer, digest, digest_len);
    gcry_md_close(h);
}

void SHA_512(const unsigned char *M, size_t M_len, unsigned char *buffer)
{
    unsigned char *digest;
    unsigned int digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);

    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    digest = gcry_md_read(h, GCRY_MD_SHA512);
    memcpy(buffer, digest, digest_len);
    gcry_md_close(h);
}

void SHAKE_128(const unsigned char *M, size_t M_len, unsigned char *buffer, unsigned int out_len)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE128, buffer, out_len);
    gcry_md_close(h);
}

void SHAKE_256(const unsigned char *M, size_t M_len, unsigned char *buffer, unsigned int out_len)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, out_len);
    gcry_md_close(h);
}
