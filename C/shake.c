#include <gcrypt.h>
#include "params.h"
#include "adrs.h"

void H_msg(Parameters *prm, const uint8_t *R, const uint8_t *pk_seed, const uint8_t *pk_root, const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, pk_seed, prm->n);
    gcry_md_write(h, pk_root, prm->n);
    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->m);
    gcry_md_close(h);
}

void PRF_msg(Parameters *prm, const uint8_t *sk_prf, const uint8_t *opt_rand, const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, sk_prf, prm->n);
    gcry_md_write(h, opt_rand, prm->n);
    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, prm->n);
    gcry_md_close(h);
}

void H(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *M2, uint8_t *buffer)
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

void F(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *M1, uint8_t *buffer)
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

void Tlen(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, uint8_t *Ml, size_t Ml_len, uint8_t *buffer)
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

void PRF(Parameters *prm, const uint8_t *pk_seed, const uint8_t *sk_seed, const ADRS *adrs, uint8_t *buffer)
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

void SHA_256(const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    uint8_t *digest;
    uint32_t digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);

    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    digest = gcry_md_read(h, GCRY_MD_SHA256);
    memcpy(buffer, digest, digest_len);
    gcry_md_close(h);
}

void SHA_512(const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    uint8_t *digest;
    uint32_t digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);

    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    digest = gcry_md_read(h, GCRY_MD_SHA512);
    memcpy(buffer, digest, digest_len);
    gcry_md_close(h);
}

void SHAKE_128(const uint8_t *M, size_t M_len, uint8_t *buffer, uint32_t out_len)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE128, buffer, out_len);
    gcry_md_close(h);
}

void SHAKE_256(const uint8_t *M, size_t M_len, uint8_t *buffer, uint32_t out_len)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, out_len);
    gcry_md_close(h);
}
