#ifndef SHAKE_H
#define SHAKE_H

#include <stdlib.h>
#include "adrs.h"
#include "params.h"

void H_msg(Parameters *prm, const unsigned char *R, const unsigned char *pk_seed, const unsigned char *pk_root, const unsigned char *M, size_t M_len, unsigned char *buffer);

void PRF_msg(Parameters *prm, const unsigned char *sk_prf, const unsigned char *opt_rand, const unsigned char *M, size_t M_len, unsigned char *buffer);

void H(Parameters *prm, const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M2, unsigned char *buffer);

void F(Parameters *prm, const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M1, unsigned char *buffer);

void Tlen(Parameters *prm, const unsigned char *pk_seed, const ADRS *adrs, unsigned char *Ml, size_t Ml_len, unsigned char *buffer);

void PRF(Parameters *prm, const unsigned char *pk_seed, const unsigned char *sk_seed, const ADRS *adrs, unsigned char *buffer);

void SHA_256(const unsigned char *M, size_t M_len, unsigned char *buffer);

void SHA_512(const unsigned char *M, size_t M_len, unsigned char *buffer);

void SHAKE_128(const unsigned char *M, size_t M_len, unsigned char *buffer, unsigned int out_len);

void SHAKE_256(const unsigned char *M, size_t M_len, unsigned char *buffer, unsigned int out_len);

#endif
