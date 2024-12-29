#ifndef SHAKE_H
#define SHAKE_H

#include "adrs.h"

void H(const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M2, unsigned char *buffer, int out_len);

void F(const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M1, unsigned char *buffer, int out_len);

void Tlen(const unsigned char *pk_seed, const ADRS *adrs, unsigned char *Ml, unsigned char *buffer, int out_len);

void PRF(const unsigned char* pk_seed, const unsigned char* sk_seed, const ADRS* adrs, unsigned char *buffer, int out_len);

#endif
