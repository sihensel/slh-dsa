#ifndef WOTS_H
#define WOTS_H

#include "adrs.h"
#include "params.h"

int gen_len2(int n, int lg_w);

void base_2b(const unsigned char *X, int b, int out_len, unsigned char *baseb);

void chain(Parameters *prm, const unsigned char *X, int i, int s, const unsigned char *PK_seed, ADRS *adrs, unsigned char *buffer);

void wots_pkGen(Parameters *prm, const unsigned char *SK_seed, const unsigned char *PK_seed, ADRS adrs, unsigned char *pk);

void wots_sign(Parameters *prm, const unsigned char *M, const unsigned char *SK_seed, const unsigned char *PK_seed, ADRS adrs, unsigned char *sig);

void wots_pkFromSig(Parameters *prm, unsigned char *sig, const unsigned char *M, const unsigned char *PK_seed, ADRS adrs, unsigned char *pksig);

#endif
