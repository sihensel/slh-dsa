#ifndef FORS_H
#define FORS_H

#include "params.h"
#include "adrs.h"

void fors_skGen(Parameters *prm, const unsigned char *sk_seed, const unsigned char *pk_seed, ADRS adrs, int idx, unsigned char *buffer);

void fors_node(Parameters *prm, const unsigned char *sk_seed, int i, int z, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer);

void fors_sign(Parameters *prm, const unsigned char *md, const unsigned char *sk_seed, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer);

void fors_pkFromSig(Parameters *prm, unsigned char *sig_fors, const unsigned char *md, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer);

#endif
