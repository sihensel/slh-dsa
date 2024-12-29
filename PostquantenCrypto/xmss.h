#ifndef XMSS_H
#define XMSS_H

#include "adrs.h"
#include "params.h"

void xmss_node(Parameters *prm, const unsigned char* sk_seed, int i, int z, const unsigned char* pk_seed, ADRS adrs, unsigned char *buffer);

void xmss_sign(Parameters *prm, const unsigned char *M, const unsigned char *sk_seed, int idx, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer);

void xmss_pkFromSig(Parameters *prm, int idx, const unsigned char *sig_xmss, const unsigned char *M, const unsigned char *pk_seed, ADRS adrs, unsigned char *buffer);

#endif
