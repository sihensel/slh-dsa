#include "adrs.h"

void F(const unsigned char *pk_seed, const ADRS *adrs, const unsigned char *M1, unsigned char *buffer, int out_len);

void Tlen(const unsigned char *pk_seed, const ADRS *adrs, unsigned char **Ml, int len, unsigned char *buffer, int out_len);

void PRF(const unsigned char* pk_seed, const unsigned char* sk_seed, const ADRS* adrs, unsigned char *buffer, int out_len);
