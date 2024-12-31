#ifndef INTERNAL_H
#define INTERNAL_H

#include <stdbool.h>
#include <stdlib.h>
#include "params.h"

void slh_keygen_internal(Parameters *prm, unsigned char *sk_seed, unsigned char *sk_prf, unsigned char *pk_seed, unsigned char *SK, unsigned char *PK);

void slh_sign_internal(Parameters *prm, unsigned char *M, size_t M_len, const unsigned char *SK, const unsigned char *addrnd, unsigned char *buffer);

bool slh_verify_internal(Parameters *prm, unsigned char *M, size_t M_len, unsigned char *SIG, size_t SIG_len, const unsigned char *PK);

#endif
