#ifndef EXTERNAL_H
#define EXTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "params.h"

#define MAX_CTX_LENGTH 255

void slh_keygen(Parameters *prm, unsigned char *SK, unsigned char *PK);

void slh_sign(Parameters *prm, const unsigned char *M, size_t M_len, const unsigned char *ctx, size_t ctx_len, const unsigned char *SK, unsigned char *SIG);

void hash_slh_sign(Parameters *prm, const uint8_t *M, size_t M_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *SK, uint8_t *SIG);

bool slh_verify(Parameters *prm, const uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *PK);

bool hash_slh_verify(Parameters *prm, const uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *PK);

#endif
