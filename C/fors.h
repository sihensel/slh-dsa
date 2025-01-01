#pragma once

#include "params.h"
#include "adrs.h"

void fors_skGen(Parameters *prm, const uint8_t *sk_seed, const uint8_t *pk_seed, ADRS adrs, uint32_t idx, uint8_t *buffer);

void fors_node(Parameters *prm, const uint8_t *sk_seed, uint32_t i, uint32_t z, const uint8_t *pk_seed, ADRS adrs, uint8_t *buffer);

void fors_sign(Parameters *prm, const uint8_t *md, const uint8_t *sk_seed, const uint8_t *pk_seed, ADRS adrs, uint8_t *buffer);

void fors_pkFromSig(Parameters *prm, uint8_t *sig_fors, const uint8_t *md, const uint8_t *pk_seed, ADRS adrs, uint8_t *buffer);
