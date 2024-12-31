#ifndef HYPERTREE_H
#define HYPERTREE_H

#include <stdint.h>
#include <stdbool.h>
#include "params.h"

void ht_sign(Parameters *prm, const uint8_t *M, const uint8_t *sk_seed, const uint8_t *pk_seed, uint32_t idx_tree, uint32_t idx_leaf, unsigned char *buffer);

bool ht_verify(Parameters *prm, const uint8_t *M, const uint8_t *sig_ht, const uint8_t *pk_seed, uint32_t idx_tree, uint32_t idx_leaf, const uint8_t *pk_root);

#endif
