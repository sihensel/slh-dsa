#pragma once

#include <stdint.h>

#define ADRS_SIZE 32

typedef struct {
    uint8_t adrs[ADRS_SIZE]; // 32 Byte Address
} ADRS;

void toByte(uint32_t x, uint32_t n, uint8_t *S);

uint32_t toInt(uint8_t *X, uint32_t n);

void initADRS(ADRS *adrs);

void setLayerAddress(ADRS *adrs, uint32_t l);

void setTreeAddress(ADRS *adrs, uint32_t t);

void setTypeAndClear(ADRS *adrs, uint32_t Y);

void setKeyPairAddress(ADRS *adrs, uint32_t i);

void setChainAddress(ADRS *adrs, uint32_t i);

void setTreeHeight(ADRS *adrs, uint32_t i);

void setHashAddress(ADRS *adrs, uint32_t i);

void setTreeIndex(ADRS *adrs, uint32_t i);

uint32_t getKeyPairAddress(ADRS *adrs);

uint32_t getTreeIndex(ADRS *adrs);
