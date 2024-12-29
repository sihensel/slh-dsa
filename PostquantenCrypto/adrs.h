#ifndef ADRS_H
#define ADRS_H

#include <stdint.h>

#define ADRS_SIZE 32

typedef struct {
    uint8_t adrs[ADRS_SIZE]; // 32 Byte Address
} ADRS;

void toByte(int x, int n, uint8_t *S);

int toInt(uint8_t *X, int n);

void initADRS(ADRS *adrs);

void setLayerAddress(ADRS *adrs, int l);

void setTreeAddress(ADRS *adrs, int t);

void setTypeAndClear(ADRS *adrs, int Y);

void setKeyPairAddress(ADRS *adrs, int i);

void setChainAddress(ADRS *adrs, int i);

void setTreeHeight(ADRS *adrs, int i);

void setHashAddress(ADRS *adrs, int i);

void setTreeIndex(ADRS *adrs, int i);

int getKeyPairAddress(ADRS *adrs);

int getTreeIndex(ADRS *adrs);

#endif
