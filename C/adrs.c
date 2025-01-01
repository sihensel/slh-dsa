#include <stdint.h>
#include <string.h>
#include "adrs.h"

// Hilfsfunktion: Wandelt eine Ganzzahl in ein Byte-Array um
void toByte(uint32_t x, uint32_t n, uint8_t *S)
{
    for (uint32_t i = 0; i < n; i++) {
        S[n - 1 - i] = x % 256;
        x >>= 8;
    }
}

// Hilfsfunktion: Wandelt ein Byte-Array in eine Ganzzahl um
uint32_t toInt(uint8_t *X, uint32_t n) {
    uint32_t total = 0;
    for (uint32_t i = 0; i < n; i++) {
        total = 256 * total + X[i];
    }
    return total;
}

// ADRS-Funktionen
void initADRS(ADRS *adrs) {
    memset(adrs->adrs, 0, ADRS_SIZE);
}

void setLayerAddress(ADRS *adrs, uint32_t l) {
    toByte(l, 4, adrs->adrs);
}

void setTreeAddress(ADRS *adrs, uint32_t t) {
    toByte(t, 12, adrs->adrs + 4);
}

void setTypeAndClear(ADRS *adrs, uint32_t Y) {
    toByte(Y, 4, adrs->adrs + 16);
    memset(adrs->adrs + 20, 0, 12);
}

void setKeyPairAddress(ADRS *adrs, uint32_t i) {
    toByte(i, 4, adrs->adrs + 20);
}

void setChainAddress(ADRS *adrs, uint32_t i) {
    toByte(i, 4, adrs->adrs + 24);
}

void setTreeHeight(ADRS *adrs, uint32_t i) {
    toByte(i, 4, adrs->adrs + 24);
}

void setHashAddress(ADRS *adrs, uint32_t i) {
    toByte(i, 4, adrs->adrs + 28);
}

void setTreeIndex(ADRS *adrs, uint32_t i) {
    toByte(i, 4, adrs->adrs + 28);
}

uint32_t getKeyPairAddress(ADRS *adrs) {
    return toInt(adrs->adrs + 20, 4);
}

uint32_t getTreeIndex(ADRS *adrs) {
    return toInt(adrs->adrs + 28, 4);
}
