#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define ADRS_SIZE 32

typedef struct {
    uint8_t adrs[ADRS_SIZE]; // 32 Byte Address
} ADRS;

// Hilfsfunktion: Wandelt eine Ganzzahl in ein Byte-Array um
void toByte(int x, int n, uint8_t *S) {
    for (int i = 0; i < n; i++) {
        S[n - 1 - i] = x & 0xFF;
        x >>= 8;
    }
}

// Hilfsfunktion: Wandelt ein Byte-Array in eine Ganzzahl um
int toInt(uint8_t *X, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total = 256 * total + X[i];
    }
    return total;
}

// ADRS-Funktionen
void initADRS(ADRS *adrs) {
    memset(adrs->adrs, 0, ADRS_SIZE);
}

void setLayerAddress(ADRS *adrs, int l) {
    toByte(l, 4, adrs->adrs);
}

void setTreeAddress(ADRS *adrs, int t) {
    toByte(t, 12, adrs->adrs + 4);
}

void setTypeAndClear(ADRS *adrs, int Y) {
    toByte(Y, 4, adrs->adrs + 16);
    memset(adrs->adrs + 20, 0, 12);
}

void setKeyPairAddress(ADRS *adrs, int i) {
    toByte(i, 4, adrs->adrs + 20);
}

void setChainAddress(ADRS *adrs, int i) {
    toByte(i, 4, adrs->adrs + 24);
}

void setTreeHeight(ADRS *adrs, int i) {
    toByte(i, 4, adrs->adrs + 24);
}

void setHashAddress(ADRS *adrs, int i) {
    toByte(i, 4, adrs->adrs + 28);
}

void setTreeIndex(ADRS *adrs, int i) {
    toByte(i, 4, adrs->adrs + 28);
}

int getKeyPairAddress(ADRS *adrs) {
    return toInt(adrs->adrs + 20, 4);
}

int getTreeIndex(ADRS *adrs) {
    return toInt(adrs->adrs + 28, 4);
}
