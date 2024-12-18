#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h> // Für Hash-Funktionen

#include "params.h"          // Parameterdatei
#include "adrs.h"            // Hilfsfunktionen für Adressen
#include "internal.h"        // Interne SLH-DSA Funktionen

#define MAX_CTX_LENGTH 255

// Algorithmus 21: Generiert ein SLH-DSA Schlüsselpaar
int slh_keygen(uint8_t **SK, uint8_t **PK) {
    uint8_t SK_seed[PARAM_N];
    uint8_t SK_prf[PARAM_N];
    uint8_t PK_seed[PARAM_N];

    // Zufällige Seeds generieren
    if (!RAND_bytes(SK_seed, PARAM_N) || !RAND_bytes(SK_prf, PARAM_N) || !RAND_bytes(PK_seed, PARAM_N)) {
        return -1; // Fehler beim Generieren
    }

    // Aufruf der internen Schlüsselpaarfunktion
    return slh_keygen_internal(SK_seed, SK_prf, PK_seed, SK, PK);
}

// Algorithmus 22: Generiert eine reine SLH-DSA Signatur
int slh_sign(const uint8_t *M, size_t M_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *SK, uint8_t **SIG) {
    if (ctx_len > MAX_CTX_LENGTH) return -1;

    uint8_t addrnd[PARAM_N];
    if (!RAND_bytes(addrnd, PARAM_N)) return -1;

    uint8_t M_prime[1 + 1 + MAX_CTX_LENGTH + M_len];
    M_prime[0] = 0;
    M_prime[1] = (uint8_t)ctx_len;

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, M, M_len);

    return slh_sign_internal(M_prime, sizeof(M_prime), SK, addrnd, SIG);
}

// Algorithmus 23: Generiert eine vorgehashte SLH-DSA Signatur
int hash_slh_sign(const uint8_t *M, size_t M_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *SK, uint8_t **SIG) {
    if (ctx_len > MAX_CTX_LENGTH) return -1;

    uint8_t addrnd[PARAM_N];
    if (!RAND_bytes(addrnd, PARAM_N)) return -1;

    uint8_t OID[11];
    uint8_t PHM[SHA512_DIGEST_LENGTH];

    if (strcmp(PH, "SHA-256") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", 11);
        SHA256(M, M_len, PHM);
    } else if (strcmp(PH, "SHA-512") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", 11);
        SHA512(M, M_len, PHM);
    } else {
        return -1; // Unsupported hash function
    }

    uint8_t M_prime[1 + 1 + MAX_CTX_LENGTH + 11 + sizeof(PHM)];
    M_prime[0] = 1;
    M_prime[1] = (uint8_t)ctx_len;

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, OID, 11);
    memcpy(M_prime + 2 + ctx_len + 11, PHM, sizeof(PHM));

    return slh_sign_internal(M_prime, sizeof(M_prime), SK, addrnd, SIG);
}

// Algorithmus 24: Verifiziert eine reine SLH-DSA Signatur
int slh_verify(const uint8_t *M, size_t M_len, const uint8_t *SIG, size_t SIG_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *PK) {
    if (ctx_len > MAX_CTX_LENGTH) return 0;

    uint8_t M_prime[1 + 1 + MAX_CTX_LENGTH + M_len];
    M_prime[0] = 0;
    M_prime[1] = (uint8_t)ctx_len;

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, M, M_len);

    return slh_verify_internal(M_prime, sizeof(M_prime), SIG, SIG_len, PK);
}

// Algorithmus 25: Verifiziert eine vorgehashte SLH-DSA Signatur
int hash_slh_verify(const uint8_t *M, size_t M_len, const uint8_t *SIG, size_t SIG_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *PK) {
    if (ctx_len > MAX_CTX_LENGTH) return 0;

    uint8_t OID[11];
    uint8_t PHM[SHA512_DIGEST_LENGTH];

    if (strcmp(PH, "SHA-256") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", 11);
        SHA256(M, M_len, PHM);
    } else if (strcmp(PH, "SHA-512") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", 11);
        SHA512(M, M_len, PHM);
    } else {
        return 0; // Unsupported hash function
    }

    uint8_t M_prime[1 + 1 + MAX_CTX_LENGTH + 11 + sizeof(PHM)];
    M_prime[0] = 1;
    M_prime[1] = (uint8_t)ctx_len;

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, OID, 11);
    memcpy(M_prime + 2 + ctx_len + 11, PHM, sizeof(PHM));

    return slh_verify_internal(M_prime, sizeof(M_prime), SIG, SIG_len, PK);
}

