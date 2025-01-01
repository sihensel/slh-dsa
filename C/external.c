#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "adrs.h"
#include "params.h"
#include "internal.h"
#include "shake.h"
#include "external.h"

// Algorithmus 21: Generiert ein SLH-DSA Schlüsselpaar
void slh_keygen(Parameters *prm, uint8_t *SK, uint8_t *PK)
{
    uint8_t SK_seed[prm->n];
    uint8_t SK_prf[prm->n];
    uint8_t PK_seed[prm->n];

    arc4random_buf(SK_seed, sizeof SK_seed);
    arc4random_buf(SK_prf , sizeof SK_prf);
    arc4random_buf(PK_seed, sizeof PK_seed);

    slh_keygen_internal(prm, SK_seed, SK_prf, PK_seed, SK, PK);
}

// Algorithmus 22: Generiert eine reine SLH-DSA Signatur
void slh_sign(Parameters *prm, const uint8_t *M, size_t M_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *SK, uint8_t *SIG)
{
    if (ctx_len > MAX_CTX_LENGTH) {
        printf("Context is longer that %d\n", MAX_CTX_LENGTH);
        return;
    }

    uint8_t addrnd[prm->n];
    arc4random_buf(addrnd, sizeof addrnd);

    uint8_t M_prime[1 + 1 + ctx_len + M_len];
    M_prime[0] = 0;
    toByte(ctx_len, 1, M_prime + 1);

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, M, M_len);

    slh_sign_internal(prm, M_prime, sizeof M_prime, SK, addrnd, SIG);
}

// Algorithmus 23: Generiert eine vorgehashte SLH-DSA Signatur
void hash_slh_sign(Parameters *prm, const uint8_t *M, size_t M_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *SK, uint8_t *SIG)
{
    if (ctx_len > MAX_CTX_LENGTH) {
        printf("Context is longer that %d\n", MAX_CTX_LENGTH);
        return;
    }

    uint8_t addrnd[prm->n];
    arc4random_buf(addrnd, sizeof addrnd);

    uint8_t OID[11];
    uint8_t PHM[64] = {0};

    if (strcmp(PH, "SHA-256") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", 11);
        SHA_256(M, M_len, PHM);
    } else if (strcmp(PH, "SHA-512") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", 11);
        SHA_512(M, M_len, PHM);
    } else if (strcmp(PH, "SHAKE128") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0B", 11);
        SHAKE_128(M, M_len, PHM, 32);
    } else if (strcmp(PH, "SHAKE256") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0C", 11);
        SHAKE_256(M, M_len, PHM, 64);
    } else {
        printf("Unsupported hash function\n");
        printf("Valid values are 'SHA-256', 'SHA-512', 'SHAKE128', 'SHAKE256'\n");
        return;
    }

    uint8_t M_prime[1 + 1 + ctx_len + 11 + sizeof PHM];
    M_prime[0] = 1;
    toByte(ctx_len, 1, M_prime + 1);

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, OID, sizeof OID);
    memcpy(M_prime + 2 + ctx_len + sizeof OID, PHM, sizeof PHM);

    slh_sign_internal(prm, M_prime, sizeof M_prime, SK, addrnd, SIG);
}

// Algorithmus 24: Verifiziert eine reine SLH-DSA Signatur
bool slh_verify(Parameters *prm, const uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, const uint8_t *ctx, size_t ctx_len, const uint8_t *PK)
{
    if (ctx_len > MAX_CTX_LENGTH) {
        printf("Context is longer that %d\n", MAX_CTX_LENGTH);
        return 1;
    }

    uint8_t M_prime[1 + 1 + ctx_len + M_len];
    M_prime[0] = 0;
    toByte(ctx_len, 1, M_prime + 1);

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, M, M_len);

    return slh_verify_internal(prm, M_prime, sizeof M_prime, SIG, SIG_len, PK);
}

// Algorithmus 25: Verifiziert eine vorgehashte SLH-DSA Signatur
bool hash_slh_verify(Parameters *prm, const uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *PK)
{
    if (ctx_len > MAX_CTX_LENGTH) {
        printf("Context is longer that %d\n", MAX_CTX_LENGTH);
        return 1;
    }

    uint8_t OID[11];
    uint8_t PHM[64] = {0};

    if (strcmp(PH, "SHA-256") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", 11);
        SHA_256(M, M_len, PHM);
    } else if (strcmp(PH, "SHA-512") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", 11);
        SHA_512(M, M_len, PHM);
    } else if (strcmp(PH, "SHAKE128") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0B", 11);
        SHAKE_128(M, M_len, PHM, 32);
    } else if (strcmp(PH, "SHAKE256") == 0) {
        memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0C", 11);
        SHAKE_256(M, M_len, PHM, 64);
    } else {
        printf("Unsupported hash function\n");
        printf("Valid values are 'SHA-256', 'SHA-512', 'SHAKE128', 'SHAKE256'\n");
        return 1;
    }

    uint8_t M_prime[1 + 1 + ctx_len + 11 + sizeof PHM];
    M_prime[0] = 1;
    toByte(ctx_len, 1, M_prime + 1);

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, OID, sizeof OID);
    memcpy(M_prime + 2 + ctx_len + sizeof OID, PHM, sizeof PHM);

    return slh_verify_internal(prm, M_prime, sizeof M_prime, SIG, SIG_len, PK);
}
