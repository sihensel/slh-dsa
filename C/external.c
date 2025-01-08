#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

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

    if (sodium_init() < 0) {
        printf("Error initalizing sodium library\n");
        return;
    }

    /*randombytes_buf(SK_seed, sizeof SK_seed);*/
    /*randombytes_buf(SK_prf , sizeof SK_prf);*/
    /*randombytes_buf(PK_seed, sizeof PK_seed);*/
    /*memcpy(SK_seed, "\xFC\x29\xE8\xD2\x15\x09\xD1\x55\x80\x1D\x88\x85\xCA\xBB\xC9\xE9", prm->n);*/
    /*memcpy(SK_prf,  "\x0C\xD2\x1C\xBF\xC4\x96\x06\xE5\xC5\x16\x45\xB7\xFA\x1C\x95\x4E", prm->n);*/
    /*memcpy(PK_seed, "\xD7\xAA\x10\x48\xA9\xF6\x61\xEA\x58\xFD\x29\x14\x26\x8B\xB0\x15", prm->n);*/
    memcpy(SK_seed, "\x7C\x99\x35\xA0\xB0\x76\x94\xAA\x0C\x6D\x10\xE4\xDB\x6B\x1A\xDD", prm->n);
    memcpy(SK_prf,  "\x2F\xD8\x1A\x25\xCC\xB1\x48\x03\x2D\xCD\x73\x99\x36\x73\x7F\x2D", prm->n);
    memcpy(PK_seed, "\xB5\x05\xD7\xCF\xAD\x1B\x49\x74\x99\x32\x3C\x86\x86\x32\x5E\x47", prm->n);

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
    if (sodium_init() < 0) {
        printf("Error initalizing sodium library\n");
        return;
    }
    // randombytes_buf(addrnd, sizeof addrnd);

    // for deterministic varaiant, use PK_seed for addrnd
    memcpy(addrnd, SK + 2 * prm->n, prm->n);

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
    if (sodium_init() < 0) {
        printf("Error initalizing sodium library\n");
        return;
    }
    // randombytes_buf(addrnd, sizeof addrnd);
    memcpy(addrnd, SK + 2 * prm->n, prm->n);

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
        return false;
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
        return false;
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
        return false;
    }

    uint8_t M_prime[1 + 1 + ctx_len + 11 + sizeof PHM];
    M_prime[0] = 1;
    toByte(ctx_len, 1, M_prime + 1);

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, OID, sizeof OID);
    memcpy(M_prime + 2 + ctx_len + sizeof OID, PHM, sizeof PHM);

    return slh_verify_internal(prm, M_prime, sizeof M_prime, SIG, SIG_len, PK);
}
