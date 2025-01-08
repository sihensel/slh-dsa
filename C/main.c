/*
   compile with:
   gcc -lm -lgcrypt main.c external.c internal.c fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c -o main
   gcc -lm -lgcrypt main.c external.c internal.c fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c -o main -Wall -Wpedantic
*/

#include <stdio.h>
#include <string.h>
#include "params.h"
#include "external.h"


uint32_t ascii_to_hex(char c)
{
    uint32_t num = (int32_t) c;
    if (num < 58 && num > 47)
        return num - 48;
    if (num < 103 && num > 96)
        return num - 87;
    return num;
}

int main(void)
{
    Parameters prm;
    // try verifying test vectors
    // https://github.com/slh-dsa/sloth/blob/main/kat/sphincs-shake-128f-simple.rsp.1
    // https://raw.githubusercontent.com/integritychain/fips205/refs/heads/main/tests/nist_acvp_vectors/SLH-DSA-sigVer-FIPS205/internalProjection.json
    setup_parameter_set(&prm, "SLH-DSA-SHAKE-128f");

    uint8_t SK[4 * prm.n];
    uint8_t PK[2 * prm.n];
    memset(SK, 0, prm.n * 4);
    memset(PK, 0, prm.n * 2);

    uint8_t ctx[1] = {0};
    uint32_t sig_len = prm.n + (prm.k * (1 + prm.a) * prm.n) + ((prm.h + prm.d * prm.len) * prm.n);
    uint8_t SIG[sig_len];
    uint8_t M[4] = {1, 2, 3, 4};

    uint8_t c1, c2, sum;
    FILE *fp = fopen("key.txt", "r");
    for(uint32_t i = 0; i < sizeof PK; i++) {
        c1 = ascii_to_hex(fgetc(fp));
        c2 = ascii_to_hex(fgetc(fp));
        sum = c1 << 4 | c2;
        PK[i] = sum;
        // printf("%02x ",sum);
    }
    // printf("\n");
    fclose(fp);

    FILE *fp_msg = fopen("msg.txt", "r");
    for(uint64_t i = 0; i < sizeof M; i++) {
        c1 = ascii_to_hex(fgetc(fp_msg));
        c2 = ascii_to_hex(fgetc(fp_msg));
        sum = c1 << 4 | c2;
        M[i] = sum;
        // printf("%02x ",sum);
    }
    // printf("\n");
    fclose(fp_msg);

    FILE *fp_sig = fopen("sig.txt", "r");
    for(uint64_t i = 0; i < sizeof SIG; i++) {
        c1 = ascii_to_hex(fgetc(fp_sig));
        c2 = ascii_to_hex(fgetc(fp_sig));
        sum = c1 << 4 | c2;
        SIG[i] = sum;
        // printf("%02x ",sum);
    }
    // printf("\n");
    fclose(fp_sig);

    bool result = slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, PK);
    if (result == true) { printf("Signature valid\n"); }
    else { printf("Signature invalid\n"); }


    return 0;


    // Our own tests
    char *parameter_sets[6] = {
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-192s",
        // NOTE 256 bit parameter sets lead to a floating point exception due to type casts
        // "SLH-DSA-SHAKE-256f",
        // "SLH-DSA-SHAKE-256s"
    };
    char *hash_functions[4] = {
        "SHA-256",
        "SHA-512",
        "SHAKE128",
        "SHAKE256"
    };

    printf("Running all tests...\n");
    for (uint32_t i = 0; i < 4; i++) {
        printf("\nParameter Set %s\n", parameter_sets[i]);
        setup_parameter_set(&prm, parameter_sets[i]);

        uint8_t SK[prm.n * 4];
        uint8_t PK[prm.n * 2];
        memset(SK, 0, prm.n * 4);
        memset(PK, 0, prm.n * 2);

        uint8_t M[10];
        uint8_t ctx[1];
        uint32_t sig_len = prm.n + (prm.k * (1 + prm.a) * prm.n) + ((prm.h + prm.d * prm.len) * prm.n);
        uint8_t SIG[sig_len];

        memset(M, 0, sizeof M);
        memset(ctx, 0, sizeof ctx);
        memset(SIG, 0, sizeof SIG);

        // generate keys
        slh_keygen(&prm, SK, PK);

        printf("SK: ");
        for (uint32_t i = 0; i < 4 * prm.n; i++) {
            printf("%x02", SK[i]);
        }
        printf("\nPK: ");
        for (uint32_t i = 0; i < 2 * prm.n; i++) {
            printf("%x02", PK[i]);
        }
        printf("\n");

        // test signing M
        printf("Signing M\t\t");
        slh_sign(&prm, M, sizeof M, ctx, sizeof ctx, SK, SIG);

        bool result = slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, PK);
        if (result == true) printf("Signature valid\n");
        else printf("Signature invalid\n");

        for (uint32_t j = 0; j < 4; j++) {
            memset(M, 0, sizeof M);
            memset(ctx, 0, sizeof ctx);
            memset(SIG, 0, sizeof SIG);

            // test signing hash of M
            printf("Signing %s(M)\t", hash_functions[j]);
            hash_slh_sign(&prm, M, sizeof M, ctx, sizeof ctx, hash_functions[j], SK, SIG);
            result = hash_slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, hash_functions[j], PK);

            if (result == true) printf("Signature valid\n");
            else printf("Signature invalid\n");
        }
    }

    return EXIT_SUCCESS;
}
