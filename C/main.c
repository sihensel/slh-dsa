/*
   compile with:
   gcc -lm -lgcrypt main.c external.c internal.c fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c -o main
   gcc -lm -lgcrypt main.c external.c internal.c fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c -o main -Wall -Wpedantic
*/

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "external.h"

int main(void)
{
    // init variables
    Parameters prm;

    char *parameter_sets[6] = {
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-256f",
        "SLH-DSA-SHAKE-256s"
    };
    char *hash_functions[4] = {
        "SHA-256",
        "SHA-512",
        "SHAKE128",
        "SHAKE256"
    };

    printf("Running all tests...\n");
    for (uint32_t i = 0; i < 6; i++) {
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
        if (result == 0) printf("Signature valid\n");
        else printf("Signature invalid\n");

        for (uint32_t j = 0; j < 4; j++) {
            memset(M, 0, sizeof M);
            memset(ctx, 0, sizeof ctx);
            memset(SIG, 0, sizeof SIG);

            // test signing hash of M
            printf("Signing %s(M)\t", hash_functions[j]);
            hash_slh_sign(&prm, M, sizeof M, ctx, sizeof ctx, hash_functions[j], SK, SIG);
            result = hash_slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, hash_functions[j], PK);

            if (result == 0) printf("Signature valid\n");
            else printf("Signature invalid\n");
        }
    }

    return EXIT_SUCCESS;
}
