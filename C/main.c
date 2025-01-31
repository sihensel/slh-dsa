#include <stdio.h>
#include <string.h>
#include "params.h"
#include "external.h"
#include "internal.h"


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
    /*
    setup_parameter_set(&prm, "SLH-DSA-SHAKE-128f");

    // uint8_t sk_seed[prm.n];
    // uint8_t sk_prf[prm.n];
    // uint8_t pk_seed[prm.n];
    // uint8_t SK[4 * prm.n];
    uint8_t PK[2 * prm.n];
    // memset(SK, 0, prm.n * 4);
    memset(PK, 0, sizeof PK);

    uint32_t sig_len = prm.n + (prm.k * (1 + prm.a) * prm.n) + ((prm.h + prm.d * prm.len) * prm.n);
    uint8_t SIG[sig_len];
    uint8_t M[6286] = {0};
    uint8_t ctx[251] = {0};

    uint8_t c1, c2, sum;

    FILE *fp_key = fopen("key.txt", "r");
    for(uint32_t i = 0; i < sizeof PK; i++) {
        c1 = ascii_to_hex(fgetc(fp_key));
        c2 = ascii_to_hex(fgetc(fp_key));
        sum = c1 << 4 | c2;
        PK[i] = sum;
    }
    fclose(fp_key);

    FILE *fp_msg = fopen("msg.txt", "r");
    for(uint64_t i = 0; i < sizeof M; i++) {
        c1 = ascii_to_hex(fgetc(fp_msg));
        c2 = ascii_to_hex(fgetc(fp_msg));
        sum = c1 << 4 | c2;
        M[i] = sum;
    }
    fclose(fp_msg);

    FILE *fp_sig = fopen("sig.txt", "r");
    for(uint64_t i = 0; i < sizeof SIG; i++) {
        c1 = ascii_to_hex(fgetc(fp_sig));
        c2 = ascii_to_hex(fgetc(fp_sig));
        sum = c1 << 4 | c2;
        SIG[i] = sum;
    }
    fclose(fp_sig);

    FILE *fp_ctx = fopen("ctx.txt", "r");
    for(uint64_t i = 0; i < sizeof ctx; i++) {
        c1 = ascii_to_hex(fgetc(fp_ctx));
        c2 = ascii_to_hex(fgetc(fp_ctx));
        sum = c1 << 4 | c2;
        ctx[i] = sum;
    }
    fclose(fp_ctx);

    bool res = slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, PK);
    if (res == true)
        printf("VALID\n");
    else
        printf("INVALID\n");
    */

    // Our own tests
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

    for (uint32_t i = 0; i < 6; i++) {
        setup_parameter_set(&prm, parameter_sets[i]);

        uint8_t sk_seed[prm.n];
        uint8_t sk_prf[prm.n];
        uint8_t pk_seed[prm.n];
        uint8_t SK[prm.n * 4];
        uint8_t PK[prm.n * 2];
        memset(SK, 0, prm.n * 4);
        memset(PK, 0, prm.n * 2);
        memset(sk_seed, 0, prm.n);
        memset(sk_prf, 0, prm.n);
        memset(pk_seed, 0, prm.n);

        uint8_t M[10];
        uint8_t ctx[1];
        uint32_t sig_len = prm.n + (prm.k * (1 + prm.a) * prm.n) + ((prm.h + prm.d * prm.len) * prm.n);
        uint8_t SIG[sig_len];

        memset(M, 0, sizeof M);
        memset(ctx, 0, sizeof ctx);
        memset(SIG, 0, sizeof SIG);

        // generate keys
        slh_keygen(&prm, sk_seed, sk_prf, pk_seed, SK, PK);

        // test signing M
        slh_sign(&prm, M, sizeof M, ctx, sizeof ctx, SK, SIG, true);

        bool result = slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, PK);

        for (uint32_t j = 0; j < 4; j++) {
            memset(M, 0, sizeof M);
            memset(ctx, 0, sizeof ctx);
            memset(SIG, 0, sizeof SIG);

            // test signing hash of M
            hash_slh_sign(&prm, M, sizeof M, ctx, sizeof ctx, hash_functions[j], SK, SIG, true);
            result = hash_slh_verify(&prm, M, sizeof M, SIG, sizeof SIG, ctx, sizeof ctx, hash_functions[j], PK);
        }
    }

    return EXIT_SUCCESS;
}
