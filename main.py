import time

from external import slh_keygen, slh_sign, slh_verify
from external import hash_slh_sign, hash_slh_verify


def main(M: bytes,
         gen_keypair: bool=False,
         sign_msg_hash: bool=True,
         sk_seed: int=0,
         sk_prf: int=0,
         pk_seed :int=0,
         pk_root: int=0
    ):

    if gen_keypair:
        SK, PK = slh_keygen()
        print("sk_seed:", int.from_bytes(SK[0]))
        print("sk_prf: ", int.from_bytes(SK[1]))
        print("pk_seed:", int.from_bytes(SK[2]))
        print("pk_root:", int.from_bytes(SK[3]))
    else:
        SK = (sk_seed.to_bytes(16), sk_prf.to_bytes(16), pk_seed.to_bytes(16), pk_root.to_bytes(16))
        PK = (pk_seed.to_bytes(16), pk_root.to_bytes(16))

    # ctx is usually initialized as an empty byte array
    ctx = [0]

    if sign_msg_hash:
        # create signature of hash(M) and verify
        hash_sig = hash_slh_sign(M, ctx, "SHA-256", SK)
        return hash_slh_verify(M, hash_sig, ctx, "SHA-256", PK)
    else:
        # create signature of M and verify
        sig = slh_sign(M, ctx, SK)
        return slh_verify(M, sig, ctx, PK)


if __name__ == "__main__":
    # FIXME maybe add CLI interface via argparse
    # FIXME find a way to call params.setup_parameter_set
    M = b"1234"

    start = time.time()
    result = main(M=M, gen_keypair=True, sign_msg_hash=True)
    end = time.time()
    print("signature valid") if result else print("signature invalid")
    print(f"Took {end - start} seconds")
