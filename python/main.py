#!/usr/bin/env python3

import time

from external import slh_keygen, slh_sign, slh_verify
from external import hash_slh_sign, hash_slh_verify
from params import setup_parameter_set


def main(M: bytes,
         gen_keypair: bool=False,
         sign_msg_hash: bool=False,
         verify: bool=False,
         SK: tuple[bytes, bytes, bytes, bytes]=(b"", b"", b"", b""),
         PK: tuple[bytes, bytes]=(b"", b""),
         sig: list[bytes]=[],
         parameter_set: str="SLH-DSA-SHAKE-128f"
    ) -> bool:

    setup_parameter_set(parameter_set)

    if gen_keypair:
        SK, PK = slh_keygen()
        with open("key.txt", "w") as fp:
            print("writing key data into key.txt")
            fp.write(SK[0].hex() + SK[1].hex() + SK[2].hex() + SK[3].hex() + "\n")
            fp.write(SK[2].hex() + SK[3].hex() + "\n")

    # ctx is usually initialized as an empty byte array
    ctx = [0]

    if sign_msg_hash:
        if verify:
            return hash_slh_verify(M, sig, ctx, "SHA-256", PK)
        else:
            # create signature of hash(M) and verify
            sig = hash_slh_sign(M, ctx, "SHA-256", SK)
            with open("sig.txt", "w") as fp:
                print("writing signature to signature.txt")
                data = [i.hex() for i in sig]
                for i in data:
                    fp.write(i + "\n")
    else:
        if verify:
            return slh_verify(M, sig, ctx, PK)
        else:
            # create signature of M and verify
            sig = slh_sign(M, ctx, SK)
            with open("sig.txt", "w") as fp:
                print("writing signature to signature.txt")
                data = [i.hex() for i in sig]
                for i in data:
                    fp.write(i + "\n")
    return True


if __name__ == "__main__":

    M = b"Hello World"

    # read key data from file
    with open("key.txt", "r") as fp:
        data = [line.rstrip() for line in fp]
        SK = bytes.fromhex(data[0])
        SK = (SK[0:16], SK[16:32], SK[32:48], SK[48:])
        PK = bytes.fromhex(data[1])
        PK = (PK[0:16], PK[16:])

    # read signature from file
    with open("sig.txt", "r") as fp:
        data = [line.rstrip() for line in fp]
        sig = [bytes.fromhex(i) for i in data]

    verify = True
    start = time.time()
    result = main(M=M,
                  gen_keypair=False,
                  sign_msg_hash=False,
                  verify=verify,
                  SK=SK,
                  PK=PK,
                  sig=sig,
                  parameter_set="SLH-DSA-SHAKE-128f"
                  )
    end = time.time()
    print(f"Took {end - start} seconds")
    if verify:
        print("signature valid") if result else print("signature invalid")
