import hashlib
from types import SimpleNamespace

from adrs import ADRS


def setup_parameter_set(name: str) -> SimpleNamespace:
    p = SimpleNamespace()

    # these are the same for all parameter sets
    p.WOTS_HASH = 0
    p.WOTS_PK = 1
    p.TREE = 2
    p.FORS_TREE = 3
    p.FORS_ROOTS = 4
    p.WOTS_PRF = 5
    p.FORS_PRF = 6
    p.lg_w = 4
    p.w = 16
    p.len2 = 3

    if name == "SLH-DSA-SHAKE-128s":
        p.n = 16
        p.h = 63
        p.d = 7
        p.h_ = 9
        p.a = 12
        p.k = 14
        p.m = 30

    elif name == "SLH-DSA-SHAKE-128f":
        p.n = 16
        p.h = 66
        p.d = 22
        p.h_ = 3
        p.a = 6
        p.k = 33
        p.m = 34

    elif name == "SLH-DSA-SHAKE-192s":
        p.n = 24
        p.h = 63
        p.d = 7
        p.h_ = 9
        p.a = 14
        p.k = 17
        p.m = 39

    elif name == "SLH-DSA-SHAKE-192f":
        p.n = 24
        p.h = 66
        p.d = 22
        p.h_ = 3
        p.a = 8
        p.k = 33
        p.m = 42

    elif name == "SLH-DSA-SHAKE-256s":
        p.n = 32
        p.h = 64
        p.d = 8
        p.h_ = 8
        p.a = 14
        p.k = 22
        p.m = 47

    elif name == "SLH-DSA-SHAKE-256s":
        p.n = 32
        p.h = 68
        p.d = 17
        p.h_ = 4
        p.a = 9
        p.k = 35
        p.m = 49

    else:
        print("invalid parameter set")
        exit()

    # calculate len1 and len
    p.len1 = 2 * p.n
    p.len = p.len1 + p.len2

    return p


Params = setup_parameter_set("SLH-DSA-SHAKE-128f")


# wrapper around hashlib.shake_256
def shake256(*data, out_len: int) -> bytes:
    h = hashlib.shake_256()
    for item in data:
        if type(item) is int:
            h.update(item.to_bytes(16))
        elif type(item) is bytes:
            h.update(item)
        # if we get a list, add each element individually to update()
        elif type(item) is list:
            for elem in item:
                if type(elem) is int:
                    h.update(elem.to_bytes(16))
                elif type(elem) is bytes:
                    h.update(elem)
        else:
            print("shake256: unknown data type")
    return h.digest(out_len)


def H_msg(R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes|list) -> bytes:
    return shake256(R, pk_seed, pk_root, M, out_len=8 * Params.m)


def PRF(pk_seed: bytes, sk_seed: bytes, adrs: ADRS) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), sk_seed, out_len=8 * Params.n)


def PRF_msg(sk_prf: bytes, opt_rand: bytes, M: list|bytes) -> bytes:
    return shake256(sk_prf, opt_rand, M, out_len=8 * Params.n)


def F(pk_seed: bytes, adrs: ADRS, M1: list|bytes) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), M1, out_len=8 * Params.n)


def H(pk_seed: bytes, adrs: ADRS, M2: list|bytes) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), M2, out_len=8 * Params.n)


def Tlen(pk_seed: bytes, adrs: ADRS, Ml: list|bytes) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), Ml, out_len=8 * Params.n)
