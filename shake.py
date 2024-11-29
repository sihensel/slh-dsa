import hashlib

import params
from adrs import ADRS


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
    return shake256(R, pk_seed, pk_root, M, out_len=8 * params.prm.m)


def PRF(pk_seed: bytes, sk_seed: bytes, adrs: ADRS) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), sk_seed, out_len=8 * params.prm.n)


def PRF_msg(sk_prf: bytes, opt_rand: bytes, M: list|bytes) -> bytes:
    return shake256(sk_prf, opt_rand, M, out_len=8 * params.prm.n)


def F(pk_seed: bytes, adrs: ADRS, M1: list|bytes) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), M1, out_len=8 * params.prm.n)


def H(pk_seed: bytes, adrs: ADRS, M2: list|bytes) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), M2, out_len=8 * params.prm.n)


def Tlen(pk_seed: bytes, adrs: ADRS, Ml: list|bytes) -> bytes:
    return shake256(pk_seed, adrs.getADRS(), Ml, out_len=8 * params.prm.n)
