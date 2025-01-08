import hashlib

import params
from adrs import ADRS


def H_msg(R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes) -> bytes:
    h = hashlib.shake_256()
    h.update(R)
    h.update(pk_seed)
    h.update(pk_root)
    h.update(M)
    return h.digest(params.prm.m)


def PRF(pk_seed: bytes, sk_seed: bytes, adrs: ADRS) -> bytes:
    h = hashlib.shake_256()
    h.update(pk_seed)
    h.update(sk_seed)
    h.update(bytearray(adrs.getADRS()))
    return h.digest(params.prm.n)


def PRF_msg(sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
    h = hashlib.shake_256()
    h.update(sk_prf)
    h.update(opt_rand)
    h.update(M)
    return h.digest(params.prm.n)


def F(pk_seed: bytes, adrs: ADRS, M1: bytes|list) -> bytes:
    h = hashlib.shake_256()
    h.update(pk_seed)
    h.update(bytearray(adrs.getADRS()))
    if type(M1) is list:
        for i in M1:
            h.update(i)
    else:
        h.update(M1)
    return h.digest(params.prm.n)
    return shake256(pk_seed, adrs.getADRS(), M1, out_len=params.prm.n)


def H(pk_seed: bytes, adrs: ADRS, M2: bytes) -> bytes:
    h = hashlib.shake_256()
    h.update(pk_seed)
    h.update(bytearray(adrs.getADRS()))
    h.update(M2)
    return h.digest(params.prm.n)


def Tlen(pk_seed: bytes, adrs: ADRS, Ml: list[bytes]) -> bytes:
    h = hashlib.shake_256()
    h.update(pk_seed)
    h.update(bytearray(adrs.getADRS()))
    for i in Ml:
        h.update(i)
    return h.digest(params.prm.n)
