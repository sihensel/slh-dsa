import hashlib
from adrs import ADRS


# FIXME maybe instead of a class we can use types.SimpleNamespace
class Params:
    # global parameter set for SLH-DSA-SHAKE-128s
    n    = 16
    h    = 63
    d    = 7
    h_   = 9    # h' in the specification
    a    = 12
    k    = 14
    lg_w = 4
    m    = 30

    # NOTE lg_w is always 4 for all parameter sets, so the parameters
    # w, len1, len2 and len are always the same
    # see section 5 of specification
    w    = 16           # 2 ** lg_w
    len1 = 2 * n        # math.ceil((8 * n) / lg_w)
    len2 = 3            # can also be optained via wots.gen_l2()
    len = 2 * n + 3     # len1 + len2 = 35

    # ADRS types
    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4
    WOTS_PRF = 5
    FORS_PRF = 6


# wrapper around hashlib.shake_256
def shake256(*data, out_len):
    h = hashlib.new('shake_256')
    for item in data:
        # check if the item is a list of ints or bytes
        match type(item[0]):
            case 'int':
                h.update(bytearray(item))
            case 'bytes':
                h.update(item)
    return h.digest(out_len)

def H_msg(R, pk_seed, pk_root, M):
    return shake256(R, pk_seed, pk_root, M, out_len=8 * Params.m)

def PRF(pk_seed, sk_seed, adrs: ADRS):
    return shake256(pk_seed, adrs.getADRS(), sk_seed, out_len=8 * Params.n)

def PRF_msg(sk_prf, opt_rand, M):
    return shake256(sk_prf, opt_rand, M, out_len=8 * Params.n)

def F(pk_seed, adrs: ADRS, M1):
    return shake256(pk_seed, adrs.getADRS(), M1, out_len=8 * Params.n)

def H(pk_seed, adrs: ADRS, M2):
    return shake256(pk_seed, adrs.getADRS(), M2, out_len=8 * Params.n)

def Tlen(pk_seed, adrs: ADRS, Ml):
    return shake256(pk_seed, adrs.getADRS(), Ml, out_len=8 * Params.n)
