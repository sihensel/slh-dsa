from hashlib import shake_256
from adrs import ADRS

# global parameter set for SLH-DSA-SHAKE-128s
n = 16
h =63
d = 7
h_ = 9
a = 12
k = 14
lg_w = 4
m = 30

# ADRS types
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6


def H_msg(R, pk_seed, pk_root, M):
    # FIXME according to the specification, the input to shake are concatenated lists
    # we need to check how our input parameters look like
    return shake_256(R + pk_seed + pk_root + M).hexdigest(8 * m)

def PRF(pk_seed, sk_seed, adrs: ADRS):
    return shake_256(pk_seed + adrs.getADRS() + sk_seed).hexdigest(8 * n)

def PRF_msg(sk_prf, opt_rand, M):
    return shake_256(sk_prf + opt_rand + M).hexdigest(8 * n)

def F(pk_seed, adrs: ADRS, M1):
    return shake_256(pk_seed + adrs.getADRS() + M1).hexdigest(8 * n)

def H(pk_seed, adrs: ADRS, M2):
    return shake_256(pk_seed + adrs.getADRS() + M2).hexdigest(8 * n)

def Tlen(pk_seed, adrs: ADRS, Ml):
    return shake_256(pk_seed + adrs.getADRS() + Ml).hexdigest(8 * n)
