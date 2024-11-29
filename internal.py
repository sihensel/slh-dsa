from copy import deepcopy
from math import ceil

from adrs import ADRS
from fors import fors_sign, fors_pkFromSig
from hypertree import ht_sign, ht_verify
from params import Params, H_msg, PRF_msg
from adrs import toInt
from xmss import xmss_node


# algorithm 18
def slh_keygen_internal(sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> tuple:
    adrs = ADRS()
    adrs.setLayerAddress(Params.d - 1)
    pk_root = xmss_node(sk_seed, 0, Params.h_, pk_seed, adrs)
    return ((sk_seed, sk_prf, pk_seed, pk_root), (pk_seed, pk_root))


# algorithm 19
def slh_sign_internal(M: list, SK: tuple, addrnd: bytes) -> list:
    # NOTE precompute these values to make the code cleaner
    param1 = ceil(Params.k * Params.a / 8)
    param2 = ceil((Params.h - Params.h / Params.d) / 8)
    SIG = []
    adrs = ADRS()
    opt_rand = deepcopy(addrnd)

    R = PRF_msg(SK[1], opt_rand, M)
    SIG.append(R)
    digest = H_msg(R, SK[2], SK[3], M)
    md = digest[0:param1]
    tmp_idx_tree = digest[param1:param1 + param2]
    tmp_idx_leaf = digest[param1 + param2:param1 + param2 + ceil(Params.h / (Params.d * 8))]

    idx_tree = int(toInt(tmp_idx_tree, param2) % 2 ** (Params.h - Params.h / Params.d))
    idx_leaf = int(toInt(tmp_idx_leaf, ceil(Params.h / (Params.d * 8))) % 2 ** (Params.h / Params.d))

    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(Params.FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)

    SIG_FORS = fors_sign(md, SK[0], SK[2], adrs)
    SIG += SIG_FORS

    PK_FORS = fors_pkFromSig(SIG_FORS, md, SK[2], adrs)
    SIG_HT = ht_sign(PK_FORS, SK[0], SK[2], idx_tree, idx_leaf)
    SIG += SIG_HT
    # SLH-DSA signature consists of the following:
    # Randomness        1
    # FORS signature    k * (a + 1) = 182
    # HT signature      h + d * len = 308
    # = 491 elements in the list (for our parameter set)
    return SIG


# algorithm 20
def slh_verify_internal(M: list, SIG: list, PK: tuple) -> bool:
    param1 = ceil(Params.k * Params.a / 8)
    param2 = ceil((Params.h - Params.h / Params.d) / 8)

    if len(SIG) != 1 + Params.k * (1 + Params.a) + Params.h + Params.d * Params.len:
        return False

    adrs = ADRS()
    R = SIG[0]
    SIG_FORS = SIG[1:1 + Params.k * (1 + Params.a)]
    SIG_HT = SIG[1 + Params.k * (1 + Params.a):]

    digest = H_msg(R, PK[0], PK[1], M)
    md = digest[0: param1]
    tmp_idx_tree = digest[param1:param1 + param2]
    tmp_idx_leaf = digest[param1 + param2:param1 + param2 + ceil(Params.h / (8 * Params.d))]
    idx_tree = int(toInt(tmp_idx_tree, param2) % 2 ** (Params.h - Params.h / Params.d))
    idx_leaf = int(toInt(tmp_idx_leaf, ceil(Params.h / (Params.d * 8))) % 2 ** (Params.h / Params.d))

    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(Params.FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)

    PK_FORS = fors_pkFromSig(SIG_FORS, md, PK[0], adrs)
    return ht_verify(PK_FORS, SIG_HT, PK[0], idx_tree, idx_leaf, PK[1])
