from math import ceil

import params
from adrs import ADRS, toInt
from fors import fors_sign, fors_pkFromSig
from hypertree import ht_sign, ht_verify
from shake import H_msg, PRF_msg
from xmss import xmss_node


# algorithm 18
def slh_keygen_internal(sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> tuple:
    adrs = ADRS()
    adrs.setLayerAddress(params.prm.d - 1)
    pk_root = xmss_node(sk_seed, 0, params.prm.h_, pk_seed, adrs)
    return ((sk_seed, sk_prf, pk_seed, pk_root), (pk_seed, pk_root))


# algorithm 19
def slh_sign_internal(M: bytes, SK: tuple, addrnd: bytes) -> list:
    # NOTE precompute these values to make the code cleaner
    param1 = ceil(params.prm.k * params.prm.a / 8)
    param2 = ceil((params.prm.h - params.prm.h / params.prm.d) / 8)
    param3 = ceil(params.prm.h / (params.prm.d * 8))
    SIG = []
    adrs = ADRS()

    R = PRF_msg(SK[1], addrnd, M)
    SIG.append(R)
    digest = H_msg(R, SK[2], SK[3], M)
    md = digest[0:param1]
    tmp_idx_tree = digest[param1:param1 + param2]
    tmp_idx_leaf = digest[param1 + param2:param1 + param2 + param3]

    idx_tree = toInt(tmp_idx_tree, param2) % 2 ** int(params.prm.h - params.prm.h / params.prm.d)
    idx_leaf = toInt(tmp_idx_leaf, param3) % 2 ** int(params.prm.h / params.prm.d)

    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(params.prm.FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)

    SIG_FORS = fors_sign(md, SK[0], SK[2], adrs)
    SIG += SIG_FORS

    PK_FORS = fors_pkFromSig(SIG_FORS, md, SK[2], adrs)
    SIG_HT = ht_sign(PK_FORS, SK[0], SK[2], idx_tree, idx_leaf)
    SIG += SIG_HT
    return SIG


# algorithm 20
def slh_verify_internal(M: bytearray, SIG: list, PK: tuple) -> bool:
    param1 = ceil(params.prm.k * params.prm.a / 8)
    param2 = ceil((params.prm.h - params.prm.h / params.prm.d) / 8)
    param3 = ceil(params.prm.h / (params.prm.d * 8))

    if len(SIG) != 1 + params.prm.k * (1 + params.prm.a) + params.prm.h + params.prm.d * params.prm.len:
        return False

    adrs = ADRS()
    R = SIG[0]
    SIG_FORS = SIG[1:1 + params.prm.k * (1 + params.prm.a)]
    SIG_HT = SIG[1 + params.prm.k * (1 + params.prm.a):]

    digest = H_msg(R, PK[0], PK[1], M)
    md = digest[0: param1]
    tmp_idx_tree = digest[param1:param1 + param2]
    tmp_idx_leaf = digest[param1 + param2:param1 + param2 + param3]
    idx_tree = toInt(tmp_idx_tree, param2) % 2 ** int(params.prm.h - params.prm.h / params.prm.d)
    idx_leaf = toInt(tmp_idx_leaf, param3) % 2 ** int(params.prm.h / params.prm.d)

    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(params.prm.FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)

    PK_FORS = fors_pkFromSig(SIG_FORS, md, PK[0], adrs)
    return ht_verify(PK_FORS, SIG_HT, PK[0], idx_tree, idx_leaf, PK[1])
