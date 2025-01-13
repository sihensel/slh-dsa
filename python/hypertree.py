from copy import deepcopy


import params
from adrs import ADRS
from xmss import xmss_sign, xmss_pkFromSig


# algorithm 12
def ht_sign(M: bytes, sk_seed: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int) -> bytes:
    """
    Generates a hypertree signature

    Params:
        M           n-byte message
        pk_seed     public seed
        sk_seed     secret seed
        idx_tree    tree index
        idx_leaf    leaf index
    Returns:
        signature of the hypertree with h + d * len elements
    """
    adrs = ADRS()
    adrs.setTreeAddress(idx_tree)

    sig_tmp = xmss_sign(M, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = deepcopy(sig_tmp)
    root = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs)

    for j in range(1, params.prm.d):
        idx_leaf = idx_tree % (2 ** params.prm.h_)
        idx_tree = idx_tree >> params.prm.h_
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht += sig_tmp

        if j < params.prm.d - 1:
            root = xmss_pkFromSig(idx_leaf, sig_tmp, root, pk_seed, adrs)
    return sig_ht


# algorithm 13
def ht_verify(M: bytes, sig_ht: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, pk_root: bytes) -> bool:
    """
    Verifies a hypertree signature

    Params:
        M           n-byte message
        sig_ht      hypertree signature to verify
        pk_seed     public seed
        idx_tree    tree index
        idx_leaf    leaf index
        pk_root     hypertree public key
    Returns:
        boolean indicating whether the signature is valid
    """
    adrs = ADRS()
    adrs.setTreeAddress(idx_tree)
    sig_tmp = sig_ht[0:(params.prm.h_ + params.prm.len) * params.prm.n]
    node = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs)

    for j in range(1, params.prm.d):
        idx_leaf = int(idx_tree % (2 ** params.prm.h_))
        idx_tree = idx_tree >> params.prm.h_
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = sig_ht[j * (params.prm.h_ + params.prm.len) * params.prm.n:(j + 1) * (params.prm.h_ + params.prm.len) * params.prm.n]
        node = xmss_pkFromSig(idx_leaf, sig_tmp, node, pk_seed, adrs)

    return node == pk_root
