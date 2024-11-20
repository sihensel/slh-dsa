from copy import deepcopy


from adrs import ADRS
from params import Params
from xmss import xmss_sign, xmss_pkFromSig


def getXMSSSignature(sig_ht: list, idx: int):
    """
    Get one XMSS signature (WOTS+ sig and authentication path) from a hypertree signature
    Params:
        sig_ht: hypertree signature
        idx:    index of the XMSS signature in sig_ht
    """
    # hypertree signatures contain d XMSS signatures
    # each XMSS signature is len + h' elements
    start = idx * (Params.len + Params.h_)
    end = (idx + 1) * (Params.len + Params.h_)
    return sig_ht[start:end]


# algorithm 12
def ht_sign(M, sk_seed, pk_seed, idx_tree, idx_leaf):
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

    for j in range(1, Params.d):
        idx_leaf = idx_tree % (2 ** Params.h_)
        idx_tree = idx_tree >> Params.h_
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht += sig_tmp

        if j < Params.d - 1:
            root = xmss_pkFromSig(idx_leaf, sig_tmp, root, pk_seed, adrs)
    return sig_ht


# algorithm 13
def ht_verify(M, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root):
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
    sig_tmp = getXMSSSignature(sig_ht, 0)
    node = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs)

    for j in range(1, Params.d):
        idx_leaf = idx_tree % (2 ** Params.h_)
        idx_tree = idx_tree >> Params.h_
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = getXMSSSignature(sig_ht, j)
        node = xmss_pkFromSig(idx_leaf, sig_tmp, node, pk_seed, adrs)

    if node == pk_root:
        return True
    return False
