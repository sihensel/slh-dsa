import math
from copy import deepcopy

from adrs import ADRS
from params import Params, H, PRF
from wots import wots_pkGen, wots_sign, wots_pkFromSig


# algorithm 9
def xmss_node(sk_seed, i: int, z: int, pk_seed, adrs: ADRS):
    """
    Computes the root of a Merkle subtree of WOTS+ public keys
    Params:
        sk_seed     secret seed
        i           target node index
        z           target node height
        pk_seed     public seed
        adrs        address
    Returns:
        n-byte root node
    """
    if z == 0:
        adrs.setTypeAndClear(Params.WOTS_HASH)
        adrs.setKeyPairAddress(i)
        node = wots_pkGen(sk_seed, pk_seed, adrs)
    else:
        lnode = xmss_node(sk_seed, i * 2,     z - 1, pk_seed, adrs)
        rnode = xmss_node(sk_seed, i * 2 + 1, z - 1, pk_seed, adrs)
        adrs.setTypeAndClear(Params.TREE)
        adrs.setTreeHeight(z)
        adrs.setTreeIndex(i)
        node = H(pk_seed, adrs, lnode + rnode)
    return node


# algorithm 10
def xmss_sign(M, sk_seed, idx: int, pk_seed, adrs: ADRS):
    """
    Generates an XMSS signature
    
    Params:
        M           n-byte message
        sk_seed     secret seed
        idx         index
        pk_seed     public seed
        adrs        address
    Returns:
        xmss signature
    """
    AUTH = [0] * Params.h_
    for j in range(Params.h_):
        k = math.floor(idx / (2 ** j)) ^ 1
        # alternative:
        # k = (idx >> )j ^ 1
        # https://github.com/slh-dsa/sloth/blob/f202c5f3fa4916f176f5d80f63be3fda6d5cb999/slh/slh_dsa.c#L241
        AUTH[j] = xmss_node(sk_seed, k, j, pk_seed, adrs)

    adrs.setTypeAndClear(Params.WOTS_HASH)
    adrs.setKeyPairAddress(idx)
    sig = wots_sign(M, sk_seed, pk_seed, adrs)
    sig_xmss = sig + AUTH
    return sig_xmss


# algorithm 11
def xmss_pkFromSig(idx: int, sig_xmss: list , M, pk_seed, adrs: ADRS):
    """
    Computes an XMSS public key from an XMSS signature

    Params:
        idx         index
        sig_xmss    XMSS signature (signature and authentication path)
        M           n-byte message
        pk_seed     public seed
        adrs        address
    Returns:
        n-byte root value node[0]
    """
    node = [0, 0]
    adrs.setTypeAndClear(Params.WOTS_HASH)
    adrs.setKeyPairAddress(idx)

    sig = getWOTSSig(sig_xmss)
    AUTH = getXMSSAUTH(sig_xmss)

    node[0] = wots_pkFromSig(sig, M, pk_seed, adrs)
    adrs.setTypeAndClear(Params.TREE)
    adrs.setTreeIndex(idx)

    for k in range(Params.h_):
        adrs.setTreeHeight(k + 1)
        if math.floor(idx / 2 ** k) % 2 == 0:
        # alternative
        # if ((idx >> k) & 1) == 0:
            adrs.setTreeIndex(int(adrs.getTreeIndex() / 2))
            node[1] = H(pk_seed, adrs, node[0] + AUTH[k])
        else:
            adrs.setTreeIndex(int((adrs.getTreeIndex() - 1) / 2))
            node[1] = H(pk_seed, adrs, AUTH[k] + node[0])
        node[0] = node[1]
    return node[0]


def getWOTSSig(sig_xmss: list):
    """
    Returns the WOTS+ signature of a XMSS signature
    The WOTS+ signature always has len elements
    """
    return sig_xmss[0:Params.len]


def getXMSSAUTH(sig_xmss: list):
    """
    Returns the authentication path of a XMSS signature
    The authentication path consists of h' elements
    """
    return sig_xmss[Params.len:Params.len + Params.h_]


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


# algorithm 14
def fors_skGen(sk_seed, pk_seed, adrs: ADRS, idx):
    """
    Generates a FORS private-key value

    Params:
        sk_seed     secret seed
        pk_seed     public seed
        ADRS        address
        idx         secret key index
    Returns:
        n-byte FORS private key
    """
    sk_adrs = deepcopy(adrs)
    sk_adrs.setTypeAndClear(Params.FORS_PRF)
    sk_adrs.setKeyPairAddress(adrs.getKeyPairAddress())
    sk_adrs.setTreeIndex(idx)
    return PRF(pk_seed, sk_seed, adrs)
