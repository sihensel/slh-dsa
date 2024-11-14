import math
from copy import deepcopy

from adrs import ADRS
# FIXME importing everything with out prefix is not a good solution
from params import *


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
        adrs.setTypeAndClear(WOTS_HASH)
        adrs.setKeyPairAddress(i)
        node = wots_pkGen(sk_seed, pk_seed, adrs)
    else:
        lnode = xmss_node(sk_seed, i * 2,     z - 1, pk_seed, adrs)
        rnode = xmss_node(sk_seed, i * 2 + 1, z - 1, pk_seed, adrs)
        adrs.setTypeAndClear(TREE)
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
    # h = tree height, where to get this from?
    AUTH = [0 for _ in range(h)]
    for j in range(h):
        k = math.floor(idx / 2 ** j) ^ 1
        # alternative:
        # k = (idx >> )j ^ 1
        # https://github.com/slh-dsa/sloth/blob/f202c5f3fa4916f176f5d80f63be3fda6d5cb999/slh/slh_dsa.c#L241
        AUTH[j] = xmss_node(sk_seed, k, j, pk_seed, adrs)

    adrs.setTypeAndClear(WOTS_HASH)
    adrs.setKeyPairAddress(idx)
    sig = wots_sign(M, sk_seed, pk_seed, adrs)
    sig_xmss = sig + AUTH
    return sig_xmss


# algorithm 11
def xmss_pkFromSig(idx: int, sig_xmss, M, pk_seed, adrs: ADRS):
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
    adrs.setTypeAndClear(WOTS_HASH)
    adrs.setKeyPairAddress(idx)
    # NOTE sig_xmss is a list
    # either create a class for it or make a function that slices the list
    sig = sig_xmss.getWOTSSig()
    AUTH = sig_xmss.getXMSSAUTH()
    node[0] = wots_pkFromSig(sig, M, pk_seed, adrs)
    adrs.setTypeAndClear(TREE)
    adrs.setTreeIndex(idx)

    for k in range(h):
        adrs.setTreeHeight(k + 1)
        if math.floor(idx / 2 ** k) % 2 == 0:
        # alternative
        # if ((idx >> k) & 1) == 0:
            adrs.setTreeIndex(adrs.getTreeIndex() / 2)
            node[1] = H(pk_seed, adrs, node[0] + AUTH[k])
        else:
            adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2)
            node[1] = H(pk_seed, adrs, AUTH[k] + node[0])
        node [0] = node[1]

    return node[0]


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
        signature of the hypertree
    """
    adrs = ADRS()
    adrs.setTreeAddress(idx_tree)

    sig_tmp = xmss_sign(M, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = sig_tmp
    root = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs)

    # FIXME check out where d and h (h') are coming from
    for j in range(1, d):
        idx_leaf = idx_tree % (s ** h)
        idx_tree = idx_tree >> h
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        # sig_tmp and sig_ht are probably lists
        sig_ht += sig_tmp

        if j < d - 1:
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
    # either sig_ht is an object or getXMSSSignature needs to be a static function
    # either way sig_ht is essentially a list and getXMSSSignature does list slicing
    sig_tmp = sig_ht.getXMSSSignature(0)
    node = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs)

    # FIXME check out where d and h (which is actually h') are coming from
    for j in range(1, d):
        idx_leaf = idx_tree % (2 ** h)
        idx_tree = idx_tree >> h
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = sig_ht.getXMSSSignature(j)
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
    sk_adrs.setTypeAndClear(FORS_PRF)
    sk_adrs.setKeyPairAddress(adrs.getKeyPairAddress())
    sk_adrs.setTreeIndex(idx)
    # FIXME find out how PRF is defined
    return PRF(pk_seed, sk_seed, adrs)
