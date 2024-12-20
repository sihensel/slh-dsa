from math import floor

import params
from adrs import ADRS
from shake import H
from wots import wots_pkGen, wots_sign, wots_pkFromSig


# algorithm 9
def xmss_node(sk_seed: bytes, i: int, z: int, pk_seed: bytes, adrs: ADRS) -> bytes:
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
        adrs.setTypeAndClear(params.prm.WOTS_HASH)
        adrs.setKeyPairAddress(i)
        node = wots_pkGen(sk_seed, pk_seed, adrs)
    else:
        lnode = xmss_node(sk_seed, i * 2,     z - 1, pk_seed, adrs)
        rnode = xmss_node(sk_seed, i * 2 + 1, z - 1, pk_seed, adrs)
        adrs.setTypeAndClear(params.prm.TREE)
        adrs.setTreeHeight(z)
        adrs.setTreeIndex(i)
        node = H(pk_seed, adrs, lnode + rnode)
    return node


# algorithm 10
def xmss_sign(M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> list:
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
    AUTH: list = [0] * params.prm.h_
    for j in range(params.prm.h_):
        k = floor(idx / (2 ** j)) ^ 1
        # alternative:
        # k = (idx >> j) ^ 1
        # https://github.com/slh-dsa/sloth/blob/f202c5f3fa4916f176f5d80f63be3fda6d5cb999/slh/slh_dsa.c#L241
        AUTH[j] = xmss_node(sk_seed, k, j, pk_seed, adrs)

    adrs.setTypeAndClear(params.prm.WOTS_HASH)
    adrs.setKeyPairAddress(idx)
    sig = wots_sign(M, sk_seed, pk_seed, adrs)
    sig_xmss = sig + AUTH
    return sig_xmss


# algorithm 11
def xmss_pkFromSig(idx: int, sig_xmss: list , M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
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
    node: list = [0, 0]
    adrs.setTypeAndClear(params.prm.WOTS_HASH)
    adrs.setKeyPairAddress(idx)

    sig = getWOTSSig(sig_xmss)
    AUTH = getXMSSAUTH(sig_xmss)

    node[0] = wots_pkFromSig(sig, M, pk_seed, adrs)
    adrs.setTypeAndClear(params.prm.TREE)
    adrs.setTreeIndex(idx)

    for k in range(params.prm.h_):
        adrs.setTreeHeight(k + 1)
        # alternative: if ((idx >> k) & 1) == 0:
        if floor(idx / (2 ** k)) % 2 == 0:
            adrs.setTreeIndex(int(adrs.getTreeIndex() / 2))
            node[1] = H(pk_seed, adrs, node[0] + AUTH[k])
        else:
            adrs.setTreeIndex(int((adrs.getTreeIndex() - 1) / 2))
            node[1] = H(pk_seed, adrs, AUTH[k] + node[0])
        node[0] = node[1]
    return node[0]


def getWOTSSig(sig_xmss: list) -> list:
    """
    Returns the WOTS+ signature of a XMSS signature
    The WOTS+ signature always has len elements
    """
    return sig_xmss[0:params.prm.len]


def getXMSSAUTH(sig_xmss: list) -> list:
    """
    Returns the authentication path of a XMSS signature
    The authentication path consists of h' elements
    """
    return sig_xmss[params.prm.len:params.prm.len + params.prm.h_]
