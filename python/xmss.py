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
def xmss_sign(M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> bytes:
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
    AUTH = b""
    for j in range(params.prm.h_):
        k = (idx >> j) ^ 1
        AUTH += xmss_node(sk_seed, k, j, pk_seed, adrs)

    adrs.setTypeAndClear(params.prm.WOTS_HASH)
    adrs.setKeyPairAddress(idx)
    sig = wots_sign(M, sk_seed, pk_seed, adrs)
    sig_xmss = sig + AUTH
    return sig_xmss


# algorithm 11
def xmss_pkFromSig(idx: int, sig_xmss: bytes , M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
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
    adrs.setTypeAndClear(params.prm.WOTS_HASH)
    adrs.setKeyPairAddress(idx)

    sig = sig_xmss[0:params.prm.len * params.prm.n]
    AUTH = sig_xmss[params.prm.len * params.prm.n:]

    node_0 = wots_pkFromSig(sig, M, pk_seed, adrs)
    adrs.setTypeAndClear(params.prm.TREE)
    adrs.setTreeIndex(idx)

    for k in range(params.prm.h_):
        adrs.setTreeHeight(k + 1)
        auth_k = AUTH[k * params.prm.n:(k + 1) * params.prm.n]
        if (idx >> k) & 1 == 0:
            adrs.setTreeIndex(int(adrs.getTreeIndex() / 2))
            node_1 = H(pk_seed, adrs, node_0 + auth_k)
        else:
            adrs.setTreeIndex(int((adrs.getTreeIndex() - 1) / 2))
            node_1 = H(pk_seed, adrs, auth_k + node_0)
        node_0 = node_1
    return node_0
