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
    return ((sk_seed + sk_prf + pk_seed + pk_root), (pk_seed + pk_root))


# algorithm 19
def slh_sign_internal(M: bytes, SK: bytes, addrnd: bytes) -> bytes:
    # precompute these values to make the code cleaner
    index1 = (params.prm.k * params.prm.a + 7) // 8
    index2 = ((params.prm.h - (params.prm.h // params.prm.d)) + 7) // 8
    index3 = ((params.prm.h // params.prm.d) + 7) // 8

    sk_seed = SK[0               :params.prm.n]
    sk_prf  = SK[    params.prm.n:2 * params.prm.n]
    pk_seed = SK[2 * params.prm.n:3 * params.prm.n]
    pk_root = SK[3 * params.prm.n:]

    SIG = b""
    adrs = ADRS()

    R = PRF_msg(sk_prf, addrnd, M)
    SIG += R
    digest = H_msg(R, pk_seed, pk_root, M)
    md = digest[0:index1]
    tmp_idx_tree = digest[index1:index1 + index2]
    tmp_idx_leaf = digest[index1 + index2:index1 + index2 + index3]

    idx_tree = toInt(tmp_idx_tree, index2) % (2 ** (params.prm.h - (params.prm.h // params.prm.d)))
    idx_leaf = toInt(tmp_idx_leaf, index3) % (2 ** (params.prm.h // params.prm.d))

    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(params.prm.FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)

    SIG_FORS = fors_sign(md, sk_seed, pk_seed, adrs)
    SIG += SIG_FORS

    PK_FORS = fors_pkFromSig(SIG_FORS, md, pk_seed, adrs)
    SIG_HT = ht_sign(PK_FORS, sk_seed, pk_seed, idx_tree, idx_leaf)
    SIG += SIG_HT
    return SIG


# algorithm 20
def slh_verify_internal(M: bytes, SIG: bytes, PK: bytes) -> bool:
    index1 = (params.prm.k * params.prm.a + 7) // 8
    index2 = ((params.prm.h - (params.prm.h // params.prm.d)) + 7) // 8
    index3 = ((params.prm.h // params.prm.d) + 7) // 8

    pk_seed = PK[0:params.prm.n]
    pk_root = PK[params.prm.n:]

    if len(SIG) != (1 + params.prm.k * (1 + params.prm.a) + params.prm.h + params.prm.d * params.prm.len) * params.prm.n:
        print("Invalid signature length")
        return False

    adrs = ADRS()
    R = SIG[0:params.prm.n]
    SIG_FORS = SIG[params.prm.n:(1 + params.prm.k * (1 + params.prm.a)) * params.prm.n]
    SIG_HT = SIG[(1 + params.prm.k * (1 + params.prm.a)) * params.prm.n:]

    digest = H_msg(R, pk_seed, pk_root, M)
    md = digest[0:index1]
    tmp_idx_tree = digest[index1:index1 + index2]
    tmp_idx_leaf = digest[index1 + index2:index1 + index2 + index3]
    idx_tree = toInt(tmp_idx_tree, index2) % (2 ** (params.prm.h - (params.prm.h // params.prm.d)))
    idx_leaf = toInt(tmp_idx_leaf, index3) % (2 ** (params.prm.h // params.prm.d))

    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(params.prm.FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)

    PK_FORS = fors_pkFromSig(SIG_FORS, md, pk_seed, adrs)
    return ht_verify(PK_FORS, SIG_HT, pk_seed, idx_tree, idx_leaf, pk_root)
