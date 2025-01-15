from copy import deepcopy

import params
from adrs import ADRS
from shake import F, H, PRF, Tlen
from wots import base_2b


# algorithm 14
def fors_skGen(sk_seed: bytes, pk_seed: bytes, adrs: ADRS, idx: int) -> bytes:
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
    sk_adrs.setTypeAndClear(params.prm.FORS_PRF)
    sk_adrs.setKeyPairAddress(adrs.getKeyPairAddress())
    sk_adrs.setTreeIndex(idx)
    return PRF(pk_seed, sk_adrs, sk_seed)


#Algorithmus 15 (Computes the root of a Merkle subtree of FORS public values)
def fors_node(SK_seed: bytes, i: int, z: int, PK_seed: bytes, ADRS) -> bytes:    #Input: Secret seed SK.seed, target node index 𝑖, target node height 𝑧, public seed PK.seed, address ADRS

    if z == 0:
        sk = fors_skGen(SK_seed, PK_seed, ADRS, i)
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i)
        node = F(PK_seed, ADRS, sk)
    else:
        lnode = fors_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS)
        rnode = fors_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS)
        ADRS.setTreeHeight(z)
        ADRS.setTreeIndex(i)

        concatenated_nodes = lnode + rnode
        node = H(PK_seed, ADRS, concatenated_nodes)

    return node                                 #Output: 𝑛-byte root 𝑛𝑜𝑑𝑒

#Algorithmus 16 (Generates a FORS signature)
def fors_sign(md: bytes, SK_seed: bytes, PK_seed: bytes, ADRS: ADRS) -> bytes:      #Input: Message digest 𝑚𝑑, secret seed SK.seed, address ADRS, public seed PK.seed

    SIG_FORS = b""
    indices = base_2b(md, params.prm.a, params.prm.k)                 # Compute indices using base_2b function

    for i in range(params.prm.k):
        SIG_FORS += fors_skGen(SK_seed, PK_seed, ADRS, i * 2 ** params.prm.a + indices[i])

        AUTH = b""
        for j in range(params.prm.a):
            s = (indices[i] >> j) ^ 1
            AUTH += fors_node(SK_seed, i * 2**(params.prm.a - j) + s, j, PK_seed, ADRS)
        SIG_FORS += AUTH

    return SIG_FORS                             # Output: FORS signature SIG𝐹 𝑂𝑅𝑆


#Algorithmus 17 (Computes a FORS public key from a FORS signature)
def fors_pkFromSig(SIG_FORS: bytes, md: bytes, PK_seed: bytes, ADRS: ADRS) -> bytes:

    indices = base_2b(md, params.prm.a, params.prm.k)
    root = b""

    for i in range(params.prm.k):
        sk = SIG_FORS[i * (params.prm.a + 1) * params.prm.n:(i * (params.prm.a + 1) + 1) * params.prm.n]
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i * 2 ** params.prm.a + indices[i])
        node_0 = F(PK_seed, ADRS, sk)

        auth = SIG_FORS[(i * (params.prm.a + 1) + 1) * params.prm.n:(i + 1) * (params.prm.a + 1) * params.prm.n]
        for j in range(params.prm.a):
            auth_j = auth[j * params.prm.n:(j + 1) * params.prm.n]
            ADRS.setTreeHeight(j + 1)
            if indices[i] // 2**j % 2 == 0:
                ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
                node_1 = H(PK_seed, ADRS, node_0 + auth_j);
            else:
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)
                node_1 = H(PK_seed, ADRS, auth_j + node_0);

            node_0 = node_1
        root += node_0

    forspkADRS = deepcopy(ADRS)
    forspkADRS.setTypeAndClear(params.prm.FORS_ROOTS)
    forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    pk = Tlen(PK_seed, forspkADRS, root)
    return pk
