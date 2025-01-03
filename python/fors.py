from copy import deepcopy
from math import floor

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
    return PRF(pk_seed, sk_seed, adrs)


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
def fors_sign(md: bytes, SK_seed: bytes, PK_seed: bytes, ADRS: ADRS) -> list:      #Input: Message digest 𝑚𝑑, secret seed SK.seed, address ADRS, public seed PK.seed

    SIG_FORS = []                              # Initialize SIG_FORS as an empty byte string
    indices = base_2b(md, params.prm.a, params.prm.k)                 # Compute indices using base_2b function

    for i in range(params.prm.k):
        SIG_FORS.append(fors_skGen(SK_seed, PK_seed, ADRS, i * 2 ** params.prm.a + indices[i]))   # Compute signature elements

        AUTH = []
        for j in range(params.prm.a):
            s = floor(indices[i] / 2 ** j) ^ 1              # Compute auth path
            AUTH.append(fors_node(SK_seed, i * 2**(params.prm.a - j) + s, j, PK_seed, ADRS))
        SIG_FORS += AUTH

    # a FORS signature is:
    # (n bytes + a * n bytes ) * k (=182 for our paremeter set)
    return SIG_FORS                             # Output: FORS signature SIG𝐹 𝑂𝑅𝑆


#Algorithmus 17 (Computes a FORS public key from a FORS signature)
def fors_pkFromSig(SIG_FORS: list, md: bytes, PK_seed: bytes, ADRS: ADRS) -> bytes:    # Input: FORS signature SIG𝐹 𝑂𝑅𝑆, message digest 𝑚𝑑, public seed PK.seed, address ADRS

    indices = base_2b(md, params.prm.a, params.prm.k)
    root: list = [0] * params.prm.k
    node: list = [0, 0]

    for i in range(params.prm.k):
        sk = SIG_FORS[i * (params.prm.a + 1):i * (params.prm.a + 1) + 1]    # Compute leaf
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i * 2 ** params.prm.a + indices[i])
        node[0] = F(PK_seed, ADRS, sk)

        auth = SIG_FORS[i * (params.prm.a + 1) + 1:(i + 1) * (params.prm.a + 1)]    # Compute root from leaf and AUTH
        for j in range(params.prm.a):
            ADRS.setTreeHeight(j + 1)
            if indices[i] // 2**j % 2 == 0:
                ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)

                concatenated_input = node[0] + auth[j]  # Concatenate node[0] and auth[j]
                node[1] = H(PK_seed, ADRS, concatenated_input)  # Compute H(PK_seed, ADRS, node[0] || auth[j]) and store it in node[1]
            else:
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)

                concatenated_input = auth[j] + node[0]  # Concatenate node[0] and auth[j]
                node[1] = H(PK_seed, ADRS, concatenated_input)  # Compute H(PK_seed, ADRS, node[0] || auth[j]) and store it in node[1]

            node[0] = node[1]

        root[i] = node[0]

    forspkADRS = deepcopy(ADRS)                    # Copy address to create a FORS public-key address
    forspkADRS.setTypeAndClear(params.prm.FORS_ROOTS)
    forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    pk = Tlen(PK_seed, forspkADRS, root)          # Compute the FORS public key

    return pk                                   # Output: FORS public key
