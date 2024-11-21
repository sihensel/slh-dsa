from copy import deepcopy
from math import floor

from adrs import ADRS
from params import Params, PRF, H, F, Tlen
from wots import base_2b


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

#Algorithmus 15 (Computes the root of a Merkle subtree of FORS public values)
def fors_node(SK_seed, i, z, PK_seed, ADRS):    #Input: Secret seed SK.seed, target node index 𝑖, target node height 𝑧, public seed PK.seed, address ADRS

    if z == 0:
        sk = fors_skGen(SK_seed, PK_seed, ADRS, i)
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i)
        node = F(PK_seed, ADRS, sk)
    else:
        ADRS.setTreeHeight(z - 1)
        lnode = fors_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS)
        ADRS.setTreeHeight(z - 1)
        rnode = fors_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS)
        ADRS.setTreeHeight(z)
        ADRS.setTreeIndex(i)

        concatenated_nodes = lnode + rnode
        node = H(PK_seed, ADRS, concatenated_nodes)

    return node                                 #Output: 𝑛-byte root 𝑛𝑜𝑑𝑒

#Algorithmus 16 (Generates a FORS signature)
def fors_sign(md, SK_seed, PK_seed, ADRS):      #Input: Message digest 𝑚𝑑, secret seed SK.seed, address ADRS, public seed PK.seed

    SIG_FORS = []                              # Initialize SIG_FORS as an empty byte string
    indices = base_2b(md, Params.a, Params.k)                 # Compute indices using base_2b function

    for i in range(Params.k):
        SIG_FORS.append(fors_skGen(SK_seed, PK_seed, ADRS, i * 2**Params.a + indices[i]))   # Compute signature elements

        AUTH = []
        for j in range(Params.a):
            s = floor(indices[i] / 2 ** j) ^ 1              # Compute auth path
            AUTH.append(fors_node(SK_seed, i * 2**(Params.a - j) + s, j, PK_seed, ADRS))
        SIG_FORS += AUTH

    # a FORS signature is:
    # (n bytes + a * n bytes ) * k (=182 for our paremeter set)
    return SIG_FORS                             # Output: FORS signature SIG𝐹 𝑂𝑅𝑆

#Algorithmus 17 (Computes a FORS public key from a FORS signature)
def fors_pkFromSig(SIG_FORS, md, PK_seed, ADRS):    # Input: FORS signature SIG𝐹 𝑂𝑅𝑆, message digest 𝑚𝑑, public seed PK.seed, address ADRS

    indices = base_2b(md, Params.a, Params.k)
    root = [0] * Params.k
    node = [0, 0]

    for i in range(Params.k):
        sk = SIG_FORS[i * (Params.a + 1):i * (Params.a + 1) + 1]    # Compute leaf
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i * 2**Params.a + indices[i])
        node[0] = F(PK_seed, ADRS, sk)

        auth = SIG_FORS[i * (Params.a + 1) + 1:(i + 1) * (Params.a + 1)]    # Compute root from leaf and AUTH
        for j in range(Params.a):
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
    forspkADRS.setTypeAndClear(Params.FORS_ROOTS)
    forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    pk = Tlen(PK_seed, forspkADRS, root)          # Compute the FORS public key

    return pk                                   # Output: FORS public key
