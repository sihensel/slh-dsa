import math
import hashlib

#Algorhitmus 1 (Computes 𝑙𝑒𝑛2)
def gen_len2(n, lg_w): #Input: Security parameter 𝑛, bits per hash chain 𝑙𝑔_𝑤
    w = 2 ** lg_w                               #Compute w: w = 2^lg_w
    len1 = math.ceil((8 * n + lg_w - 1) / lg_w) #Compute len1
    max_checksum = len1 * (w - 1)               #Compute maximum possible checksum value
    len2 = 1                                    #Initialize len2
    capacity = w                                #Initialize capacity

    while capacity <= max_checksum:             #Loop until capacity exceeds max_checksum
        len2 += 1
        capacity *= w

    return len2                                 #Output: 𝑙𝑒𝑛2

#Algorithmus 2 (Converts a byte string to an integer)
def toInt(X, n):                                #Input: 𝑛-byte string 𝑋
    total = 0
    for i in range(n):
        total = 256 * total + X[i]
    return total                                #Output: Integer value of 𝑋

#Algorithmus 3 (Converts an integer to a byte string)
def toByte(x, n):                               #Input: Integer 𝑥, string length 𝑛
    total = x                                   #Initialize total to x
    S = [0] * n                                 #Create an array of size n to store the byte string
    for i in range(n):                          # Loop from 0 to n-1
        S[n - 1 - i] = total % 256              # Set S[n - 1 - i] to the least significant byte of total
        total = total >> 8                      # Shift total right by 8 bits to remove the last byte
    return S                                    #Output: Byte string of length 𝑛 containing binary representation of 𝑥 in big-endian byte-order

#Algorithmus 4 (Computes the base 2𝑏 representation of 𝑋)
def base_2b(X, b, out_len):                     #Input: Byte string 𝑋 of length at least ⌈𝑜𝑢𝑡_𝑙𝑒𝑛⋅𝑏/8⌉, integer 𝑏, output length 𝑜𝑢𝑡_𝑙𝑒𝑛
    in_index = 0                                # Equivalent to `in` in pseudocode
    bits = 0                                    # Number of bits currently in `total`
    total = 0                                   # Accumulates the bit representation
    baseb = [0] * out_len                       # Initialize output array of size `out_len`

    for out in range(out_len):
        while bits < b:                         # Fill `total` with bits until it has at least `b` bits
            total = (total << 8) + X[in_index]  # Add 8 bits from X[in_index]
            in_index += 1
            bits += 8

        baseb[out] = (total >> (bits - b)) % (1 << b) # Extract the `b` least significant bits
        bits -= b                               # Reduce `bits` by `b` as we've used them

    return baseb                                #Output: Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range [0, … , 2𝑏 − 1]

#Algorithmus 5 (Chaining function used in WOTS+)
def chain(X, i, s, PK_seed, ADRS):              #Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS
    tmp = X
    for j in range(i, i + s):
        ADRS.setHashAddress(j)
        tmp = F(PK_seed, ADRS, tmp)

    return tmp                                  #Output: Value of F iterated 𝑠 times on 𝑋

#Algorithmus 6 (Generates a WOTS+ public key)
def wots_pkGen(SK_seed, PK_seed, ADRS):         #Input: Secret seed SK.seed, public seed PK.seed, address ADRS
    skADRS = ADRS.copy()                        # Copy address to create key generation key address
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    tmp = []
    for i in range(len):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS)      # Compute secret value for chain i
        ADRS.setChainAddress(i)
        tmp.append(chain(sk, 0, w - 1, PK_seed, ADRS))  # Compute public value for chain i

    wotspkADRS = ADRS.copy()                    # Copy address to create WOTS+ public key address
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    pk = Tlen(PK_seed, wotspkADRS, tmp)         # Compress public key
    return pk                                   # Output: WOTS+ public key 𝑝𝑘

#Algorithmus 7 (Generates a WOTS+ signature on an n-byte message)
def wots_sign(M, SK_seed, PK_seed, ADRS):       # Input: Message 𝑀, secret seed SK.seed, public seed PK.seed, address ADRS
    csum = 0
    msg = base_2w(M, lg_w, len1)                # Convert message to base w
    for i in range(len1):
        csum += w - 1 - msg[i]                  # Compute checksum

    csum <<= (8 - ((len1 * lg_w) % 8)) % 8      # For lg_w = 4, left shift by 4
    msg += msg + base_2w(toByte(csum, len1 * lg_w), lg_w, len2)  # Convert to base w

    skADRS = ADRS.copy()                        # Copy address to create key generation key address
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    sig = []
    for i in range(len2):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS)      # Compute chain i secret value
        ADRS.setChainAddress(i)
        sig.append(chain(sk, 0, msg[i], PK_seed, ADRS))  # Compute chain i signature value

    return sig                                  # Output: WOTS+ signature 𝑠𝑖𝑔

#Algorithmus 8 (Computes a WOTS+ public key from a message and its signature)
def wots_pkFromSig(sig, M, PK_seed, ADRS):      # Input: WOTS+ signature 𝑠𝑖𝑔, message 𝑀, public seed PK.seed, address ADRS
    csum = 0
    msg = base_2w(M, lg_w, len1)                # Konvertiere Nachricht in Basis w
    for i in range(len1):
        csum += w - 1 - msg[i]                  # Berechne Prüfsumme

    csum <<= (8 - ((len1 * lg_w) % 8)) % 8      # Für lg_w = 4, shift um 4 nach links
    msg += msg + base_2w(toByte(csum, len1 * lg_w), lg_w, len2)  # Konvertiere in Basis w

    for i in range(len2):
        ADRS.setChainAddress(i)
        tmp[i] = chain(sig[i], msg[i], w - 1 - msg[i], PK_seed, ADRS)

    wotspkADRS = ADRS.copy()                    # Kopiere Adresse, um WOTS+ öffentlichen Schlüssel zu erstellen
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    pksig = Tlen(PK_seed, wotspkADRS, tmp)
    return pksig                                # Output: WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔

#Algorithmus 9 (Computes the root of a Merkle subtree of WOTS+ public keys)
def xmss_node(SK_seed, i, z, PK_seed, ADRS):


    if z == 0:                                  # Check if the node height z is 0
        ADRS.setTypeAndClear('WOTS_HASH')       # Set the address type to WOTS_HASH and clear any existing settings
        ADRS.setKeyPairAddress(i)               # Set the key pair address to the target node index i
        node = wots_pkGen(SK_seed, PK_seed, ADRS)   # Generate the WOTS+ public key for the given SK_seed, PK_seed, and ADRS

    else:
        lnode = xmss_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS) # Recursively compute the left and right child nodes for the tree
        rnode = xmss_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS)

        ADRS.setTypeAndClear('TREE')            # Set the address type to TREE and clear any existing settings
        ADRS.setTreeHeight(z)                   # Set the tree height to z
        ADRS.setTreeIndex(i)                    # Set the tree index to i

        node = H(PK_seed, ADRS, lnode + rnode)  # Compute the hash of the concatenated left and right child nodes

    return node                                 # Return the computed node

#Algorithmus 15 (Computes the root of a Merkle subtree of FORS public values)
def H(PK_seed, ADRS, concatenated_nodes):
    data = PK_seed + ADRS + concatenated_nodes  # Concatenate PK_seed, ADRS, and concatenated_nodes (lnode || rnode)
    return hashlib.sha256(data).digest()        # Apply SHA-256 (or another hash function) to the concatenated data

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
        node = H(PK_seed, ADRS.to_bytes(), concatenated_nodes)

    return node                                 #Output: 𝑛-byte root 𝑛𝑜𝑑𝑒

#Algorithmus 16 (Generates a FORS signature)
def fors_sign(md, SK_seed, PK_seed, ADRS):      #Input: Message digest 𝑚𝑑, secret seed SK.seed, address ADRS, public seed PK.seed

    SIG_FORS = b''                              # Initialize SIG_FORS as an empty byte string
    indices = base_2b(md, a, k)                 # Compute indices using base_2b function

    for i in range(k):
        SIG_FORS += fors_skGen(SK_seed, PK_seed, ADRS, i * 2**a + indices[i])   # Compute signature elements

        s = indices[i] // 2**a + 1              # Compute auth path
        AUTH = []
        for j in range(a):
            AUTH.append(fors_node(SK_seed, i * 2**(a - 1) + s, j, PK_seed, ADRS))
        SIG_FORS += b''.join(AUTH)

    return SIG_FORS                             # Output: FORS signature SIG𝐹 𝑂𝑅𝑆

#Algorithmus 17 (Computes a FORS public key from a FORS signature)
def fors_pkFromSig(SIG_FORS, md, PK_seed, ADRS):    # Input: FORS signature SIG𝐹 𝑂𝑅𝑆, message digest 𝑚𝑑, public seed PK.seed, address ADRS

    indices = base_2b(md, a, k)
    root = []

    for i in range(k):
        sk = SIG_FORS[i * (a + 1) * n:(i * (a + 1) + 1) * n]    # Compute leaf
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i * 2**a + indices[i])
        node = [F(PK_seed, ADRS, sk)]

        auth = SIG_FORS[(i * (a + 1) + 1) * n:(i + 1) * (a + 1) * n]    # Compute root from leaf and AUTH
        for j in range(a):
            if indices[i] // 2**j % 2 == 0:
                ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)

                concatenated_input = node[0] + auth[j]  # Concatenate node[0] and auth[j]
                node[1] = H(PK_seed, ADRS, concatenated_input)  # Compute H(PK_seed, ADRS, node[0] || auth[j]) and store it in node[1]
            else:
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)

                concatenated_input = auth[j] + node[0]  # Concatenate node[0] and auth[j]
                node[1] = H(PK_seed, ADRS,concatenated_input)  # Compute H(PK_seed, ADRS, node[0] || auth[j]) and store it in node[1]

            node[0] = node[1]

        root[i] = node[0]

    forspkADRS = ADRS.copy()                    # Copy address to create a FORS public-key address
    forspkADRS.setTypeAndClear(FORS_ROOTS)
    forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())

    pk = Tk(PK_seed, forspkADRS, root)          # Compute the FORS public key

    return pk                                   # Output: FORS public key



