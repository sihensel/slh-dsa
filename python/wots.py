from copy import deepcopy

import params
from adrs import ADRS, toByte
from shake import F, PRF, Tlen


#Algorithmus 4 (Computes the base 2𝑏 representation of 𝑋)
def base_2b(X: list|bytes, b: int, out_len: int) -> list: #Input: Byte string 𝑋 of length at least ⌈𝑜𝑢𝑡_𝑙𝑒𝑛⋅𝑏/8⌉, integer 𝑏, output length 𝑜𝑢𝑡_𝑙𝑒𝑛
    in_index = 0                                    # Equivalent to `in` in pseudocode
    bits = 0                                        # Number of bits currently in `total`
    total = 0                                       # Accumulates the bit representation
    baseb = [0] * out_len                           # Initialize output array of size `out_len`

    for out in range(out_len):
        while bits < b:                             # Fill `total` with bits until it has at least `b` bits
            total = (total << 8) + X[in_index]      # Add 8 bits from X[in_index]
            in_index += 1
            bits += 8

        baseb[out] = (total >> (bits - b)) % (1 << b) # Extract the `b` least significant bits
        bits -= b                                   # Reduce `bits` by `b` as we've used them

    return baseb                                    #Output: Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range [0, … , 2𝑏 − 1]


#Algorithmus 5 (Chaining function used in WOTS+)
def chain(X: bytes, i: int, s: int, PK_seed: bytes, adrs: ADRS) -> bytes:     #Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS
    tmp = X
    for j in range(i, i + s):
        adrs.setHashAddress(j)
        tmp = F(PK_seed, adrs, tmp)

    return tmp                                  #Output: Value of F iterated 𝑠 times on 𝑋


#Algorithmus 6 (Generates a WOTS+ public key)
def wots_pkGen(SK_seed: bytes, PK_seed: bytes, adrs: ADRS) -> bytes:    #Input: Secret seed SK.seed, public seed PK.seed, address ADRS
    skADRS = deepcopy(adrs)                     # Copy address to create key generation key address
    skADRS.setTypeAndClear(params.prm.WOTS_PRF)
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    tmp = b""
    for i in range(params.prm.len):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, skADRS,SK_seed)      # Compute secret value for chain i
        adrs.setChainAddress(i)
        tmp += chain(sk, 0, params.prm.w - 1, PK_seed, adrs)  # Compute public value for chain i

    wotspkADRS = deepcopy(adrs)                 # Copy address to create WOTS+ public key address
    wotspkADRS.setTypeAndClear(params.prm.WOTS_PK)
    wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    pk = Tlen(PK_seed, wotspkADRS, tmp)         # Compress public key
    return pk                                   #Output: WOTS+ public key 𝑝𝑘


#Algorithmus 7 (Generates a WOTS+ signature on an n-byte message)
def wots_sign(M: bytes, SK_seed: bytes, PK_seed: bytes, adrs: ADRS) -> bytes:   #Input: Message 𝑀, secret seed SK.seed, public seed PK.seed, address ADRS
    csum = 0
    msg = base_2b(M, params.prm.lg_w, params.prm.len1)                # Convert message to base w
    for i in range(params.prm.len1):
        csum += params.prm.w - 1 - msg[i]                  # Compute checksum

    # NOTE is the same as  (8 - ((params.prm.len2 * params.prm.lg_w) % 8)) % 8
    # len2 and lg_w are static across all parameter sets, so the above equation returns always 4
    csum <<= 4
    msg += base_2b(toByte(csum, (params.prm.len2 * params.prm.lg_w + 7) // 8), params.prm.lg_w, params.prm.len2)  # Convert to base w

    skADRS = deepcopy(adrs)                     # Copy address to create key generation key address
    skADRS.setTypeAndClear(params.prm.WOTS_PRF)
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    sig = b""
    for i in range(params.prm.len):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, skADRS, SK_seed)      # Compute chain i secret value
        adrs.setChainAddress(i)
        sig += chain(sk, 0, msg[i], PK_seed, adrs)  # Compute chain i signature value

    return sig                                  #Output: WOTS+ signature 𝑠𝑖𝑔


#Algorithmus 8 (Computes a WOTS+ public key from a message and its signature)
def wots_pkFromSig(sig: bytes, M: bytes, PK_seed: bytes, adrs: ADRS) -> bytes:
    csum = 0
    msg = base_2b(M, params.prm.lg_w, params.prm.len1)                # Konvertiere Nachricht in Basis w
    for i in range(params.prm.len1):
        csum += params.prm.w - 1 - msg[i]                  # Berechne Prüfsumme

    # NOTE is the same as (8 - ((params.prm.len2 * params.prm.lg_w) % 8)) % 8
    # len2 and lg_w are static across all parameter sets, so the above equation returns always 4
    csum <<= 4
    msg += base_2b(toByte(csum, (params.prm.len2 * params.prm.lg_w + 7) // 8), params.prm.lg_w, params.prm.len2)  # Konvertiere in Basis w

    tmp = b""
    for i in range(params.prm.len):
        adrs.setChainAddress(i)
        tmp += chain(sig[i * params.prm.n:(i + 1) * params.prm.n], msg[i], params.prm.w - 1 - msg[i], PK_seed, adrs)

    wotspkADRS = deepcopy(adrs)                 # Kopiere Adresse, um WOTS+ öffentlichen Schlüssel zu erstellen
    wotspkADRS.setTypeAndClear(params.prm.WOTS_PK)
    wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    pksig = Tlen(PK_seed, wotspkADRS, tmp)
    return pksig                                #Output: WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔
