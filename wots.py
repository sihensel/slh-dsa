import math
from copy import deepcopy

from adrs import ADRS
from params import Params, Tlen, PRF, F

#Algorhitmus 1 (Computes 𝑙𝑒𝑛2)
def gen_len2(n, lg_w): #Input: Security parameter 𝑛, bits per hash chain 𝑙𝑔_𝑤
    w = 2 ** lg_w                                #Compute w: w = 2^lg_w
    len1 = math.floor((8 * n + lg_w - 1) / lg_w) #Compute len1
    max_checksum = len1 * (w - 1)                #Compute maximum possible checksum value
    len2 = 1                                     #Initialize len2
    capacity = w                                 #Initialize capacity

    while capacity <= max_checksum:              #Loop until capacity exceeds max_checksum
        len2 += 1
        capacity *= w

    return len2                                  #Output: 𝑙𝑒𝑛2

#Algorithmus 2 (Converts a byte string to an integer)
# NOTE we can either leave this separate or take it from the ADRS class
def toInt(X, n):                                #Input: 𝑛-byte string 𝑋
    total = 0
    for i in range(n):
        total = 256 * total + X[i]
    return total                                #Output: Integer value of 𝑋

#Algorithmus 3 (Converts an integer to a byte string)
# NOTE we can either leave this separate or take it from the ADRS class
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
def chain(X, i, s, PK_seed, adrs: ADRS):              #Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS
    tmp = X
    for j in range(i, i + s):
        adrs.setHashAddress(j)
        tmp = F(PK_seed, adrs, tmp)

    return tmp                                  #Output: Value of F iterated 𝑠 times on 𝑋

#Algorithmus 6 (Generates a WOTS+ public key)
def wots_pkGen(SK_seed, PK_seed, adrs: ADRS):         #Input: Secret seed SK.seed, public seed PK.seed, address ADRS
    skADRS = deepcopy(adrs)                     # Copy address to create key generation key address
    skADRS.setTypeAndClear(Params.WOTS_PRF)
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    tmp = []
    for i in range(Params.len):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS)      # Compute secret value for chain i
        adrs.setChainAddress(i)
        tmp.append(chain(sk, 0, Params.w - 1, PK_seed, adrs))  # Compute public value for chain i

    wotspkADRS = deepcopy(adrs)                 # Copy address to create WOTS+ public key address
    wotspkADRS.setTypeAndClear(Params.WOTS_PK)
    wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    pk = Tlen(PK_seed, wotspkADRS, tmp)         # Compress public key
    return pk                                   #Output: WOTS+ public key 𝑝𝑘

#Algorithmus 7 (Generates a WOTS+ signature on an n-byte message)
def wots_sign(M, SK_seed, PK_seed, adrs: ADRS):       #Input: Message 𝑀, secret seed SK.seed, public seed PK.seed, address ADRS
    csum = 0
    msg = base_2b(M, Params.lg_w, Params.len1)                # Convert message to base w
    for i in range(Params.len1):
        csum += Params.w - 1 - msg[i]                  # Compute checksum

    csum <<= (8 - ((Params.len1 * Params.lg_w) % 8)) % 8      # For lg_w = 4, left shift by 4
    msg += base_2b(toByte(csum, math.ceil((Params.len2 * Params.lg_w) / 8)), Params.lg_w, Params.len2)  # Convert to base w

    skADRS = deepcopy(adrs)                     # Copy address to create key generation key address
    skADRS.setTypeAndClear(Params.WOTS_PRF)
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    sig = []
    for i in range(Params.len):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS)      # Compute chain i secret value
        adrs.setChainAddress(i)
        sig.append(chain(sk, 0, msg[i], PK_seed, adrs))  # Compute chain i signature value

    return sig                                  #Output: WOTS+ signature 𝑠𝑖𝑔

#Algorithmus 8 (Computes a WOTS+ public key from a message and its signature)
def wots_pkFromSig(sig, M, PK_seed, adrs: ADRS):      #Input: WOTS+ signature 𝑠𝑖𝑔, message 𝑀, public seed PK.seed, address ADRS
    csum = 0
    msg = base_2b(M, Params.lg_w, Params.len1)                # Konvertiere Nachricht in Basis w
    for i in range(Params.len1):
        csum += Params.w - 1 - msg[i]                  # Berechne Prüfsumme

    csum <<= (8 - ((Params.len2 * Params.lg_w) % 8)) % 8      # Für lg_w = 4, shift um 4 nach links
    msg += base_2b(toByte(csum, math.ceil((Params.len2 * Params.lg_w) / 8)), Params.lg_w, Params.len2)  # Konvertiere in Basis w

    tmp = [0] * Params.len
    for i in range(Params.len):
        adrs.setChainAddress(i)
        tmp[i] = chain(sig[i], msg[i], Params.w - 1 - msg[i], PK_seed, adrs)

    wotspkADRS = deepcopy(adrs)                 # Kopiere Adresse, um WOTS+ öffentlichen Schlüssel zu erstellen
    wotspkADRS.setTypeAndClear(Params.WOTS_PK)
    wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())

    pksig = Tlen(PK_seed, wotspkADRS, tmp)
    return pksig                                #Output: WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔
