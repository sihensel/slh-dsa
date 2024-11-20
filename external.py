import secrets
import hashlib

from internal import slh_keygen_internal, slh_sign_internal, slh_verify_internal
from params import Params
from wots import toByte

# Algorithmus 21 (Generates an SLH-DSA key pair)
def slh_keygen():

    # Generate random seeds
    SK_seed = secrets.token_bytes(Params.n)
    SK_prf = secrets.token_bytes(Params.n)
    PK_seed = secrets.token_bytes(Params.n)

    # Check for errors
    if not SK_seed or not SK_prf or not PK_seed:
        return None, None

    # Call the internal key generation function
    return slh_keygen_internal(SK_seed, SK_prf, PK_seed)    # Output: SLH-DSA key pair (SK, PK)

# Algorithmus 22 (Generates a pure SLH-DSA signature)
def slh_sign(M, ctx, SK):           # Input: Message 𝑀, context string 𝑐𝑡𝑥, private key SK

    if len(ctx) > 255:
        return None

    addrnd = secrets.token_bytes(Params.n)  # Skip for deterministic variant
    if addrnd is None:
        return None

    # M_prime = b'\x00' + bytes([len(ctx)]) + ctx + M
    M_prime = toByte(0, 1) + toByte(len(ctx), 1) + ctx + M

    SIG = slh_sign_internal(M_prime, SK, addrnd)  # Omit addrnd for deterministic variant

    return SIG          # Output: SLH-DSA signature SIG

# Algorithmus 23 (Generates a pre-hash SLH-DSA signature)
def slh_hash_sign(M, ctx, PH, SK):  # Input: Message 𝑀, context string 𝑐𝑡𝑥, pre-hash function PH, private key SK

    if len(ctx) > 255:
        return None

    addrnd = secrets.token_bytes(Params.n)  # Skip for deterministic variant
    if addrnd is None:
        return None

    # Pre-hash the message
    if PH == "SHA-256":
        PHM = hashlib.sha256(M).digest()
    elif PH == "SHA-512":
        PHM = hashlib.sha512(M).digest()
    elif PH == "SHAKE128":
        PHM = hashlib.shake_128(M).digest(256)
    elif PH == "SHAKE256":
        PHM = hashlib.shake_256(M).digest(512)
    else:
        # Handle other approved hash functions or XOFs
        raise NotImplementedError("Unsupported pre-hash function")

    # Construct the M' message
    M_prime = b'\x01' + bytes([len(ctx)]) + ctx + PHM

    # Sign the M' message
    SIG = slh_sign_internal(M_prime, SK, addrnd)  # Omit addrnd for deterministic variant

    return SIG                                  # Output: SLH-DSA signature SIG

# Algorithmus 24 (Verifies a pure SLH-DSA signature)
def slh_verify(M, SIG, ctx, PK):        # Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, public key PK

    if len(ctx) > 255:
        return False

    M_prime = b'\x00' + bytes([len(ctx)]) + ctx + M

    return slh_verify_internal(M_prime, SIG, PK)    # Output: Boolean

# Algorithmus 25 (Verifies a pre-hash SLH-DSA signature)
def slh_hash_verify(M, SIG, ctx, PH, PK):   # Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK

    if len(ctx) > 255:
        return False

    # Pre-hash the message
    if PH == "SHA-256":
        PHM = hashlib.sha256(M).digest()
    elif PH == "SHA-512":
        PHM = hashlib.sha512(M).digest()
    elif PH == "SHAKE128":
        PHM = hashlib.shake_128(M).digest(256)
    elif PH == "SHAKE256":
        PHM = hashlib.shake_256(M).digest(512)
    else:
        # Handle other approved hash functions or XOFs
        raise NotImplementedError("Unsupported pre-hash function")

    # Construct the M' message
    M_prime = b'\x01' + bytes([len(ctx)]) + ctx + PHM

    return slh_verify_internal(M_prime, SIG, PK)    # Output: Boolean


# test data
M = [10, 12, 15]
ctx = [0]
SK, PK = slh_keygen()
sig = slh_sign(M, ctx, SK)
