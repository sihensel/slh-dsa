import secrets
import hashlib

import params
from adrs import toByte
from internal import slh_keygen_internal, slh_sign_internal, slh_verify_internal

# Algorithmus 21 (Generates an SLH-DSA key pair)
def slh_keygen() -> tuple:

    # Generate random seeds
    SK_seed = secrets.token_bytes(params.prm.n)
    SK_prf = secrets.token_bytes(params.prm.n)
    PK_seed = secrets.token_bytes(params.prm.n)

    # Check for errors
    if not SK_seed or not SK_prf or not PK_seed:
        return None, None

    # Call the internal key generation function
    return slh_keygen_internal(SK_seed, SK_prf, PK_seed)    # Output: SLH-DSA key pair (SK, PK)


# Algorithmus 22 (Generates a pure SLH-DSA signature)
def slh_sign(M: bytes, ctx: list, SK: tuple) -> list:           # Input: Message 𝑀, context string 𝑐𝑡𝑥, private key SK

    if len(ctx) > 255:
        return []

    addrnd = secrets.token_bytes(params.prm.n)  # Skip for deterministic variant
    if addrnd is None:
        return []

    # NOTE M is a bytes object, hence we need to put it in a list so the + operator works
    M_prime = toByte(0, 1) + toByte(len(ctx), 1) + ctx + [M]

    SIG = slh_sign_internal(M_prime, SK, addrnd)  # Omit addrnd for deterministic variant

    return SIG          # Output: SLH-DSA signature SIG


# Algorithmus 23 (Generates a pre-hash SLH-DSA signature)
def hash_slh_sign(M: bytes, ctx: list, PH: str, SK: tuple) -> list:  # Input: Message 𝑀, context string 𝑐𝑡𝑥, pre-hash function PH, private key SK

    if len(ctx) > 255:
        return []

    addrnd = secrets.token_bytes(params.prm.n)  # Skip for deterministic variant
    if addrnd is None:
        return []

    # Pre-hash the message
    match PH:
        case "SHA-256":
            OID = toByte(0x0609608648016503040201, 11)
            PHM = hashlib.sha256(M).digest()
        case "SHA-512":
            OID = toByte(0x0609608648016503040203, 11)
            PHM = hashlib.sha512(M).digest()
        case "SHAKE128":
            OID = toByte(0x060960864801650304020B, 11)
            PHM = hashlib.shake_128(M).digest(256)
        case "SHAKE256":
            OID = toByte(0x060960864801650304020C, 11)
            PHM = hashlib.shake_256(M).digest(512)
        case _:
            # Handle other approved hash functions or XOFs
            raise NotImplementedError("Unsupported pre-hash function")

    # Construct the M' message
    M_prime = toByte(1, 1) + toByte(len(ctx), 1) + ctx + OID + [PHM]

    # Sign the M' message
    SIG = slh_sign_internal(M_prime, SK, addrnd)  # Omit addrnd for deterministic variant

    return SIG                                  # Output: SLH-DSA signature SIG


# Algorithmus 24 (Verifies a pure SLH-DSA signature)
def slh_verify(M: bytes, SIG: list, ctx: list, PK: tuple) -> bool:        # Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, public key PK

    if len(ctx) > 255:
        return False

    M_prime = toByte(0, 1) + toByte(len(ctx), 1) + ctx + [M]

    return slh_verify_internal(M_prime, SIG, PK)    # Output: Boolean


# Algorithmus 25 (Verifies a pre-hash SLH-DSA signature)
def hash_slh_verify(M: bytes, SIG: list, ctx: list, PH: str, PK: tuple) -> bool:   # Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK

    if len(ctx) > 255:
        return False

    # Pre-hash the message
    match PH:
        case "SHA-256":
            OID = toByte(0x0609608648016503040201, 11)
            PHM = hashlib.sha256(M).digest()
        case "SHA-512":
            OID = toByte(0x0609608648016503040203, 11)
            PHM = hashlib.sha512(M).digest()
        case "SHAKE128":
            OID = toByte(0x060960864801650304020B, 11)
            PHM = hashlib.shake_128(M).digest(256)
        case "SHAKE256":
            OID = toByte(0x060960864801650304020C, 11)
            PHM = hashlib.shake_256(M).digest(512)
        case _:
            # Handle other approved hash functions or XOFs
            raise NotImplementedError("Unsupported pre-hash function")

    # Construct the M' message
    M_prime = toByte(1, 1) + toByte(len(ctx), 1) + ctx + OID + [PHM]

    return slh_verify_internal(M_prime, SIG, PK)    # Output: Boolean
