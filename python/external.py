import secrets
import hashlib

import params
from adrs import toByte
from internal import slh_keygen_internal, slh_sign_internal, slh_verify_internal

# Algorithmus 21 (Generates an SLH-DSA key pair)
def slh_keygen(SK_seed: bytes = b"", SK_prf: bytes = b"", PK_seed: bytes = b"") -> tuple:

    # Generate random seeds
    if not SK_seed:
        SK_seed = secrets.token_bytes(params.prm.n)
    if not SK_prf:
        SK_prf = secrets.token_bytes(params.prm.n)
    if not PK_seed:
        PK_seed = secrets.token_bytes(params.prm.n)

    # Check for errors
    if not SK_seed or not SK_prf or not PK_seed:
        return None, None

    # Call the internal key generation function
    return slh_keygen_internal(SK_seed, SK_prf, PK_seed)    # Output: SLH-DSA key pair (SK, PK)


# Algorithmus 22 (Generates a pure SLH-DSA signature)
def slh_sign(M: bytes, SK: bytes, deterministic: bool = True) -> bytes:

    # for deterministic variant, use PK_seed for addrnd
    if deterministic:
        addrnd = SK[2 * params.prm.n:3 * params.prm.n]
    else:
        addrnd = secrets.token_bytes(params.prm.n)
        if addrnd is None:
            return b""

    return slh_sign_internal(M, SK, addrnd)


# Algorithmus 23 (Generates a pre-hash SLH-DSA signature)
def hash_slh_sign(M: bytes, ctx: list, PH: str, SK: bytes, deterministic: bool = True) -> bytes:

    if len(ctx) > 255:
        return b""

    if deterministic:
        addrnd = SK[2 * params.prm.n:3 * params.prm.n]
    else:
        addrnd = secrets.token_bytes(params.prm.n)  # Skip for deterministic variant
        if addrnd is None:
            return b""

    # NOTE we initialize PHM as an array with 64 bytes
    PHM = bytearray([0] * 64)

    # Pre-hash the message
    match PH:
        case "SHA-256":
            OID = toByte(0x0609608648016503040201, 11)
            PHM[0:32] = hashlib.sha256(M).digest()
        case "SHA-512":
            OID = toByte(0x0609608648016503040203, 11)
            PHM[0:64] = hashlib.sha512(M).digest()
        case "SHAKE128":
            OID = toByte(0x060960864801650304020B, 11)
            PHM[0:32] = hashlib.shake_128(M).digest(32)
        case "SHAKE256":
            OID = toByte(0x060960864801650304020C, 11)
            PHM[0:64] = hashlib.shake_256(M).digest(64)
        case _:
            # Handle other approved hash functions or XOFs
            raise NotImplementedError("Unsupported pre-hash function")

    # Construct the M' message
    M_prime = toByte(1, 1) + toByte(len(ctx), 1) + ctx + OID
    M_prime = bytearray(M_prime) + PHM

    return slh_sign_internal(M_prime, SK, addrnd)  # Omit addrnd for deterministic variant


# Algorithmus 24 (Verifies a pure SLH-DSA signature)
def slh_verify(M: bytes, SIG: bytes, PK: bytes) -> bool:
    return slh_verify_internal(M, SIG, PK)


# Algorithmus 25 (Verifies a pre-hash SLH-DSA signature)
def hash_slh_verify(M: bytes, SIG: bytes, ctx: list, PH: str, PK: bytes) -> bool:   # Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK

    if len(ctx) > 255:
        return False

    PHM = bytearray([0] * 64)
    # Pre-hash the message
    match PH:
        case "SHA-256":
            OID = toByte(0x0609608648016503040201, 11)
            PHM[0:32] = hashlib.sha256(M).digest()
        case "SHA-512":
            OID = toByte(0x0609608648016503040203, 11)
            PHM[0:64] = hashlib.sha512(M).digest()
        case "SHAKE128":
            OID = toByte(0x060960864801650304020B, 11)
            PHM[0:32] = hashlib.shake_128(M).digest(32)
        case "SHAKE256":
            OID = toByte(0x060960864801650304020C, 11)
            PHM[0:64] = hashlib.shake_256(M).digest(64)
        case _:
            # Handle other approved hash functions or XOFs
            raise NotImplementedError("Unsupported pre-hash function")

    # Construct the M' message
    M_prime = toByte(1, 1) + toByte(len(ctx), 1) + ctx + OID
    M_prime = bytearray(M_prime) + PHM

    return slh_verify_internal(M_prime, SIG, PK)
