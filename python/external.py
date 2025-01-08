import secrets
import hashlib

import params
from adrs import toByte
from internal import slh_keygen_internal, slh_sign_internal, slh_verify_internal

# Algorithmus 21 (Generates an SLH-DSA key pair)
def slh_keygen() -> tuple:

    # Generate random seeds
    # SK_seed = secrets.token_bytes(params.prm.n)
    # SK_prf = secrets.token_bytes(params.prm.n)
    # PK_seed = secrets.token_bytes(params.prm.n)
    # SK_seed = bytes.fromhex("FC29E8D21509D155801D8885CABBC9E9")
    # SK_prf = bytes.fromhex("0CD21CBFC49606E5C51645B7FA1C954E")
    # PK_seed = bytes.fromhex("D7AA1048A9F661EA58FD2914268BB015")
    SK_seed = bytes.fromhex("7C9935A0B07694AA0C6D10E4DB6B1ADD")
    SK_prf = bytes.fromhex("2FD81A25CCB148032DCD739936737F2D")
    PK_seed = bytes.fromhex("B505D7CFAD1B497499323C8686325E47")

    # Check for errors
    if not SK_seed or not SK_prf or not PK_seed:
        return None, None

    # Call the internal key generation function
    return slh_keygen_internal(SK_seed, SK_prf, PK_seed)    # Output: SLH-DSA key pair (SK, PK)


# Algorithmus 22 (Generates a pure SLH-DSA signature)
def slh_sign(M: bytes, ctx: list, SK: tuple) -> list:           # Input: Message 𝑀, context string 𝑐𝑡𝑥, private key SK

    if len(ctx) > 255:
        return []

    # addrnd = secrets.token_bytes(params.prm.n)  # Skip for deterministic variant
    # if addrnd is None:
    #     return []

    # NOTE for deterministic variant, use PK_seed for addrnd
    addrnd = SK[2]

    # NOTE M is a bytes object, hence we need to put it in a list so the + operator works
    M_prime = toByte(0, 1) + toByte(len(ctx), 1) + ctx
    M_prime = bytearray(M_prime) + M

    SIG = slh_sign_internal(M_prime, SK, addrnd)  # Omit addrnd for deterministic variant

    return SIG          # Output: SLH-DSA signature SIG


# Algorithmus 23 (Generates a pre-hash SLH-DSA signature)
def hash_slh_sign(M: bytes, ctx: list, PH: str, SK: tuple) -> list:  # Input: Message 𝑀, context string 𝑐𝑡𝑥, pre-hash function PH, private key SK

    if len(ctx) > 255:
        return []

    # addrnd = secrets.token_bytes(params.prm.n)  # Skip for deterministic variant
    # if addrnd is None:
    #     return []
    addrnd = SK[2]

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

    # Sign the M' message
    SIG = slh_sign_internal(M_prime, SK, addrnd)  # Omit addrnd for deterministic variant

    return SIG                                  # Output: SLH-DSA signature SIG


# Algorithmus 24 (Verifies a pure SLH-DSA signature)
def slh_verify(M: bytes, SIG: list, ctx: list, PK: tuple) -> bool:        # Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, public key PK

    if len(ctx) > 255:
        return False

    M_prime = toByte(0, 1) + toByte(len(ctx), 1) + ctx
    M_prime = bytearray(M_prime) + M

    return slh_verify_internal(M_prime, SIG, PK)    # Output: Boolean


# Algorithmus 25 (Verifies a pre-hash SLH-DSA signature)
def hash_slh_verify(M: bytes, SIG: list, ctx: list, PH: str, PK: tuple) -> bool:   # Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK

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

    return slh_verify_internal(M_prime, SIG, PK)    # Output: Boolean
