#!/usr/bin/env python3

from internal import slh_sign_internal, slh_verify_internal
from external import slh_keygen, slh_sign, slh_verify
import params
from params import setup_parameter_set


if __name__ == "__main__":

    # test vectors from https://github.com/usnistgov/ACVP-Server

    setup_parameter_set("SLH-DSA-SHAKE-128f")
    # NOTE these are the "old" test vectors from Nov. 15
    # test key gen SLH-DSA-SHAKE-128f
    sk_seed = bytes.fromhex("BBC74306F75DC2DAF7372B3C9841A4D6")
    sk_prf  = bytes.fromhex("852C17B459F1692B8E9A1A0DACE5BA26")
    pk_seed = bytes.fromhex("380C99304A0DDD32F344B95144E1FDEF")
    SK, PK = slh_keygen(sk_seed, sk_prf, pk_seed)
    assert PK.hex().upper() == "380C99304A0DDD32F344B95144E1FDEF60BBC2340E08770FB41A80A76CB08E34"

    # test sig gen SLH-DSA-SHAKE-128f
    SK = bytes.fromhex("1E464D08EF2F1A2509DBCB207BEE9E3BD314BC356857155836412601F09684927F5023810597D9A4B611F0E1B5ED965F7CBA20C4F6DB19D44FB1D4EE142B44AA")
    M = bytes.fromhex("DB2AC8E44B2DA9CC5813B11FBDE28081326BD0542971899CF9086212246D6BE761E4E37118B7FDEE9A777979CC132E6CEDEF8EE6D6FF20BE9BE19B491C4443D28C7D33EB4E6E71C051A6534930257E94527F566740F76594D032DF8A784F94EEC0AA9F4AA880EB4356CEDE3B93F0F17B6B1398B132047C2BC8DB6C39B2C88F30E2E73A21A1E9A8EA30886CBC232D6F3C6C9252077F77D6FBCB4034506A1B")
    pk_seed = SK[2 * params.prm.n:3 * params.prm.n]
    SIG = slh_sign_internal(M, SK, pk_seed)

    assert SIG[0:16].hex().upper() == "2C241D50D55454CD5DBD8714CC8D6383"

    # insert the test data into the corresponding files and run
    # test sig verify SLH-DSA-SHAKE-128f
    with open("msg.txt", "r") as fp:
        M = bytes.fromhex(fp.read())
    with open("key.txt", "r") as fp:
        PK = bytes.fromhex(fp.read())
    with open("sig.txt", "r") as fp:
        SIG = bytes.fromhex(fp.read())
    with open("ctx.txt", "r") as fp:
        ctx = bytes.fromhex(fp.read())

    assert slh_verify(M, ctx, SIG, PK) == True
    print("Done")
