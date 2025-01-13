from types import SimpleNamespace


def setup_parameter_set(name: str):
    # NOTE this approach is a bit hacky, but since we only read parameters
    # and never change them at runtime we should be fine
    global prm
    prm = SimpleNamespace()

    # these are the same for all parameter sets
    prm.WOTS_HASH = 0
    prm.WOTS_PK = 1
    prm.TREE = 2
    prm.FORS_TREE = 3
    prm.FORS_ROOTS = 4
    prm.WOTS_PRF = 5
    prm.FORS_PRF = 6
    prm.lg_w = 4
    prm.w = 16
    prm.len2 = 3

    if name == "SLH-DSA-SHAKE-128s":
        prm.n = 16
        prm.h = 63
        prm.d = 7
        prm.h_ = 9
        prm.a = 12
        prm.k = 14
        prm.m = 30

    elif name == "SLH-DSA-SHAKE-128f":
        prm.n = 16
        prm.h = 66
        prm.d = 22
        prm.h_ = 3
        prm.a = 6
        prm.k = 33
        prm.m = 34

    elif name == "SLH-DSA-SHAKE-192s":
        prm.n = 24
        prm.h = 63
        prm.d = 7
        prm.h_ = 9
        prm.a = 14
        prm.k = 17
        prm.m = 39

    elif name == "SLH-DSA-SHAKE-192f":
        prm.n = 24
        prm.h = 66
        prm.d = 22
        prm.h_ = 3
        prm.a = 8
        prm.k = 33
        prm.m = 42

    elif name == "SLH-DSA-SHAKE-256s":
        prm.n = 32
        prm.h = 64
        prm.d = 8
        prm.h_ = 8
        prm.a = 14
        prm.k = 22
        prm.m = 47

    elif name == "SLH-DSA-SHAKE-256f":
        prm.n = 32
        prm.h = 68
        prm.d = 17
        prm.h_ = 4
        prm.a = 9
        prm.k = 35
        prm.m = 49

    else:
        print("Invalid parameter set name")

    # calculate len1 and len
    prm.len1 = 2 * prm.n
    prm.len = prm.len1 + prm.len2
