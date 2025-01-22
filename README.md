# SLH-DSA

Implementation of Fips 205 in Python and C.

See `main.py` and `main.c` on how to use access the external and internal interfaces respectively.

The C implementation requires the sodium and gcrypt libraries to compile.
For more information check the Makefile.

For Shake256, we are using the kcp/optimized1600AVX512 implementation, of which a copy is included here.
