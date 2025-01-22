.PHONY: clean

short:
	gcc -lgcrypt -lsodium main.c external.c internal.c KeccakP-1600-AVX512.c KeccakSpongeWidth1600.c fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c -o main -march=skylake-avx512 -O3

clean:
	rm main
