#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "crypto_sign.h"
#include "sha512.h"
#include "ge25519.h"

static void get_hram(unsigned char *hram, const unsigned char *sm, const unsigned char *pk, unsigned char *playground, unsigned long long smlen)
{
	unsigned long long i;

	for (i =  0;i < 32;++i)    playground[i] = sm[i];
	for (i = 32;i < 64;++i)    playground[i] = pk[i-32];
	for (i = 64;i < smlen;++i) playground[i] = sm[i];

	crypto_hash_sha512(hram,playground,smlen);
}

void die(const char * msg) {
	puts(msg);
	fflush(stdout);
	exit(1);
}

void dump_array_32(const crypto_uint32 *array, size_t size) {
	if (size == 0)
		return;
	for (size_t i = 0; i < size-1; i++) {
		printf("%02X ", array[i]);
	}
	printf("%02X", array[size-1]);
}
void dump_array(const unsigned char *array, size_t size) {
	if (size == 0)
		return;
	for (size_t i = 0; i < size-1; i++) {
		printf("%02X ", array[i]);
	}
	printf("%02X", array[size-1]);
}

#define BYTES (64 + 4)

const unsigned char pk[32] = {238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127};
/* const unsigned char pk[32]; */
unsigned char m[BYTES];
unsigned char sm[BYTES];
int main() {
	unsigned long long mlen_ = BYTES;
	unsigned long long *mlen = &mlen_;
	unsigned long long smlen = BYTES;

	sm[0] = 1;

	sm[64] = 'a';
	sm[64+1] = 'b';
	sm[64+2] = 'c';
	sm[64+3] = 'd';

	int i, ret;
	unsigned char t2[32];
	ge25519 get1, get2;
	sc25519 schram, scs;
	unsigned char hram[crypto_hash_sha512_BYTES];

	ret = ge25519_unpackneg_vartime(&get1, pk);
	if (ret != 0)
		die("ge25519_unpackneg_vartime failed");

	get_hram(hram,sm,pk,m,smlen);

	sc25519_from64bytes(&schram, hram);

	sc25519_from32bytes(&scs, sm+32);

	ge25519_double_scalarmult_vartime(&get2, &get1, &schram, &ge25519_base, &scs);
	ge25519_pack(t2, &get2);

	printf("t2 = ");
	dump_array(t2, 32);
	printf("\n");

	ret = crypto_verify_32(sm, t2);
	if (ret != 0)
		die("crypto_verify_32 failed");

	puts("OK");
	return 0;
}
