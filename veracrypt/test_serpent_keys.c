#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef unsigned __int32 uint32;
typedef unsigned __int8 uint8;

#define rotl32(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#define rotr32(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))

#define LE32(x) (x)

// S-box macros (only need for key schedule)
#define S0(i, r0, r1, r2, r3, r4) \
       {           \
    r3 ^= r0;   \
    r4 = r1;   \
    r1 &= r3;   \
    r4 ^= r2;   \
    r1 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r4;   \
    r4 ^= r3;   \
    r3 ^= r2;   \
    r2 |= r1;   \
    r2 ^= r4;   \
    r4 = ~r4;      \
    r4 |= r1;   \
    r1 ^= r3;   \
    r1 ^= r4;   \
    r3 |= r0;   \
    r1 ^= r3;   \
    r4 ^= r3;   \
            }

#define S1(i, r0, r1, r2, r3, r4) \
       {           \
    r0 = ~r0;      \
    r2 = ~r2;      \
    r4 = r0;   \
    r0 &= r1;   \
    r2 ^= r0;   \
    r0 |= r3;   \
    r3 ^= r2;   \
    r1 ^= r0;   \
    r0 ^= r4;   \
    r4 |= r1;   \
    r1 ^= r3;   \
    r2 |= r0;   \
    r2 &= r4;   \
    r0 ^= r1;   \
    r1 &= r2;   \
    r1 ^= r0;   \
    r0 &= r2;   \
    r0 ^= r4;   \
            }

#define S2(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r0;   \
    r0 &= r2;   \
    r0 ^= r3;   \
    r2 ^= r1;   \
    r2 ^= r0;   \
    r3 |= r4;   \
    r3 ^= r1;   \
    r4 ^= r2;   \
    r1 = r3;   \
    r3 |= r4;   \
    r3 ^= r0;   \
    r0 &= r1;   \
    r4 ^= r0;   \
    r1 ^= r3;   \
    r1 ^= r4;   \
    r4 = ~r4;      \
            }

#define S3(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r0;   \
    r0 |= r3;   \
    r3 ^= r1;   \
    r1 &= r4;   \
    r4 ^= r2;   \
    r2 ^= r3;   \
    r3 &= r0;   \
    r4 |= r1;   \
    r3 ^= r4;   \
    r0 ^= r1;   \
    r4 &= r0;   \
    r1 ^= r3;   \
    r4 ^= r2;   \
    r1 |= r0;   \
    r1 ^= r2;   \
    r0 ^= r3;   \
    r2 = r1;   \
    r1 |= r3;   \
    r1 ^= r0;   \
            }

#define LKf(k, n, ra, rb, rc, rd) \
    ra ^= k[n];   \
    rb ^= k[n+1];   \
    rc ^= k[n+2];   \
    rd ^= k[n+3]

#define SKf(k, n, ra, rb, rc, rd) \
    k[n] = ra;   \
    k[n+1] = rb;   \
    k[n+2] = rc;   \
    k[n+3] = rd

#define S0f(r0, r1, r2, r3, r4)  S0(0, r0, r1, r2, r3, r4)
#define S1f(r0, r1, r2, r3, r4)  S1(0, r0, r1, r2, r3, r4)
#define S2f(r0, r1, r2, r3, r4)  S2(0, r0, r1, r2, r3, r4)
#define S3f(r0, r1, r2, r3, r4)  S3(0, r0, r1, r2, r3, r4)

void serpent_set_key(const unsigned __int8 *userKey, unsigned __int8 *ks)
{
	unsigned __int32 a,b,c,d,e;
	unsigned __int32 *k = (unsigned __int32 *)ks;
	unsigned __int32 t;
	int i;

	for (i = 0; i < 8; i++)
		k[i] = LE32(((unsigned __int32*)userKey)[i]);

	k += 8;
	t = k[-1];
	for (i = 0; i < 132; ++i)
		k[i] = t = rotl32(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
	k -= 20;

	for (i=0; i<4; i++)
	{
		LKf (k, 20, &a, &e, &b, &d); S3f (a, e, b, d, c); SKf (k, 16, &e, &b, &d, &c);
		LKf (k, 24, &c, &b, &a, &e); S2f (c, b, a, e, d); SKf (k, 20, &a, &e, &b, &d);
		LKf (k, 28, &b, &e, &c, &a); S1f (b, e, c, a, d); SKf (k, 24, &c, &b, &a, &e);
		LKf (k, 32, &a, &b, &c, &d); S0f (a, b, c, d, e); SKf (k, 28, &b, &e, &c, &a);
		k += 8*4;
		LKf (k,  4, &a, &c, &d, &b); S7f (a, c, d, b, e); SKf (k,  0, &d, &e, &b, &a);
		LKf (k,  8, &a, &c, &b, &e); S6f (a, c, b, e, d); SKf (k,  4, &a, &c, &d, &b);
		LKf (k, 12, &b, &a, &e, &c); S5f (b, a, e, c, d); SKf (k,  8, &a, &c, &b, &e);
		LKf (k, 16, &e, &b, &d, &c); S4f (e, b, d, c, a); SKf (k, 12, &b, &a, &e, &c);
	}
	LKf (k, 20, &a, &e, &b, &d); S3f (a, e, b, d, c); SKf (k, 16, &e, &b, &d, &c);
}

int main() {
    uint8 key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = i;
    }
    
    uint8 ks[560];  // 140 * 4 bytes
    serpent_set_key(key, ks);
    
    printf("Key schedule (first 40 words, starting from k[8]):\n");
    uint32 *k = (uint32*)ks;
    for (int i = 8; i < 48; i++) {
        printf("k[%d] = 0x%08x\n", i, k[i]);
    }
    
    return 0;
}
