#include <stdio.h>
#include <string.h>
#include <stdint.h>

// From Serpent.c - simplified for testing
typedef unsigned int uint32;

#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define rotr32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define LE32(x) (x)

static void LTf (uint32 *a, uint32 *b, uint32 *c, uint32 *d)
{
	*a = rotl32(*a, 13);
	*c = rotl32(*c, 3);
	*d = rotl32(*d ^ *c ^ (*a << 3), 7);
	*b = rotl32(*b ^ *a ^ *c, 1);
	*a = rotl32(*a ^ *b ^ *d, 5);
	*c = rotl32(*c ^ *d ^ (*b << 7), 22);
}

static void S0f (uint32 *r0, uint32 *r1, uint32 *r2, uint32 *r3, uint32 *r4)
{
	*r3 ^= *r0;
	*r4 = *r1;
	*r1 &= *r3;
	*r4 ^= *r2;
	*r1 ^= *r0;
	*r0 |= *r3;
	*r0 ^= *r4;
	*r4 ^= *r3;
	*r3 ^= *r2;
	*r2 |= *r1;
	*r2 ^= *r4;
	*r4 = ~*r4;
	*r4 |= *r1;
	*r1 ^= *r3;
	*r1 ^= *r4;
	*r3 |= *r0;
	*r1 ^= *r3;
	*r4 ^= *r3;
}

static void KXf (const uint32 *k, unsigned int r, uint32 *a, uint32 *b, uint32 *c, uint32 *d)
{
	*a ^= k[r];
	*b ^= k[r + 1];
	*c ^= k[r + 2];
	*d ^= k[r + 3];
}

int main() {
    // Test with simple values
    uint32 a = 0x00010203;
    uint32 b = 0x04050607;
    uint32 c = 0x08090A0B;
    uint32 d = 0x0C0D0E0F;
    uint32 e = 0;
    
    printf("Before S0f: a=%08X b=%08X c=%08X d=%08X e=%08X\n", a, b, c, d, e);
    
    // Assume key schedule k[8..11] = 0 for simplicity
    uint32 k[12] = {0};
    
    // First round: KXf(k, 0, &a, &b, &c, &d); S0f(&a, &b, &c, &d, &e); LTf(&b, &e, &c, &a);
    KXf(k, 0, &a, &b, &c, &d);
    printf("After KXf:  a=%08X b=%08X c=%08X d=%08X e=%08X\n", a, b, c, d, e);
    
    S0f(&a, &b, &c, &d, &e);
    printf("After S0f:  a=%08X b=%08X c=%08X d=%08X e=%08X\n", a, b, c, d, e);
    
    LTf(&b, &e, &c, &a);
    printf("After LTf:  a=%08X b=%08X c=%08X d=%08X e=%08X\n", a, b, c, d, e);
    
    return 0;
}
