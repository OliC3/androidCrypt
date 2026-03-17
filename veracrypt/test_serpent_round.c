#include <stdio.h>
#include <stdint.h>

#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void S0f (uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

static void LTf (uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*a = rotl32(*a, 13);
	*c = rotl32(*c, 3);
	*d = rotl32(*d ^ *c ^ (*a << 3), 7);
	*b = rotl32(*b ^ *a ^ *c, 1);
	*a = rotl32(*a ^ *b ^ *d, 5);
	*c = rotl32(*c ^ *d ^ (*b << 7), 22);
}

static void KXf (const uint32_t *k, unsigned int r, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*a ^= k[r];
	*b ^= k[r + 1];
	*c ^= k[r + 2];
	*d ^= k[r + 3];
}

int main() {
    // Test vector: key = 00 01 02 ... 1f, plaintext = 00 01 02 ... 0f
    // First 4 key schedule values at k[8]:
    uint32_t k[140];
    k[8] = 0x03020100;
    k[9] = 0x07060504;
    k[10] = 0x0b0a0908;
    k[11] = 0x0f0e0d0c;
    
    // Plaintext
    uint32_t a = 0x03020100;
    uint32_t b = 0x07060504;
    uint32_t c = 0x0b0a0908;
    uint32_t d = 0x0f0e0d0c;
    uint32_t e;
    
    printf("Initial: a=%08x b=%08x c=%08x d=%08x\n", a, b, c, d);
    
    // First round: KXf(k, 0, &a, &b, &c, &d); S0f(&a, &b, &c, &d, &e); LTf(&b, &e, &c, &a);
    KXf(k + 8, 0, &a, &b, &c, &d);
    printf("After KX: a=%08x b=%08x c=%08x d=%08x\n", a, b, c, d);
    
    S0f(&a, &b, &c, &d, &e);
    printf("After S0: a=%08x b=%08x c=%08x d=%08x e=%08x\n", a, b, c, d, e);
    
    LTf(&b, &e, &c, &a);
    printf("After LT: a=%08x b=%08x c=%08x d=%08x e=%08x\n", a, b, c, d, e);
    
    return 0;
}
