#include <stdio.h>
#include <stdint.h>

#define rotr32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void I7f (uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
{
	*r1 ^= *r2 & ~*r3;
	*r0 ^= *r2 & *r3;
	*r4 = *r0;
	*r0 &= *r1;
	*r4 ^= *r3;
	*r3 ^= *r2;
	*r2 |= *r0;
	*r0 ^= *r1;
	*r1 |= *r2;
	*r2 ^= *r4;
	*r1 ^= *r4;
	*r4 &= *r0;
	*r4 ^= *r3;
	*r3 &= *r1;
	*r3 ^= *r0;
	*r0 |= *r4;
	*r3 ^= *r2;
	*r0 ^= *r2;
}

static void ILTf (uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*c = rotr32(*c, 22);
	*a = rotr32(*a, 5);
	*c ^= *d ^ (*b << 7);
	*a ^= *b ^ *d;
	*b = rotr32(*b, 1);
	*d = rotr32(*d, 7) ^ *c ^ (*a << 3);
	*b ^= *a ^ *c;
	*c = rotr32(*c, 3);
	*a = rotr32(*a, 13);
}

static void KXf (const uint32_t *k, unsigned int r, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*a ^= k[r];
	*b ^= k[r + 1];
	*c ^= k[r + 2];
	*d ^= k[r + 3];
}

int main() {
    // Ciphertext from encryption: de 26 9f f8 33 e4 32 b8 5b 2e 88 d2 70 1c e7 5c
    uint32_t a = 0xf89f26de;  // Little-endian
    uint32_t b = 0xb832e433;
    uint32_t c = 0xd2882e5b;
    uint32_t d = 0x5ce71c70;
    uint32_t e;
    
    // Key schedule at k[104+32] (first KX uses k[136-139])
    uint32_t k[140];
    // These would need to be the actual key schedule values...
    // For now, let's just trace the operations
    
    printf("Initial: a=%08x b=%08x c=%08x d=%08x\n", a, b, c, d);
    
    // First operation: KXf(k, 32, &a, &b, &c, &d)
    // (Skipping actual XOR since we don't have k values)
    
    // Then: I7f(&a, &b, &c, &d, &e)
    I7f(&a, &b, &c, &d, &e);
    printf("After I7: a=%08x b=%08x c=%08x d=%08x e=%08x\n", a, b, c, d, e);
    
    return 0;
}
