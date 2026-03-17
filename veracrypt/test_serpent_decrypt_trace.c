#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define rotr32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define LE32(x) (x)

// Include all the I-box and ILT definitions here
#define I7(i, r0, r1, r2, r3, r4) \
       {           \
    r4 = r2;   \
    r2 ^= r0;   \
    r0 &= r3;   \
    r2 = ~r2;      \
    r4 |= r3;   \
    r3 ^= r1;   \
    r1 |= r0;   \
    r0 ^= r2;   \
    r2 &= r4;   \
    r1 ^= r2;   \
    r2 ^= r0;   \
    r0 |= r2;   \
    r3 &= r4;   \
    r0 ^= r3;   \
    r4 ^= r1;   \
    r3 ^= r4;   \
    r4 |= r0;   \
    r3 ^= r2;   \
    r4 ^= r2;   \
            }

#define ILT(i, a, b, c, d, e) {\
	c = rotr32(c, 22);	\
	a = rotr32(a, 5); 	\
	c ^= d ^ (b << 7);	\
	a ^= b ^ d; 		\
	b = rotr32(b, 1); 	\
	d = rotr32(d, 7) ^ c ^ (a << 3);	\
	b ^= a ^ c; 		\
	c = rotr32(c, 3); 	\
	a = rotr32(a, 13);}

#define KX(r, a, b, c, d, e)	{\
	a ^= k[4 * r + 0]; \
	b ^= k[4 * r + 1]; \
	c ^= k[4 * r + 2]; \
	d ^= k[4 * r + 3];}

#define beforeI7(f) f(8,a,b,c,d,e)
#define afterI7(f) f(7,d,a,b,e,c)

// Simplified key schedule generation
void generate_key_schedule(const uint8_t *userKey, uint32_t *k) {
    // Load user key
    for (int i = 0; i < 8; i++)
        k[i] = LE32(((uint32_t*)userKey)[i]);
    
    // Expand
    k += 8;
    uint32_t t = k[-1];
    for (int i = 0; i < 132; ++i)
        k[i] = t = rotl32(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
    
    // Note: Would need full S-box transformations here, but for testing we'll use raw expansion
}

int main() {
    // Test vector: key = 00 01 02 ... 1f
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    uint32_t k[140];
    // For this test, let's just load the actual key schedule from the Kotlin output
    // We know k[136-139] after the first KX
    
    // Ciphertext: de 26 9f f8 33 e4 32 b8 5b 2e 88 d2 70 1c e7 5c
    uint32_t a = 0xf89f26de;
    uint32_t b = 0xb832e433;
    uint32_t c = 0xd2882e5b;
    uint32_t d = 0x5ce71c70;
    uint32_t e;
    
    printf("Initial: a=%08x b=%08x c=%08x d=%08x\n", a, b, c, d);
    
    // We need to know k[136-139] to do the first KX
    // From Kotlin: after first KX we get c701c5a3 2697b999 b83bbf4c 2f1edf93
    // So: a xor k[136] = 0xc701c5a3, so k[136] = 0xf89f26de xor 0xc701c5a3 = 0x3f9ee37d
    k[136] = 0xf89f26de ^ 0xc701c5a3;
    k[137] = 0xb832e433 ^ 0x2697b999;
    k[138] = 0xd2882e5b ^ 0xb83bbf4c;
    k[139] = 0x5ce71c70 ^ 0x2f1edf93;
    
    // Manually do the KX since the macro uses k directly
    a ^= k[136];
    b ^= k[137];
    c ^= k[138];
    d ^= k[139];
    printf("After first KX: a=%08x b=%08x c=%08x d=%08x\n", a, b, c, d);
    
    // Now do I7
    beforeI7(I7);
    printf("After I7: a=%08x b=%08x c=%08x d=%08x e=%08x\n", a, b, c, d, e);
    
    // Now continue with rest of first iteration
    // Need to compute k[128-135] for remaining ops
    // For now just trace what we have
    
    return 0;
}
