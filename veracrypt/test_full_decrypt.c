#include <stdio.h>
#include <stdint.h>

// Copy the full Serpent decrypt code from the C implementation
#define rotr32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef uint32_t uint32;
typedef unsigned __int8 byte;

// Inverse linear transformation
#define ILT(a,b,c,d)	do {					\
	  a = rotr32(a, 5); c = rotr32(c, 22);	\
	  a ^= b ^ d; c ^= d ^ (b << 7);		\
	  b = rotr32(b, 1); d = rotr32(d, 7) ^ c ^ (a << 3);	\
	  b ^= a ^ c; a = rotr32(a, 13); c = rotr32(c, 3);	\
	  d = rotr32(d, 7); } while (0)

// Inverse S-boxes (from Serpent.c lines 411-475)
#define I7(i, r0, r1, r2, r3, r4) \
	r4 = r2; \
	r2 ^= r0; \
	r0 &= r3; \
	r2 = ~r2; \
	r4 |= r3; \
	r3 ^= r1; \
	r1 |= r0; \
	r0 ^= r2; \
	r2 &= r4; \
	r1 ^= r2; \
	r2 ^= r0; \
	r0 |= r2; \
	r3 &= r4; \
	r0 ^= r3; \
	r4 ^= r1; \
	r3 ^= r4; \
	r4 |= r0; \
	r3 ^= r2; \
	r4 ^= r2;

#define I6(i, r0, r1, r2, r3, r4) \
	r2 ^= r0; \
	r4 = r0; \
	r0 &= r3; \
	r4 ^= r3; \
	r0 ^= r2; \
	r3 ^= r1; \
	r1 |= r4; \
	r2 |= r0; \
	r1 ^= r0; \
	r0 |= r4; \
	r2 ^= r3; \
	r0 ^= r3; \
	r3 &= r1; \
	r3 ^= r2; \
	r1 ^= r0; \
	r2 &= r0; \
	r4 ^= r3; \
	r2 ^= r1; \
	r1 ^= r4; \
	r4 = ~r4;

#define I5(i, r0, r1, r2, r3, r4) \
	r4 = r1; \
	r1 |= r2; \
	r2 ^= r4; \
	r1 ^= r3; \
	r3 &= r4; \
	r2 ^= r3; \
	r3 |= r0; \
	r0 = ~r0; \
	r3 ^= r2; \
	r2 |= r0; \
	r4 ^= r1; \
	r2 ^= r4; \
	r4 &= r0; \
	r0 ^= r1; \
	r1 ^= r3; \
	r0 &= r2; \
	r2 ^= r3; \
	r0 ^= r2; \
	r2 ^= r4; \
	r4 ^= r3;

#define I4(i, r0, r1, r2, r3, r4) \
	r2 ^= r3; \
	r4 = r0; \
	r0 &= r1; \
	r0 ^= r2; \
	r2 |= r3; \
	r4 = ~r4; \
	r1 ^= r0; \
	r0 ^= r2; \
	r2 &= r4; \
	r2 ^= r0; \
	r0 |= r4; \
	r0 ^= r3; \
	r3 &= r2; \
	r4 ^= r3; \
	r3 ^= r1; \
	r1 &= r0; \
	r4 ^= r1; \
	r0 ^= r3; \
	r3 ^= r2; \
	r1 = r4; \
	r4 = r2; \
	r2 = r3; \
	r3 = r0;

#define I3(i, r0, r1, r2, r3, r4) \
	r2 ^= r1; \
	r4 = r1; \
	r1 &= r2; \
	r1 ^= r0; \
	r0 |= r4; \
	r4 ^= r3; \
	r0 ^= r3; \
	r3 |= r1; \
	r1 ^= r2; \
	r1 ^= r3; \
	r0 ^= r2; \
	r2 ^= r3; \
	r3 &= r1; \
	r1 ^= r0; \
	r0 &= r2; \
	r4 ^= r3; \
	r3 ^= r0; \
	r0 ^= r1;

#define I2(i, r0, r1, r2, r3, r4) \
	r2 ^= r3; \
	r3 ^= r0; \
	r4 = r3; \
	r3 &= r2; \
	r3 ^= r1; \
	r1 |= r2; \
	r1 ^= r4; \
	r4 &= r3; \
	r2 ^= r3; \
	r4 &= r0; \
	r4 ^= r2; \
	r2 &= r1; \
	r2 |= r0; \
	r3 = ~r3; \
	r2 ^= r3; \
	r0 ^= r3; \
	r0 &= r1; \
	r3 ^= r4; \
	r3 ^= r0;

#define I1(i, r0, r1, r2, r3, r4) \
	r4 = r1; \
	r1 ^= r0; \
	r0 ^= r3; \
	r3 = ~r3; \
	r4 &= r1; \
	r0 |= r1; \
	r3 ^= r2; \
	r0 ^= r3; \
	r1 ^= r3; \
	r3 ^= r4; \
	r1 |= r4; \
	r4 ^= r2; \
	r2 &= r0; \
	r2 ^= r1; \
	r1 |= r0; \
	r0 = ~r0; \
	r0 ^= r4; \
	r4 ^= r1;

#define I0(i, r0, r1, r2, r3, r4) \
	r4 = r2; \
	r2 ^= r0; \
	r0 &= r3; \
	r4 &= r3; \
	r0 ^= r1; \
	r1 |= r3; \
	r4 ^= r3; \
	r0 = ~r0; \
	r1 ^= r2; \
	r2 |= r0; \
	r1 ^= r4; \
	r4 &= r0; \
	r2 ^= r0; \
	r4 ^= r1; \
	r1 &= r2; \
	r1 ^= r0; \
	r0 ^= r2; \
	r3 = r4; \
	r4 = r2; \
	r2 = r0;

#define beforeI7(f) f(7,a,b,c,d,e)
#define afterI7(f) f(7,d,a,b,e,c)
#define afterI6(f) f(6,a,b,c,e,d)
#define afterI5(f) f(5,b,d,e,c,a)
#define afterI4(f) f(4,b,c,e,a,d)
#define afterI3(f) f(3,a,b,e,c,d)
#define afterI2(f) f(2,b,d,e,c,a)
#define afterI1(f) f(1,a,b,c,e,d)
#define afterI0(f) f(0,a,d,b,e,c)

#define KX(r, a, b, c, d) \
	a ^= k[4 * r + 0]; \
	b ^= k[4 * r + 1]; \
	c ^= k[4 * r + 2]; \
	d ^= k[4 * r + 3];

void serpent_decrypt(const byte *inBlock, byte *outBlock, byte *ks)
{
	uint32 a, b, c, d, e;
	const uint32 *k = (uint32 *)ks + 104;
	unsigned int i = 4;
	uint32 *in = (uint32 *) inBlock;
	uint32 *out = (uint32 *) outBlock;

    a = in[0];
	b = in[1];
	c = in[2];
	d = in[3];

	beforeI7(KX);
	goto start;

	do
	{
		c = b;
		b = d;
		d = e;
		k -= 32;
		beforeI7(ILT);
start:
		beforeI7(I7); afterI7(KX);
		afterI7(ILT); afterI7(I6); afterI6(KX);
		afterI6(ILT); afterI6(I5); afterI5(KX);
		afterI5(ILT); afterI5(I4); afterI4(KX);
		afterI4(ILT); afterI4(I3); afterI3(KX);
		afterI3(ILT); afterI3(I2); afterI2(KX);
		afterI2(ILT); afterI2(I1); afterI1(KX);
		afterI1(ILT); afterI1(I0); afterI0(KX);
	}
	while (--i != 0);

    out[0] = a;
	out[1] = d;
	out[2] = b;
	out[3] = e;
}

// Serpent key schedule (simplified - just using precomputed values)
extern void serpent_set_key(const byte *userKey, byte *ks);

int main() {
    // Test vector from NIST
    byte key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    byte ciphertext[16] = {
        0xde, 0x26, 0x9f, 0xf8,
        0x33, 0xe4, 0x32, 0xb8,
        0x5b, 0x2e, 0x88, 0xd2,
        0x70, 0x1c, 0xe7, 0x5c
    };
    
    byte ks[560];  // 140 * 4 bytes
    byte plaintext[16];
    
    serpent_set_key(key, ks);
    serpent_decrypt(ciphertext, plaintext, ks);
    
    printf("Decrypted: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");
    
    return 0;
}
