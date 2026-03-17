#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "src/Crypto/Twofish.h"

#define rotr(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define rotl(x,n) (((x)<<(n))|((x)>>(32-(n))))

int main() {
    unsigned char encKey[32] = {
        0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45,
        0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35, 0x26,
        0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69,
        0x99, 0x59, 0x57, 0x49, 0x66, 0x96, 0x76, 0x27
    };
    
    TwofishInstance ctx;
    twofish_set_key(&ctx, (const u4byte*)encKey);
    
    // State after round 9 (i=4 complete)
    u4byte x0 = 0x9DC69BAB;
    u4byte x1 = 0xDB551F0D;
    u4byte x2 = 0xA480A0CB;
    u4byte x3 = 0x3CB5F900;
    
    u4byte *l_key = ctx.l_key;
    u4byte (*mk_tab)[256] = ctx.mk_tab;
    
#define g0_fun(x) (mk_tab[0][(x) & 0xff] ^ mk_tab[1][((x) >> 8) & 0xff] ^ mk_tab[2][((x) >> 16) & 0xff] ^ mk_tab[3][(x) >> 24])
#define g1_fun(x) (mk_tab[0][(x) >> 24] ^ mk_tab[1][(x) & 0xff] ^ mk_tab[2][((x) >> 8) & 0xff] ^ mk_tab[3][((x) >> 16) & 0xff])

    // i = 5 (rounds 10-11)
    int i = 5;
    
    // g functions for first half-round (round 10)
    u4byte t0 = g0_fun(x0);
    u4byte t1 = g1_fun(x1);
    
    printf("Round 10:\n");
    printf("  g0(x0=0x%08x) = t0 = 0x%08x\n", x0, t0);
    printf("  g1(x1=0x%08x) = t1 = 0x%08x\n", x1, t1);
    printf("  l_key[%d] = 0x%08x\n", 4*i+8, l_key[4*i+8]);
    printf("  l_key[%d] = 0x%08x\n", 4*i+9, l_key[4*i+9]);
    
    u4byte sum = t0 + t1;
    printf("  t0 + t1 = 0x%08x\n", sum);
    printf("  t0 + t1 + l_key[28] = 0x%08x\n", sum + l_key[28]);
    printf("  t0 + 2*t1 + l_key[29] = 0x%08x\n", t0 + 2*t1 + l_key[29]);
    
    u4byte new_x2_before_rot = x2 ^ (t0 + t1 + l_key[4*i+8]);
    printf("  x2 ^ (PHT result) = 0x%08x\n", new_x2_before_rot);
    x2 = rotr(new_x2_before_rot, 1);
    printf("  x2 after rotr = 0x%08x\n", x2);
    
    u4byte x3_rotated = rotl(x3, 1);
    printf("  x3 rotl = 0x%08x\n", x3_rotated);
    x3 = x3_rotated ^ (t0 + 2*t1 + l_key[4*i+9]);
    printf("  x3 after XOR = 0x%08x\n", x3);
    
    printf("\nAfter round 10: x0=0x%08X, x1=0x%08X, x2=0x%08X, x3=0x%08X\n", x0, x1, x2, x3);
    
    // g functions for second half-round (round 11)
    t0 = g0_fun(x2);
    t1 = g1_fun(x3);
    
    printf("\nRound 11:\n");
    printf("  g0(x2=0x%08x) = t0 = 0x%08x\n", x2, t0);
    printf("  g1(x3=0x%08x) = t1 = 0x%08x\n", x3, t1);
    printf("  l_key[%d] = 0x%08x\n", 4*i+10, l_key[4*i+10]);
    printf("  l_key[%d] = 0x%08x\n", 4*i+11, l_key[4*i+11]);
    
    sum = t0 + t1;
    printf("  t0 + t1 = 0x%08x\n", sum);
    printf("  t0 + t1 + l_key[30] = 0x%08x\n", sum + l_key[30]);
    printf("  t0 + 2*t1 + l_key[31] = 0x%08x\n", t0 + 2*t1 + l_key[31]);
    
    u4byte new_x0_before_rot = x0 ^ (t0 + t1 + l_key[4*i+10]);
    printf("  x0 ^ (PHT result) = 0x%08x\n", new_x0_before_rot);
    x0 = rotr(new_x0_before_rot, 1);
    printf("  x0 after rotr = 0x%08x\n", x0);
    
    u4byte x1_rotated = rotl(x1, 1);
    printf("  x1 rotl = 0x%08x\n", x1_rotated);
    x1 = x1_rotated ^ (t0 + 2*t1 + l_key[4*i+11]);
    printf("  x1 after XOR = 0x%08x\n", x1);
    
    printf("\nAfter round 11: x0=0x%08X, x1=0x%08X, x2=0x%08X, x3=0x%08X\n", x0, x1, x2, x3);
    
#undef g0_fun
#undef g1_fun
    
    return 0;
}
