#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "src/Crypto/Twofish.h"

#define rotr(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define rotl(x,n) (((x)<<(n))|((x)>>(32-(n))))

void twofish_encrypt_debug(TwofishInstance *instance, const u4byte in_blk[4], u4byte out_blk[])
{   
    u4byte  t0, t1, blk[4];
    u4byte *l_key = instance->l_key;
    u4byte (*mk_tab)[256] = instance->mk_tab;
    int i;

    blk[0] = in_blk[0] ^ l_key[0];
    blk[1] = in_blk[1] ^ l_key[1];
    blk[2] = in_blk[2] ^ l_key[2];
    blk[3] = in_blk[3] ^ l_key[3];
    
    printf("After input whitening:\n");
    printf("x0=0x%08x x1=0x%08x x2=0x%08x x3=0x%08x\n", blk[0], blk[1], blk[2], blk[3]);

#define g0_fun(x) (mk_tab[0][(x) & 0xff] ^ mk_tab[1][((x) >> 8) & 0xff] ^ mk_tab[2][((x) >> 16) & 0xff] ^ mk_tab[3][(x) >> 24])
#define g1_fun(x) (mk_tab[0][(x) >> 24] ^ mk_tab[1][(x) & 0xff] ^ mk_tab[2][((x) >> 8) & 0xff] ^ mk_tab[3][((x) >> 16) & 0xff])

    for (i = 0; i <= 7; ++i)
    {
        t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);
        blk[2] = rotr(blk[2] ^ (t0 + t1 + l_key[4 * (i) + 8]), 1);
        blk[3] = rotl(blk[3], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 9]);
        t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);
        blk[0] = rotr(blk[0] ^ (t0 + t1 + l_key[4 * (i) + 10]), 1);
        blk[1] = rotl(blk[1], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 11]);
        
        printf("After round %d: x0=0x%08X, x1=0x%08X, x2=0x%08X, x3=0x%08X\n",
               i * 2 + 1, blk[0], blk[1], blk[2], blk[3]);
    }

    out_blk[0] = blk[2] ^ l_key[4];
    out_blk[1] = blk[3] ^ l_key[5];
    out_blk[2] = blk[0] ^ l_key[6];
    out_blk[3] = blk[1] ^ l_key[7];
    
#undef g0_fun
#undef g1_fun
}

int main() {
    unsigned char encKey[32] = {
        0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45,
        0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35, 0x26,
        0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69,
        0x99, 0x59, 0x57, 0x49, 0x66, 0x96, 0x76, 0x27
    };
    
    unsigned char preXor[16] = {
        0x92, 0x82, 0xe7, 0xb2, 0x42, 0xe6, 0x14, 0x36,
        0xde, 0x0c, 0xa3, 0x81, 0x0f, 0xac, 0x53, 0x6a
    };
    
    TwofishInstance enc_ctx;
    twofish_set_key(&enc_ctx, (const u4byte*)encKey);
    
    unsigned char output[16];
    twofish_encrypt_debug(&enc_ctx, (const u4byte*)preXor, (u4byte*)output);
    
    printf("\nFinal output: ");
    for (int i = 0; i < 16; i++) printf("%02x", output[i]);
    printf("\n");
    
    return 0;
}
