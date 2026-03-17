#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "src/Crypto/Twofish.c"

#define DEBUG_ROUND(r, x0, x1, x2, x3) \
    printf("After round %d: x0=0x%08X, x1=0x%08X, x2=0x%08X, x3=0x%08X\n", r, x0, x1, x2, x3)

int main() {
    TwofishInstance ctx;
    
    uint8_t key[32] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };
    
    uint8_t plaintext[16] = {
        0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
        0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
    };
    
    twofish_set_key(&ctx, (u4byte*)key);
    
    u4byte in_blk[4];
    in_blk[0] = plaintext[0] | (plaintext[1] << 8) | (plaintext[2] << 16) | (plaintext[3] << 24);
    in_blk[1] = plaintext[4] | (plaintext[5] << 8) | (plaintext[6] << 16) | (plaintext[7] << 24);
    in_blk[2] = plaintext[8] | (plaintext[9] << 8) | (plaintext[10] << 16) | (plaintext[11] << 24);
    in_blk[3] = plaintext[12] | (plaintext[13] << 8) | (plaintext[14] << 16) | (plaintext[15] << 24);
    
    u4byte* rk = ctx.l_key;
    
    u4byte x0 = in_blk[0] ^ rk[0];
    u4byte x1 = in_blk[1] ^ rk[1];
    u4byte x2 = in_blk[2] ^ rk[2];
    u4byte x3 = in_blk[3] ^ rk[3];
    
    printf("After whitening: x0=0x%08X, x1=0x%08X, x2=0x%08X, x3=0x%08X\n", x0, x1, x2, x3);
    
    for (int j = 0; j < 16; j += 2) {
        // Round j (ROUNDA)
        u4byte f0 = ctx.mk_tab[0][x0 & 0xFF] ^ ctx.mk_tab[1][(x0 >> 8) & 0xFF] ^ ctx.mk_tab[2][(x0 >> 16) & 0xFF] ^ ctx.mk_tab[3][(x0 >> 24) & 0xFF];
        u4byte f1 = ctx.mk_tab[0][(x1 >> 24) & 0xFF] ^ ctx.mk_tab[1][x1 & 0xFF] ^ ctx.mk_tab[2][(x1 >> 8) & 0xFF] ^ ctx.mk_tab[3][(x1 >> 16) & 0xFF];
        f0 += f1;
        f1 += f0 + rk[2 * j + 9];
        f0 += rk[2 * j + 8];
        x2 = rotr32(x2 ^ f0, 1);
        x3 = rotl32(x3, 1) ^ f1;
        
        // Round j+1 (ROUNDB)
        f0 = ctx.mk_tab[0][x2 & 0xFF] ^ ctx.mk_tab[1][(x2 >> 8) & 0xFF] ^ ctx.mk_tab[2][(x2 >> 16) & 0xFF] ^ ctx.mk_tab[3][(x2 >> 24) & 0xFF];
        f1 = ctx.mk_tab[0][(x3 >> 24) & 0xFF] ^ ctx.mk_tab[1][x3 & 0xFF] ^ ctx.mk_tab[2][(x3 >> 8) & 0xFF] ^ ctx.mk_tab[3][(x3 >> 16) & 0xFF];
        f0 += f1;
        f1 += f0 + rk[2 * (j+1) + 9];
        f0 += rk[2 * (j+1) + 8];
        x0 = rotr32(x0 ^ f0, 1);
        x1 = rotl32(x1, 1) ^ f1;
        
        DEBUG_ROUND(j+1, x0, x1, x2, x3);
    }
    
    x2 ^= rk[4];
    x3 ^= rk[5];
    x0 ^= rk[6];
    x1 ^= rk[7];
    
    printf("After output whitening: x0=0x%08X, x1=0x%08X, x2=0x%08X, x3=0x%08X\n", x0, x1, x2, x3);
    printf("Output (x2, x3, x0, x1): %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X\n",
           x2 & 0xFF, (x2 >> 8) & 0xFF, (x2 >> 16) & 0xFF, (x2 >> 24) & 0xFF,
           x3 & 0xFF, (x3 >> 8) & 0xFF, (x3 >> 16) & 0xFF, (x3 >> 24) & 0xFF,
           x0 & 0xFF, (x0 >> 8) & 0xFF, (x0 >> 16) & 0xFF, (x0 >> 24) & 0xFF,
           x1 & 0xFF, (x1 >> 8) & 0xFF, (x1 >> 16) & 0xFF, (x1 >> 24) & 0xFF);
    
    return 0;
}
