#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "src/Crypto/Twofish.c"

int main() {
    TwofishInstance ctx;
    
    uint8_t key[32] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };
    
    twofish_set_key(&ctx, (u4byte*)key);
    
    // Test x2 = 0xE05420AC
    u4byte x2 = 0xE05420AC;
    printf("x2 = 0x%08X\n", x2);
    printf("  byte0 = 0x%02X\n", x2 & 0xFF);
    printf("  byte1 = 0x%02X\n", (x2 >> 8) & 0xFF);
    printf("  byte2 = 0x%02X\n", (x2 >> 16) & 0xFF);
    printf("  byte3 = 0x%02X\n", (x2 >> 24) & 0xFF);
    
    printf("\nmkTab values:\n");
    printf("  mkTab[0][0x%02X] = 0x%08X\n", x2 & 0xFF, ctx.mk_tab[0][x2 & 0xFF]);
    printf("  mkTab[1][0x%02X] = 0x%08X\n", (x2 >> 8) & 0xFF, ctx.mk_tab[1][(x2 >> 8) & 0xFF]);
    printf("  mkTab[2][0x%02X] = 0x%08X\n", (x2 >> 16) & 0xFF, ctx.mk_tab[2][(x2 >> 16) & 0xFF]);
    printf("  mkTab[3][0x%02X] = 0x%08X\n", (x2 >> 24) & 0xFF, ctx.mk_tab[3][(x2 >> 24) & 0xFF]);
    
    u4byte g0 = ctx.mk_tab[0][x2 & 0xFF] ^ ctx.mk_tab[1][(x2 >> 8) & 0xFF] ^ ctx.mk_tab[2][(x2 >> 16) & 0xFF] ^ ctx.mk_tab[3][(x2 >> 24) & 0xFF];
    printf("\ng0 = 0x%08X\n", g0);
    
    return 0;
}
