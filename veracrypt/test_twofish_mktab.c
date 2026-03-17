#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "src/Crypto/Twofish.c"

int main() {
    TwofishInstance ctx;
    
    // Test vector key
    uint8_t key[32] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };
    
    twofish_set_key(&ctx, (u4byte*)key);
    
    printf("mkTab[0][0..3]:\n");
    for (int i = 0; i < 4; i++) {
        printf("mkTab[%d][%d] = 0x%08X\n", 0, i, ctx.mk_tab[0][i]);
    }
    
    printf("\nmkTab[1][0..3]:\n");
    for (int i = 0; i < 4; i++) {
        printf("mkTab[%d][%d] = 0x%08X\n", 1, i, ctx.mk_tab[1][i]);
    }
    
    printf("\nmkTab[2][0..3]:\n");
    for (int i = 0; i < 4; i++) {
        printf("mkTab[%d][%d] = 0x%08X\n", 2, i, ctx.mk_tab[2][i]);
    }
    
    printf("\nmkTab[3][0..3]:\n");
    for (int i = 0; i < 4; i++) {
        printf("mkTab[%d][%d] = 0x%08X\n", 3, i, ctx.mk_tab[3][i]);
    }
    
    return 0;
}
