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
    
    // Test vector plaintext
    uint8_t plaintext[16] = {
        0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
        0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
    };
    
    uint8_t ciphertext[16];
    
    // Set key
    twofish_set_key(&ctx, (u4byte*)key);
    
    printf("C lKey values:\n");
    for (int i = 0; i < 8; i++) {
#if CRYPTOPP_BOOL_X64 && !defined(CRYPTOPP_DISABLE_ASM)
        if (i < 8) {
            printf("l_key[%d] = 0x%08X\n", i, (i < 2) ? ctx.w[i] : ctx.k[i-2]);
        }
#else
        printf("l_key[%d] = 0x%08X\n", i, ctx.l_key[i]);
#endif
    }
    
    // Encrypt
    memcpy(ciphertext, plaintext, 16);
    twofish_encrypt(&ctx, (u4byte*)plaintext, (u4byte*)ciphertext);
    
    printf("\nCiphertext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");
    
    printf("Expected:   6CB4561C40BF0A9705931CB6D408E7FA\n");
    
    return 0;
}
