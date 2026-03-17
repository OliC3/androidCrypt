#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char u1byte;
typedef uint32_t u4byte;
typedef unsigned char uint8;
typedef uint32_t uint32;

// Minimal includes
typedef struct {
    u4byte l_key[40];
    u4byte mk_tab[4][256];
} TwofishInstance;

#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define rotr32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

int main() {
    // Known values from our tests
    u4byte l_key[40] = {
        0xA354793D, 0x6E1A33F0, 0x6AB01A83, 0x7DF52A97,
        0x12FBC877, 0xD427152A, 0xCF9EB934, 0x69F6E699,
        // ... continue with rest (we only need first 8 + round keys)
    };
    
    // Fill in with actual computed values from real C test
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
    
    // Load plaintext as 32-bit words (little-endian)
    u4byte in_blk[4];
    in_blk[0] = plaintext[0] | (plaintext[1] << 8) | (plaintext[2] << 16) | (plaintext[3] << 24);
    in_blk[1] = plaintext[4] | (plaintext[5] << 8) | (plaintext[6] << 16) | (plaintext[7] << 24);
    in_blk[2] = plaintext[8] | (plaintext[9] << 8) | (plaintext[10] << 16) | (plaintext[11] << 24);
    in_blk[3] = plaintext[12] | (plaintext[13] << 8) | (plaintext[14] << 16) | (plaintext[15] << 24);
    
    printf("Input block words:\n");
    printf("in[0] = 0x%08X\n", in_blk[0]);
    printf("in[1] = 0x%08X\n", in_blk[1]);
    printf("in[2] = 0x%08X\n", in_blk[2]);
    printf("in[3] = 0x%08X\n", in_blk[3]);
    
    return 0;
}
