#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char u1byte;
typedef uint32_t u4byte;
typedef unsigned char uint8;
typedef uint32_t uint32;

// Include the Q, MDSQ, and RS tables from Twofish.c
static const uint32 RS[8][256] = {
    #include "src/Crypto/Twofish_RS.c.inc"
};

// Q tables
static const uint8 Q[2][256] = {
    #include "src/Crypto/Twofish_Q.c.inc"  
};

// MDSQ tables
static const uint32 MDSQ[4][256] = {
    #include "src/Crypto/Twofish_MDSQ.c.inc"
};

#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

int main() {
    // Test key from the test vector
    uint8 key[32] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };
    
    // Compute S32 (sKey equivalent)
    union {
        uint8 S8[16];
        uint32 S32[4];
    } us;
    
    us.S32[0] = RS[0][key[0]] ^ RS[1][key[1]] ^ RS[2][key[2]] ^ RS[3][key[3]] 
              ^ RS[4][key[4]] ^ RS[5][key[5]] ^ RS[6][key[6]] ^ RS[7][key[7]];
    us.S32[1] = RS[0][key[8]] ^ RS[1][key[9]] ^ RS[2][key[10]] ^ RS[3][key[11]] 
              ^ RS[4][key[12]] ^ RS[5][key[13]] ^ RS[6][key[14]] ^ RS[7][key[15]];
    us.S32[2] = RS[0][key[16]] ^ RS[1][key[17]] ^ RS[2][key[18]] ^ RS[3][key[19]] 
              ^ RS[4][key[20]] ^ RS[5][key[21]] ^ RS[6][key[22]] ^ RS[7][key[23]];
    us.S32[3] = RS[0][key[24]] ^ RS[1][key[25]] ^ RS[2][key[26]] ^ RS[3][key[27]] 
              ^ RS[4][key[28]] ^ RS[5][key[29]] ^ RS[6][key[30]] ^ RS[7][key[31]];
              
    printf("sKey values:\n");
    printf("S32[0] = 0x%08X\n", us.S32[0]);
    printf("S32[1] = 0x%08X\n", us.S32[1]);
    printf("S32[2] = 0x%08X\n", us.S32[2]);
    printf("S32[3] = 0x%08X\n", us.S32[3]);
    
    printf("\nS8 bytes:\n");
    for (int j = 0; j < 16; j++) {
        printf("S8[%d] = 0x%02X\n", j, us.S8[j]);
    }
    
    // Compute first few round keys
    printf("\nFirst round keys:\n");
    for (int i = 0; i < 4; i += 2) {
        uint32 a = MDSQ[0][Q[0][Q[0][Q[1][Q[1][i] ^ key[24]] ^ key[16]] ^ key[8]] ^ key[0]] 
                 ^ MDSQ[1][Q[0][Q[1][Q[1][Q[0][i] ^ key[25]] ^ key[17]] ^ key[9]] ^ key[1]] 
                 ^ MDSQ[2][Q[1][Q[0][Q[0][Q[0][i] ^ key[26]] ^ key[18]] ^ key[10]] ^ key[2]] 
                 ^ MDSQ[3][Q[1][Q[1][Q[0][Q[1][i] ^ key[27]] ^ key[19]] ^ key[11]] ^ key[3]];
        uint32 b = rotl32(
                   MDSQ[0][Q[0][Q[0][Q[1][Q[1][i + 1] ^ key[28]] ^ key[20]] ^ key[12]] ^ key[4]] 
                 ^ MDSQ[1][Q[0][Q[1][Q[1][Q[0][i + 1] ^ key[29]] ^ key[21]] ^ key[13]] ^ key[5]]
                 ^ MDSQ[2][Q[1][Q[0][Q[0][Q[0][i + 1] ^ key[30]] ^ key[22]] ^ key[14]] ^ key[6]] 
                 ^ MDSQ[3][Q[1][Q[1][Q[0][Q[1][i + 1] ^ key[31]] ^ key[23]] ^ key[15]] ^ key[7]], 8);
        printf("i=%d: a_raw=0x%08X, b_raw (before rotl)=0x%08X\n", i, a, rotl32(b, 32-8));
        a += b;
        printf("      lKey[%d] = a = 0x%08X\n", i, a);
        printf("      lKey[%d] = rotl(a+b,9) = 0x%08X\n", i+1, rotl32(a+b, 9));
    }
    
    return 0;
}
