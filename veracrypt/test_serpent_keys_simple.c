#include <stdio.h>
#include <stdint.h>

#define rotl32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

int main() {
    uint32_t k[140];
    uint8_t key[32];
    
    // Initialize key: 00 01 02 ... 1f
    for (int i = 0; i < 32; i++) {
        key[i] = i;
    }
    
    // Load key into first 8 words (little-endian)
    for (int i = 0; i < 8; i++) {
        k[i] = key[i*4] | (key[i*4+1] << 8) | (key[i*4+2] << 16) | (key[i*4+3] << 24);
    }
    
    // Key schedule expansion
    uint32_t t = k[7];
    uint32_t phi = 0x9e3779b9;
    for (int i = 0; i < 132; i++) {
        t = rotl32(k[i] ^ k[i+3] ^ k[i+5] ^ t ^ phi ^ i, 11);
        k[i+8] = t;
    }
    
    // Print first 16 round keys (k[8] through k[23])
    printf("Round keys k[8] through k[23]:\n");
    for (int i = 8; i < 24; i++) {
        printf("k[%d] = 0x%08x\n", i, k[i]);
    }
    
    return 0;
}
