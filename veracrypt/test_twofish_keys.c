#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Minimal Twofish key schedule test to get expected lKey values
typedef uint32_t u4byte;
typedef uint8_t u1byte;

#define extract_byte(x,n) ((u1byte)((x) >> (8 * (n))))

// Q tables (abbreviated - only showing first few)
static const u1byte Q[2][256] = {
    {0xa9, 0x67, 0xb3, 0xe8, /* ... */ },
    {0x75, 0xf3, 0xc6, 0xf4, /* ... */ }
};

void test_key_schedule() {
    // Test vector key
    u1byte key_bytes[] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46, 
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B, 
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };
    
    // Convert to 32-bit words (little-endian)
    u4byte key_words[8];
    for (int i = 0; i < 8; i++) {
        key_words[i] = key_bytes[i*4] | (key_bytes[i*4+1] << 8) | 
                       (key_bytes[i*4+2] << 16) | (key_bytes[i*4+3] << 24);
    }
    
    printf("Key words:\n");
    for (int i = 0; i < 8; i++) {
        printf("  key[%d] = 0x%08X\n", i, key_words[i]);
    }
    
    // Extract me_key and mo_key
    u4byte me_key[4], mo_key[4];
    for (int i = 0; i < 4; i++) {
        me_key[i] = key_words[i * 2];
        mo_key[i] = key_words[i * 2 + 1];
    }
    
    printf("\nme_key (even indices):\n");
    for (int i = 0; i < 4; i++) {
        printf("  me_key[%d] = 0x%08X\n", i, me_key[i]);
    }
    
    printf("\nmo_key (odd indices):\n");
    for (int i = 0; i < 4; i++) {
        printf("  mo_key[%d] = 0x%08X\n", i, mo_key[i]);
    }
}

int main() {
    test_key_schedule();
    return 0;
}
