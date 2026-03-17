#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "src/Crypto/Twofish.h"

int main() {
    // IEEE 1619 key2 (tweak key) - same as in Kotlin test
    unsigned char tweakKey[32] = {
        0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93,
        0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95,
        0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37,
        0x51, 0x05, 0x82, 0x09, 0x74, 0x94, 0x45, 0x92
    };
    
    // Sector number 0xFFFFFFFFFF as 16-byte little-endian
    unsigned char tweak[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    TwofishInstance ctx;
    twofish_set_key(&ctx, (const u4byte*)tweakKey);
    
    printf("Input tweak:  ");
    for (int i = 0; i < 16; i++) printf("%02x", tweak[i]);
    printf("\n");
    
    printf("Tweak key:    ");
    for (int i = 0; i < 32; i++) printf("%02x", tweakKey[i]);
    printf("\n");
    
    unsigned char output[16];
    twofish_encrypt(&ctx, (const u4byte*)tweak, (u4byte*)output);
    
    printf("Output tweak: ");
    for (int i = 0; i < 16; i++) printf("%02x", output[i]);
    printf("\n");
    
    return 0;
}
