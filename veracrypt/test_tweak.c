#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "src/Crypto/Aes.h"

int main() {
    // Key2 from test vector
    uint8_t key2[32] = {
        0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93,
        0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95,
        0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37,
        0x51, 0x05, 0x82, 0x09, 0x74, 0x94, 0x45, 0x92
    };
    
    // Initial tweak (data unit 0xff in little-endian)
    uint8_t tweak[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    // Encrypt tweak with AES-256
    uint8_t ks[AES_KS];
    aes_encrypt_key256(key2, ks);
    
    uint8_t encrypted_tweak[16];
    aes_encrypt(tweak, encrypted_tweak, ks);
    
    printf("Initial tweak: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", tweak[i]);
    }
    printf("\n");
    
    printf("Encrypted tweak: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", encrypted_tweak[i]);
    }
    printf("\n");
    
    return 0;
}
