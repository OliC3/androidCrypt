#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "src/Crypto/Twofish.h"

// Simple XTS encrypt of one block
void xts_twofish_encrypt_block(
    unsigned char *data,           // 16 bytes to encrypt in-place
    unsigned char *tweak_encrypted, // 16-byte encrypted tweak
    TwofishInstance *enc_ctx        // key schedule for data encryption
) {
    unsigned char temp[16];
    int i;
    
    // Pre-whitening: XOR with tweak
    for (i = 0; i < 16; i++) {
        temp[i] = data[i] ^ tweak_encrypted[i];
    }
    
    printf("After pre-XOR: ");
    for (i = 0; i < 16; i++) printf("%02x", temp[i]);
    printf("\n");
    
    // Encrypt
    twofish_encrypt(enc_ctx, (const u4byte*)temp, (u4byte*)temp);
    
    printf("After Twofish encrypt: ");
    for (i = 0; i < 16; i++) printf("%02x", temp[i]);
    printf("\n");
    
    // Post-whitening: XOR with tweak
    for (i = 0; i < 16; i++) {
        data[i] = temp[i] ^ tweak_encrypted[i];
    }
}

// GF(2^128) multiply by alpha
void multiply_by_alpha(unsigned char *tweak) {
    unsigned char carry = 0;
    unsigned char new_carry;
    int i;
    
    for (i = 0; i < 16; i++) {
        new_carry = (tweak[i] >> 7) & 1;
        tweak[i] = (tweak[i] << 1) | carry;
        carry = new_carry;
    }
    
    if (carry) {
        tweak[0] ^= 0x87;  // 135 = x^7 + x^2 + x + 1
    }
}

int main() {
    // IEEE 1619 key1 (encryption key)
    unsigned char encKey[32] = {
        0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45,
        0x23, 0x53, 0x60, 0x28, 0x74, 0x71, 0x35, 0x26,
        0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69,
        0x99, 0x59, 0x57, 0x49, 0x66, 0x96, 0x76, 0x27
    };
    
    // IEEE 1619 key2 (tweak key)
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
    
    // First 16 bytes of IEEE 1619 plaintext (0x00-0x0F)
    unsigned char plaintext[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    TwofishInstance enc_ctx, tweak_ctx;
    twofish_set_key(&enc_ctx, (const u4byte*)encKey);
    twofish_set_key(&tweak_ctx, (const u4byte*)tweakKey);
    
    // Print first 8 lkey values for enc
    printf("Enc l_key[0-7]: ");
    for (int i = 0; i < 8; i++) printf("%08x ", enc_ctx.l_key[i]);
    printf("\n");
    
    // Print mk_tab values
    printf("Enc mk_tab[0][0-3]: ");
    for (int i = 0; i < 4; i++) printf("%08x ", enc_ctx.mk_tab[0][i]);
    printf("\n");
    printf("Enc mk_tab[1][0-3]: ");
    for (int i = 0; i < 4; i++) printf("%08x ", enc_ctx.mk_tab[1][i]);
    printf("\n");
    printf("Enc mk_tab[2][0-3]: ");
    for (int i = 0; i < 4; i++) printf("%08x ", enc_ctx.mk_tab[2][i]);
    printf("\n");
    printf("Enc mk_tab[3][0-3]: ");
    for (int i = 0; i < 4; i++) printf("%08x ", enc_ctx.mk_tab[3][i]);
    printf("\n");
    
    // Print first 4 mk_tab[0] values
    printf("Enc mk_tab[0][0-3]: ");
    for (int i = 0; i < 4; i++) printf("%08x ", enc_ctx.mk_tab[0][i]);
    printf("\n");
    printf("Enc mk_tab[1][0-3]: ");
    for (int i = 0; i < 4; i++) printf("%08x ", enc_ctx.mk_tab[1][i]);
    printf("\n");
    
    // Manual trace - more detailed
    {
        unsigned char input[16] = {
            0x92, 0x82, 0xe7, 0xb2, 0x42, 0xe6, 0x14, 0x36,
            0xde, 0x0c, 0xa3, 0x81, 0x0f, 0xac, 0x53, 0x6a
        };  // After pre-XOR value
        
        u4byte x0 = ((u4byte)input[0]) | ((u4byte)input[1] << 8) | 
                    ((u4byte)input[2] << 16) | ((u4byte)input[3] << 24);
        u4byte x1 = ((u4byte)input[4]) | ((u4byte)input[5] << 8) | 
                    ((u4byte)input[6] << 16) | ((u4byte)input[7] << 24);
        u4byte x2 = ((u4byte)input[8]) | ((u4byte)input[9] << 8) | 
                    ((u4byte)input[10] << 16) | ((u4byte)input[11] << 24);
        u4byte x3 = ((u4byte)input[12]) | ((u4byte)input[13] << 8) | 
                    ((u4byte)input[14] << 16) | ((u4byte)input[15] << 24);
        
        printf("\nManual trace - Input as u4byte:\n");
        printf("x0=0x%08x x1=0x%08x x2=0x%08x x3=0x%08x\n", x0, x1, x2, x3);
        
        // Add input whitening
        x0 ^= enc_ctx.l_key[0];
        x1 ^= enc_ctx.l_key[1];
        x2 ^= enc_ctx.l_key[2];
        x3 ^= enc_ctx.l_key[3];
        
        printf("After input whitening:\n");
        printf("x0=0x%08x x1=0x%08x x2=0x%08x x3=0x%08x\n", x0, x1, x2, x3);
        
        // Round 0 - g0_fun(x0) and g1_fun(x1)
        // g0_fun: mk_tab[0][b0] ^ mk_tab[1][b1] ^ mk_tab[2][b2] ^ mk_tab[3][b3]
        u4byte f0 = enc_ctx.mk_tab[0][x0 & 0xFF] ^
                    enc_ctx.mk_tab[1][(x0 >> 8) & 0xFF] ^
                    enc_ctx.mk_tab[2][(x0 >> 16) & 0xFF] ^
                    enc_ctx.mk_tab[3][(x0 >> 24) & 0xFF];
        
        // g1_fun: mk_tab[0][b3] ^ mk_tab[1][b0] ^ mk_tab[2][b1] ^ mk_tab[3][b2]
        // Note: g1 rotates x1 left by 8 first
        u4byte rotx1 = (x1 << 8) | (x1 >> 24);
        u4byte f1 = enc_ctx.mk_tab[0][rotx1 & 0xFF] ^
                    enc_ctx.mk_tab[1][(rotx1 >> 8) & 0xFF] ^
                    enc_ctx.mk_tab[2][(rotx1 >> 16) & 0xFF] ^
                    enc_ctx.mk_tab[3][(rotx1 >> 24) & 0xFF];
        
        printf("Round 0 g functions:\n");
        printf("f0 = 0x%08X\n", f0);
        printf("f1 = 0x%08X\n", f1);
        
        u4byte sum = f0 + f1;
        u4byte pht_f0 = sum + enc_ctx.l_key[8];
        u4byte pht_f1 = sum + f1 + enc_ctx.l_key[9];
        printf("After PHT + key add:\n");
        printf("f0 = 0x%08X\n", pht_f0);
        printf("f1 = 0x%08X\n", pht_f1);
    }
    
    printf("Encryption key: ");
    for (int i = 0; i < 32; i++) printf("%02x", encKey[i]);
    printf("\n");
    
    printf("Tweak key:      ");
    for (int i = 0; i < 32; i++) printf("%02x", tweakKey[i]);
    printf("\n");
    
    printf("Initial tweak:  ");
    for (int i = 0; i < 16; i++) printf("%02x", tweak[i]);
    printf("\n");
    
    // Encrypt the tweak
    twofish_encrypt(&tweak_ctx, (const u4byte*)tweak, (u4byte*)tweak);
    
    printf("Encrypted tweak: ");
    for (int i = 0; i < 16; i++) printf("%02x", tweak[i]);
    printf("\n");
    
    printf("Plaintext:      ");
    for (int i = 0; i < 16; i++) printf("%02x", plaintext[i]);
    printf("\n");
    
    // XTS encrypt the first block
    unsigned char ciphertext[16];
    memcpy(ciphertext, plaintext, 16);
    xts_twofish_encrypt_block(ciphertext, tweak, &enc_ctx);
    
    printf("Ciphertext:     ");
    for (int i = 0; i < 16; i++) printf("%02x", ciphertext[i]);
    printf("\n");
    
    return 0;
}
