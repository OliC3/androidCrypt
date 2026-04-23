/**
 * Native XTS-AES implementation for Android – VeraCrypt-compatible.
 *
 * XTS encrypt/decrypt logic is ported directly from VeraCrypt's src/Common/Xts.c
 * (EncryptBufferXTSParallel / DecryptBufferXTSParallel for the hw-accelerated path,
 *  EncryptBufferXTSNonParallel / DecryptBufferXTSNonParallel for portable).
 *
 * AES block cipher: ARMv8 crypto extensions on arm64, T-table fallback elsewhere.
 *
 * JNI bridge: createContext, destroyContext, encryptSectors, decryptSectors,
 *             isAvailable, hasHardwareAES.
 */
#include <jni.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <android/log.h>

#ifdef __aarch64__
#include <arm_neon.h>
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#endif

#define LOG_TAG "NativeXTS"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG, __VA_ARGS__)

/* Compiler-resistant memory zeroing: the volatile function-pointer prevents
   the compiler from optimising away the wipe of sensitive data.            */
static void *(*const volatile secure_zero_ptr)(void*, int, size_t) = memset;
#define secure_zero(p, n)  secure_zero_ptr((p), 0, (n))

#include "Serpent.h"
#define SERPENT_KS_WORDS 140   // 140 x uint32 = 560-byte key schedule

#include "Twofish.h"
#include <new>        // std::nothrow

extern "C" {
#include "Aes.h"
}

/* -----------------------------------------------------------------------
   VeraCrypt-compatible constants (from src/Common/Crypto.h / Xts.h)
   ----------------------------------------------------------------------- */
#define ENCRYPTION_DATA_UNIT_SIZE  512
#define BYTES_PER_XTS_BLOCK        16
#define BLOCKS_PER_XTS_DATA_UNIT  (ENCRYPTION_DATA_UNIT_SIZE / BYTES_PER_XTS_BLOCK) /* 32 */

namespace {

// ============================================================================
// Section 5 – ARM64 hardware AES (ARMv8 crypto extensions)
// ============================================================================

#ifdef __aarch64__

static bool g_hw_aes_checked = false;
static bool g_hw_aes_available = false;

static bool detect_hw_aes() {
    if (!g_hw_aes_checked) {
        g_hw_aes_available = (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
        g_hw_aes_checked = true;
    }
    return g_hw_aes_available;
}

/* ARMv8 AES single-block encrypt. `rk` points at the raw bytes of a
   VeraCrypt aes_encrypt_ctx::ks (15 round keys, 16 bytes each, AES-256). */
__attribute__((target("+crypto")))
static void hw_aes_encrypt_block(const uint8_t* rk,
                                  const uint8_t in[16], uint8_t out[16]) {
    constexpr int Nr = 14;
    uint8x16_t block = vld1q_u8(in);
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        block = vaesmcq_u8(vaeseq_u8(block, key));
    }
    uint8x16_t key_last  = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t key_final = vld1q_u8(rk + Nr * 16);
    block = veorq_u8(vaeseq_u8(block, key_last), key_final);
    vst1q_u8(out, block);
}

/* ARMv8 AES single-block decrypt. `rk` points at the raw bytes of a
   VeraCrypt aes_decrypt_ctx::ks (already in equivalent-inverse-cipher
   form because Aesopt.h sets AES_REV_DKS). */
__attribute__((target("+crypto")))
static void hw_aes_decrypt_block(const uint8_t* rk,
                                  const uint8_t in[16], uint8_t out[16]) {
    constexpr int Nr = 14;
    uint8x16_t block = vld1q_u8(in);
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        block = vaesimcq_u8(vaesdq_u8(block, key));
    }
    uint8x16_t key_last  = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t key_final = vld1q_u8(rk + Nr * 16);
    block = veorq_u8(vaesdq_u8(block, key_last), key_final);
    vst1q_u8(out, block);
}

__attribute__((target("+crypto")))
static void hw_aes_encrypt_4blocks(const uint8_t* rk,
                                    uint8x16_t& b0, uint8x16_t& b1,
                                    uint8x16_t& b2, uint8x16_t& b3) {
    constexpr int Nr = 14;
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        b0 = vaesmcq_u8(vaeseq_u8(b0, key));
        b1 = vaesmcq_u8(vaeseq_u8(b1, key));
        b2 = vaesmcq_u8(vaeseq_u8(b2, key));
        b3 = vaesmcq_u8(vaeseq_u8(b3, key));
    }
    uint8x16_t kl = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t kf = vld1q_u8(rk + Nr * 16);
    b0 = veorq_u8(vaeseq_u8(b0, kl), kf);
    b1 = veorq_u8(vaeseq_u8(b1, kl), kf);
    b2 = veorq_u8(vaeseq_u8(b2, kl), kf);
    b3 = veorq_u8(vaeseq_u8(b3, kl), kf);
}

__attribute__((target("+crypto")))
static void hw_aes_decrypt_4blocks(const uint8_t* rk,
                                    uint8x16_t& b0, uint8x16_t& b1,
                                    uint8x16_t& b2, uint8x16_t& b3) {
    constexpr int Nr = 14;
    for (int r = 0; r < Nr - 1; r++) {
        uint8x16_t key = vld1q_u8(rk + r * 16);
        b0 = vaesimcq_u8(vaesdq_u8(b0, key));
        b1 = vaesimcq_u8(vaesdq_u8(b1, key));
        b2 = vaesimcq_u8(vaesdq_u8(b2, key));
        b3 = vaesimcq_u8(vaesdq_u8(b3, key));
    }
    uint8x16_t kl = vld1q_u8(rk + (Nr - 1) * 16);
    uint8x16_t kf = vld1q_u8(rk + Nr * 16);
    b0 = veorq_u8(vaesdq_u8(b0, kl), kf);
    b1 = veorq_u8(vaesdq_u8(b1, kl), kf);
    b2 = veorq_u8(vaesdq_u8(b2, kl), kf);
    b3 = veorq_u8(vaesdq_u8(b3, kl), kf);
}

#else // !__aarch64__

static bool detect_hw_aes() { return false; }

#endif // __aarch64__

// ============================================================================
// Section 6 – XTS context
// ============================================================================

/* XTS AES context.
   Uses VeraCrypt's upstream Brian Gladman AES key schedules unchanged
   (Aes.h, Aescrypt.c, Aeskey.c, Aestab.c). The decrypt schedule is in
   "equivalent inverse cipher" / reversed form because Aesopt.h defines
   AES_REV_DKS — the same form expected by both the upstream
   Aes_hw_armv8.c routines and our local NEON inline 4-block helpers. */
struct XTSContext {
    aes_encrypt_ctx data_enc;   // key1 – encrypt data
    aes_decrypt_ctx data_dec;   // key1 – decrypt data
    aes_encrypt_ctx tweak_enc;  // key2 – encrypt tweaks (always AES-encrypt)
    bool hw_aes;
};

/* Adapter: portable AES encrypt/decrypt using upstream API.
   Always AES-256 here (32-byte keys, validated at JNI boundary). */
static inline void aes_encrypt_block(const aes_encrypt_ctx* cx,
                                      const uint8_t in[16], uint8_t out[16]) {
    aes_encrypt(in, out, cx);
}
static inline void aes_decrypt_block(const aes_decrypt_ctx* cx,
                                      const uint8_t in[16], uint8_t out[16]) {
    aes_decrypt(in, out, cx);
}

// ============================================================================
// Section 7 – XTS encrypt / decrypt (VeraCrypt-compatible)
//
// Ported from VeraCrypt src/Common/Xts.c:
//   - Portable: EncryptBufferXTSNonParallel / DecryptBufferXTSNonParallel
//   - Hardware: EncryptBufferXTSParallel / DecryptBufferXTSParallel
//
// Parameters match VeraCrypt EncryptBufferXTS / DecryptBufferXTS:
//   buffer            – data to encrypt/decrypt in-place
//   length            – number of bytes; must be divisible by BYTES_PER_XTS_BLOCK
//   startDataUnitNo   – sequential number of the first data unit in the buffer
// ============================================================================

/* --------------- Portable (T-table) XTS encrypt --------------- */
/* Direct port of VeraCrypt EncryptBufferXTSNonParallel           */

static void EncryptBufferXTS_Portable(XTSContext* ctx, uint8_t* buffer,
                                       uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        aes_encrypt_block(&ctx->tweak_enc, whiteningValue, whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual encryption
                aes_encrypt_block(&ctx->data_enc,
                                  (uint8_t*)bufPtr, (uint8_t*)bufPtr);

                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
}

/* --------------- Portable (T-table) XTS decrypt --------------- */
/* Direct port of VeraCrypt DecryptBufferXTSNonParallel           */

static void DecryptBufferXTS_Portable(XTSContext* ctx, uint8_t* buffer,
                                       uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        aes_encrypt_block(&ctx->tweak_enc, whiteningValue, whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual decryption
                aes_decrypt_block(&ctx->data_dec,
                                  (uint8_t*)bufPtr, (uint8_t*)bufPtr);

                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
}

/* --------------- ARM64 hw-accelerated XTS encrypt --------------- */
/* Modelled on VeraCrypt EncryptBufferXTSParallel:                   */
/*   pre-compute whitening values, batch XOR, batch cipher, batch XOR */

#ifdef __aarch64__

__attribute__((target("+crypto")))
static void EncryptBufferXTS_HW(XTSContext* ctx, uint8_t* buffer,
                                 uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValues[ENCRYPTION_DATA_UNIT_SIZE];
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuesPtr64 = (uint64_t*)whiteningValues;
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    uint64_t* dataUnitBufPtr;
    unsigned int startBlock = 0, endBlock, block, countBlock;
    uint64_t remainingBlocks, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    remainingBlocks = length / BYTES_PER_XTS_BLOCK;

    while (remainingBlocks > 0) {
        if (remainingBlocks < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)remainingBlocks;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;
        countBlock = endBlock - startBlock;

        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        hw_aes_encrypt_block((const uint8_t*)ctx->tweak_enc.ks, whiteningValue, whiteningValue);

        // Generate all whitening values for this data unit
        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *whiteningValuesPtr64++ = *whiteningValuePtr64++;
                *whiteningValuesPtr64++ = *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        dataUnitBufPtr = bufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;

        // Pre-whitening XOR
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        // Actual encryption – 4 blocks at a time
        {
            uint8_t* p = (uint8_t*)dataUnitBufPtr;
            unsigned int cb = countBlock;
            while (cb >= 4) {
                uint8x16_t b0 = vld1q_u8(p);
                uint8x16_t b1 = vld1q_u8(p + 16);
                uint8x16_t b2 = vld1q_u8(p + 32);
                uint8x16_t b3 = vld1q_u8(p + 48);
                hw_aes_encrypt_4blocks((const uint8_t*)ctx->data_enc.ks, b0, b1, b2, b3);
                vst1q_u8(p,      b0);
                vst1q_u8(p + 16, b1);
                vst1q_u8(p + 32, b2);
                vst1q_u8(p + 48, b3);
                p += 64; cb -= 4;
            }
            for (; cb > 0; cb--) {
                hw_aes_encrypt_block((const uint8_t*)ctx->data_enc.ks, p, p);
                p += 16;
            }
        }

        // Post-whitening XOR
        bufPtr = dataUnitBufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        remainingBlocks -= countBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
    secure_zero(whiteningValues, sizeof(whiteningValues));
}

/* --------------- ARM64 hw-accelerated XTS decrypt --------------- */
/* Modelled on VeraCrypt DecryptBufferXTSParallel                    */

__attribute__((target("+crypto")))
static void DecryptBufferXTS_HW(XTSContext* ctx, uint8_t* buffer,
                                 uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValues[ENCRYPTION_DATA_UNIT_SIZE];
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuesPtr64 = (uint64_t*)whiteningValues;
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    uint64_t* dataUnitBufPtr;
    unsigned int startBlock = 0, endBlock, block, countBlock;
    uint64_t remainingBlocks, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    remainingBlocks = length / BYTES_PER_XTS_BLOCK;

    while (remainingBlocks > 0) {
        if (remainingBlocks < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)remainingBlocks;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;
        countBlock = endBlock - startBlock;

        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        hw_aes_encrypt_block((const uint8_t*)ctx->tweak_enc.ks, whiteningValue, whiteningValue);

        // Generate all whitening values for this data unit
        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *whiteningValuesPtr64++ = *whiteningValuePtr64++;
                *whiteningValuesPtr64++ = *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        dataUnitBufPtr = bufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;

        // Pre-whitening XOR
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        // Actual decryption – 4 blocks at a time
        {
            uint8_t* p = (uint8_t*)dataUnitBufPtr;
            unsigned int cb = countBlock;
            while (cb >= 4) {
                uint8x16_t b0 = vld1q_u8(p);
                uint8x16_t b1 = vld1q_u8(p + 16);
                uint8x16_t b2 = vld1q_u8(p + 32);
                uint8x16_t b3 = vld1q_u8(p + 48);
                hw_aes_decrypt_4blocks((const uint8_t*)ctx->data_dec.ks, b0, b1, b2, b3);
                vst1q_u8(p,      b0);
                vst1q_u8(p + 16, b1);
                vst1q_u8(p + 32, b2);
                vst1q_u8(p + 48, b3);
                p += 64; cb -= 4;
            }
            for (; cb > 0; cb--) {
                hw_aes_decrypt_block((const uint8_t*)ctx->data_dec.ks, p, p);
                p += 16;
            }
        }

        // Post-whitening XOR
        bufPtr = dataUnitBufPtr;
        whiteningValuesPtr64 = (uint64_t*)whiteningValues;
        for (block = 0; block < countBlock; block++) {
            *bufPtr++ ^= *whiteningValuesPtr64++;
            *bufPtr++ ^= *whiteningValuesPtr64++;
        }

        remainingBlocks -= countBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
    secure_zero(whiteningValues, sizeof(whiteningValues));
}

#endif // __aarch64__

// ============================================================================
// Section 8 – Dispatchers
// ============================================================================

static void EncryptBufferXTS(XTSContext* ctx, uint8_t* buf,
                              uint64_t len, uint64_t startDataUnitNo) {
#ifdef __aarch64__
    if (ctx->hw_aes) {
        EncryptBufferXTS_HW(ctx, buf, len, startDataUnitNo);
        return;
    }
#endif
    EncryptBufferXTS_Portable(ctx, buf, len, startDataUnitNo);
}

static void DecryptBufferXTS(XTSContext* ctx, uint8_t* buf,
                              uint64_t len, uint64_t startDataUnitNo) {
#ifdef __aarch64__
    if (ctx->hw_aes) {
        DecryptBufferXTS_HW(ctx, buf, len, startDataUnitNo);
        return;
    }
#endif
    DecryptBufferXTS_Portable(ctx, buf, len, startDataUnitNo);
}

} // anonymous namespace

// ============================================================================
// Section 9 – JNI bridge
// ============================================================================

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_androidcrypt_crypto_NativeXTS_nativeIsAvailable(JNIEnv*, jclass) {
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_androidcrypt_crypto_NativeXTS_hasHardwareAES(JNIEnv*, jclass) {
    return detect_hw_aes() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    /* VeraCrypt only uses AES-256; the upstream Aes.h vendored here
       is built with AES_256 only (aes_encrypt_key128 is not compiled in). */
    if (key1Len != 32 || key2Len != 32) {
        LOGE("AES-XTS requires 32-byte keys (key1=%d key2=%d)", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) XTSContext();
    if (!ctx) return 0;

    ctx->hw_aes = detect_hw_aes();

    uint8_t k1[32], k2[32];
    env->GetByteArrayRegion(key1, 0, key1Len, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, key2Len, reinterpret_cast<jbyte*>(k2));

    aes_encrypt_key256(k1, &ctx->data_enc);
    aes_decrypt_key256(k1, &ctx->data_dec);
    aes_encrypt_key256(k2, &ctx->tweak_enc);

    secure_zero(k1, sizeof(k1));
    secure_zero(k2, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeXTS_destroyContext(JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<XTSContext*>(handle);
    if (ctx) {
        secure_zero(ctx, sizeof(XTSContext));
        delete ctx;
    }
}

/**
 * Decrypt sectors in-place.
 *
 * Maps to VeraCrypt DecryptSectorsCurrentThread:
 *   DecryptBuffer(data, sectorCount * sectorSize,
 *                 sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE)
 */
JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<XTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

/**
 * Encrypt sectors in-place.
 *
 * Maps to VeraCrypt EncryptSectorsCurrentThread:
 *   EncryptBuffer(data, sectorCount * sectorSize,
 *                 sectorIndex * sectorSize / ENCRYPTION_DATA_UNIT_SIZE)
 */
JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<XTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 10 – Serpent XTS-mode  (mirrors the AES XTS sections above)
//
// Serpent is a 128-bit block cipher, same block size as AES, so the XTS
// mode logic is identical — only the block encrypt/decrypt calls change.
// The tweak key is always *encrypted* (never decrypted), matching VeraCrypt.
// ============================================================================

struct SerpentXTSContext {
    uint8_t data_ks[SERPENT_KS_WORDS * 4];   // key1 – encrypt / decrypt data
    uint8_t tweak_ks[SERPENT_KS_WORDS * 4];  // key2 – encrypt tweaks
};

/* --------------- Portable XTS-Serpent encrypt --------------- */
/* Direct mirror of EncryptBufferXTS_Portable with Serpent      */

static void EncryptBufferXTS_Serpent(SerpentXTSContext* ctx, uint8_t* buffer,
                                     uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary (tweak) key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        serpent_encrypt(whiteningValue, whiteningValue, ctx->tweak_ks);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual encryption
                serpent_encrypt((uint8_t*)bufPtr, (uint8_t*)bufPtr, ctx->data_ks);

                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
}

/* --------------- Portable XTS-Serpent decrypt --------------- */
/* Direct mirror of DecryptBufferXTS_Portable with Serpent      */

static void DecryptBufferXTS_Serpent(SerpentXTSContext* ctx, uint8_t* buffer,
                                     uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        // Encrypt the data unit number using the secondary (tweak) key
        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        serpent_encrypt(whiteningValue, whiteningValue, ctx->tweak_ks);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                // Post-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                // Actual decryption
                serpent_decrypt((uint8_t*)bufPtr, (uint8_t*)bufPtr, ctx->data_ks);

                // Pre-whitening
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            // Derive the next whitening value (GF(2^128) multiply by x)
            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
}

// ============================================================================
// Section 11 – Serpent block-cipher JNI  (single-block encrypt/decrypt)
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeSetKey(
        JNIEnv* env, jclass, jbyteArray key) {
    if (env->GetArrayLength(key) != 32) return 0;
    auto* ks = new(std::nothrow) uint8_t[SERPENT_KS_WORDS * 4];
    if (!ks) return 0;
    uint8_t k[32];
    env->GetByteArrayRegion(key, 0, 32, reinterpret_cast<jbyte*>(k));
    serpent_set_key(k, ks);
    secure_zero(k, sizeof(k));
    return reinterpret_cast<jlong>(ks);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeDestroyKey(
        JNIEnv*, jclass, jlong handle) {
    auto* ks = reinterpret_cast<uint8_t*>(handle);
    if (ks) {
        secure_zero(ks, SERPENT_KS_WORDS * 4);
        delete[] ks;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeEncryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* ks = reinterpret_cast<uint8_t*>(handle);
    if (!ks) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    serpent_encrypt(in_buf, out_buf, ks);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_SerpentJNI_nativeDecryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* ks = reinterpret_cast<uint8_t*>(handle);
    if (!ks) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    serpent_decrypt(in_buf, out_buf, ks);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

// ============================================================================
// Section 12 – Serpent XTS JNI bridge (NativeSerpentXTS)
//
// Same interface as NativeXTS: createContext, destroyContext,
// encryptSectors, decryptSectors.  The Kotlin class is NativeSerpentXTS.
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 32 || key2Len != 32) {
        LOGE("SerpentXTS: invalid key lengths: key1=%d, key2=%d", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) SerpentXTSContext();
    if (!ctx) return 0;

    uint8_t k1[32], k2[32];
    env->GetByteArrayRegion(key1, 0, 32, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 32, reinterpret_cast<jbyte*>(k2));

    serpent_set_key(k1, ctx->data_ks);
    serpent_set_key(k2, ctx->tweak_ks);

    secure_zero(k1, sizeof(k1));
    secure_zero(k2, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<SerpentXTSContext*>(handle);
    if (ctx) {
        secure_zero(ctx, sizeof(SerpentXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<SerpentXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_Serpent(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeSerpentXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<SerpentXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_Serpent(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 13 – Twofish XTS-mode  (mirrors the AES/Serpent XTS sections)
//
// Twofish is a 128-bit block cipher, same block size as AES and Serpent, so
// the XTS logic is identical — only the block encrypt/decrypt calls change.
// ============================================================================

struct TwofishXTSContext {
    TwofishInstance data_key;    // key1 – encrypt / decrypt data
    TwofishInstance tweak_key;   // key2 – encrypt tweaks
};

/* --------------- Portable XTS-Twofish encrypt --------------- */

static void EncryptBufferXTS_Twofish(TwofishXTSContext* ctx, uint8_t* buffer,
                                      uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        twofish_encrypt(&ctx->tweak_key, (u4byte*)whiteningValue, (u4byte*)whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                twofish_encrypt(&ctx->data_key, (u4byte*)bufPtr, (u4byte*)bufPtr);

                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
}

/* --------------- Portable XTS-Twofish decrypt --------------- */

static void DecryptBufferXTS_Twofish(TwofishXTSContext* ctx, uint8_t* buffer,
                                      uint64_t length, uint64_t startDataUnitNo) {
    uint8_t finalCarry;
    alignas(16) uint8_t whiteningValue[BYTES_PER_XTS_BLOCK];
    uint8_t byteBufUnitNo[BYTES_PER_XTS_BLOCK];
    uint64_t* whiteningValuePtr64 = (uint64_t*)whiteningValue;
    uint64_t* bufPtr = (uint64_t*)buffer;
    unsigned int startBlock = 0, endBlock, block;
    uint64_t blockCount, dataUnitNo;

    dataUnitNo = startDataUnitNo;
    *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    *((uint64_t*)byteBufUnitNo + 1) = 0;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    while (blockCount > 0) {
        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int)blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

        whiteningValuePtr64 = (uint64_t*)whiteningValue;

        *whiteningValuePtr64 = *((uint64_t*)byteBufUnitNo);
        *(whiteningValuePtr64 + 1) = 0;
        twofish_encrypt(&ctx->tweak_key, (u4byte*)whiteningValue, (u4byte*)whiteningValue);

        for (block = 0; block < endBlock; block++) {
            if (block >= startBlock) {
                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr-- ^= *whiteningValuePtr64--;

                twofish_decrypt(&ctx->data_key, (u4byte*)bufPtr, (u4byte*)bufPtr);

                *bufPtr++ ^= *whiteningValuePtr64++;
                *bufPtr++ ^= *whiteningValuePtr64;
            } else {
                whiteningValuePtr64++;
            }

            finalCarry =
                (*whiteningValuePtr64 & 0x8000000000000000ULL) ? 135 : 0;
            *whiteningValuePtr64-- <<= 1;
            if (*whiteningValuePtr64 & 0x8000000000000000ULL)
                *(whiteningValuePtr64 + 1) |= 1;
            *whiteningValuePtr64 <<= 1;
            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;
        dataUnitNo++;
        *((uint64_t*)byteBufUnitNo) = dataUnitNo;
    }

    secure_zero(whiteningValue, sizeof(whiteningValue));
}

// ============================================================================
// Section 14 – Twofish block-cipher JNI (single-block encrypt/decrypt)
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeSetKey(
        JNIEnv* env, jclass, jbyteArray key) {
    if (env->GetArrayLength(key) != 32) return 0;
    auto* inst = new(std::nothrow) TwofishInstance();
    if (!inst) return 0;
    uint8_t k[32];
    env->GetByteArrayRegion(key, 0, 32, reinterpret_cast<jbyte*>(k));
    twofish_set_key(inst, (const u4byte*)k);
    secure_zero(k, sizeof(k));
    return reinterpret_cast<jlong>(inst);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeDestroyKey(
        JNIEnv*, jclass, jlong handle) {
    auto* inst = reinterpret_cast<TwofishInstance*>(handle);
    if (inst) {
        secure_zero(inst, sizeof(TwofishInstance));
        delete inst;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeEncryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* inst = reinterpret_cast<TwofishInstance*>(handle);
    if (!inst) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    twofish_encrypt(inst, (const u4byte*)in_buf, (u4byte*)out_buf);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_TwofishJNI_nativeDecryptBlock(
        JNIEnv* env, jclass, jlong handle, jbyteArray inBlock, jbyteArray outBlock) {
    auto* inst = reinterpret_cast<TwofishInstance*>(handle);
    if (!inst) return;
    uint8_t in_buf[16], out_buf[16];
    env->GetByteArrayRegion(inBlock, 0, 16, reinterpret_cast<jbyte*>(in_buf));
    twofish_decrypt(inst, (const u4byte*)in_buf, (u4byte*)out_buf);
    env->SetByteArrayRegion(outBlock, 0, 16, reinterpret_cast<jbyte*>(out_buf));
}

// ============================================================================
// Section 15 – Twofish XTS JNI bridge (NativeTwofishXTS)
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 32 || key2Len != 32) {
        LOGE("TwofishXTS: invalid key lengths: key1=%d, key2=%d", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) TwofishXTSContext();
    if (!ctx) return 0;

    uint8_t k1[32], k2[32];
    env->GetByteArrayRegion(key1, 0, 32, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 32, reinterpret_cast<jbyte*>(k2));

    twofish_set_key(&ctx->data_key, (const u4byte*)k1);
    twofish_set_key(&ctx->tweak_key, (const u4byte*)k2);

    secure_zero(k1, sizeof(k1));
    secure_zero(k2, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<TwofishXTSContext*>(handle);
    if (ctx) {
        secure_zero(ctx, sizeof(TwofishXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<TwofishXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_Twofish(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeTwofishXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<TwofishXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_Twofish(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 16 – AES-Twofish-Serpent cascade XTS
//
// VeraCrypt cascade: each cipher runs a full independent XTS pass over the
// entire buffer with its own key pair.
//   Encrypt order: AES → Twofish → Serpent
//   Decrypt order: Serpent → Twofish → AES
//
// Key layout (192 bytes total):
//   Primary keys   [0–95]:   AES[0–31]  Twofish[32–63]  Serpent[64–95]
//   Secondary keys [96–191]: AES[96–127] Twofish[128–159] Serpent[160–191]
// ============================================================================

struct CascadeXTSContext {
    // AES keys (primary + tweak) using upstream Brian Gladman key schedule
    aes_encrypt_ctx  aes_data_enc;
    aes_decrypt_ctx  aes_data_dec;
    aes_encrypt_ctx  aes_tweak_enc;
    bool             hw_aes;
    // Twofish keys (primary + tweak)
    TwofishInstance  tf_data_key;
    TwofishInstance  tf_tweak_key;
    // Serpent keys (primary + tweak)
    uint8_t          sp_data_ks[SERPENT_KS_WORDS * 4];
    uint8_t          sp_tweak_ks[SERPENT_KS_WORDS * 4];
};

static void EncryptBufferXTS_Cascade(CascadeXTSContext* ctx, uint8_t* buf,
                                      uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: AES (innermost)
    {
        XTSContext aesCtx;
        aesCtx.data_enc  = ctx->aes_data_enc;
        aesCtx.data_dec  = ctx->aes_data_dec;
        aesCtx.tweak_enc = ctx->aes_tweak_enc;
        aesCtx.hw_aes    = ctx->hw_aes;
        EncryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        EncryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: Serpent (outermost)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        EncryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
}

static void DecryptBufferXTS_Cascade(CascadeXTSContext* ctx, uint8_t* buf,
                                      uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: Serpent (peel outermost layer first)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        DecryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        DecryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: AES (innermost)
    {
        XTSContext aesCtx;
        aesCtx.data_enc  = ctx->aes_data_enc;
        aesCtx.data_dec  = ctx->aes_data_dec;
        aesCtx.tweak_enc = ctx->aes_tweak_enc;
        aesCtx.hw_aes    = ctx->hw_aes;
        DecryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
}

// ============================================================================
// Section 17 – Cascade XTS JNI bridge (NativeCascadeXTS)
//
// Key inputs: key1 = 96-byte primary keys, key2 = 96-byte secondary keys
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 96 || key2Len != 96) {
        LOGE("CascadeXTS: invalid key lengths: key1=%d, key2=%d (expected 96)", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) CascadeXTSContext();
    if (!ctx) return 0;
    secure_zero(ctx, sizeof(CascadeXTSContext));

    ctx->hw_aes = detect_hw_aes();

    uint8_t k1[96], k2[96];
    env->GetByteArrayRegion(key1, 0, 96, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 96, reinterpret_cast<jbyte*>(k2));

    // Primary keys: AES[0–31], Twofish[32–63], Serpent[64–95]
    aes_encrypt_key256(k1, &ctx->aes_data_enc);
    aes_decrypt_key256(k1, &ctx->aes_data_dec);
    twofish_set_key(&ctx->tf_data_key, (const u4byte*)(k1 + 32));
    serpent_set_key(k1 + 64, ctx->sp_data_ks);

    // Secondary (tweak) keys: AES[0–31], Twofish[32–63], Serpent[64–95]
    aes_encrypt_key256(k2, &ctx->aes_tweak_enc);
    twofish_set_key(&ctx->tf_tweak_key, (const u4byte*)(k2 + 32));
    serpent_set_key(k2 + 64, ctx->sp_tweak_ks);

    secure_zero(k1, sizeof(k1));
    secure_zero(k2, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (ctx) {
        secure_zero(ctx, sizeof(CascadeXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_Cascade(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeXTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_Cascade(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

// ============================================================================
// Section 18 – Serpent-Twofish-AES cascade XTS (reversed order)
//
// Encrypt: Serpent → Twofish → AES  (three independent full-buffer XTS passes)
// Decrypt: AES → Twofish → Serpent  (reverse order)
//
// Key layout (192 bytes total):
//   Primary keys   [0–95]:   Serpent[0–31] Twofish[32–63] AES[64–95]
//   Secondary keys [96–191]: Serpent[0–31] Twofish[32–63] AES[64–95]
// Reuses CascadeXTSContext struct from Section 16.
// ============================================================================

static void EncryptBufferXTS_CascadeSTA(CascadeXTSContext* ctx, uint8_t* buf,
                                         uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: Serpent (innermost)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        EncryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        EncryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: AES (outermost)
    {
        XTSContext aesCtx;
        aesCtx.data_enc  = ctx->aes_data_enc;
        aesCtx.data_dec  = ctx->aes_data_dec;
        aesCtx.tweak_enc = ctx->aes_tweak_enc;
        aesCtx.hw_aes    = ctx->hw_aes;
        EncryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
}

static void DecryptBufferXTS_CascadeSTA(CascadeXTSContext* ctx, uint8_t* buf,
                                         uint64_t len, uint64_t startDataUnitNo) {
    // Pass 1: AES (peel outermost layer first)
    {
        XTSContext aesCtx;
        aesCtx.data_enc  = ctx->aes_data_enc;
        aesCtx.data_dec  = ctx->aes_data_dec;
        aesCtx.tweak_enc = ctx->aes_tweak_enc;
        aesCtx.hw_aes    = ctx->hw_aes;
        DecryptBufferXTS(&aesCtx, buf, len, startDataUnitNo);
    }
    // Pass 2: Twofish
    {
        TwofishXTSContext tfCtx;
        tfCtx.data_key  = ctx->tf_data_key;
        tfCtx.tweak_key = ctx->tf_tweak_key;
        DecryptBufferXTS_Twofish(&tfCtx, buf, len, startDataUnitNo);
    }
    // Pass 3: Serpent (innermost)
    {
        SerpentXTSContext spCtx;
        memcpy(spCtx.data_ks,  ctx->sp_data_ks,  sizeof(spCtx.data_ks));
        memcpy(spCtx.tweak_ks, ctx->sp_tweak_ks, sizeof(spCtx.tweak_ks));
        DecryptBufferXTS_Serpent(&spCtx, buf, len, startDataUnitNo);
    }
}

// ============================================================================
// Section 19 – Serpent-Twofish-AES cascade JNI bridge (NativeCascadeSTA_XTS)
//
// Key inputs: key1 = 96-byte primary keys, key2 = 96-byte secondary keys
//   Layout: Serpent[0–31] | Twofish[32–63] | AES[64–95]
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_createContext(
        JNIEnv* env, jclass, jbyteArray key1, jbyteArray key2) {

    jint key1Len = env->GetArrayLength(key1);
    jint key2Len = env->GetArrayLength(key2);

    if (key1Len != 96 || key2Len != 96) {
        LOGE("CascadeSTA_XTS: invalid key lengths: key1=%d, key2=%d (expected 96)", key1Len, key2Len);
        return 0;
    }

    auto* ctx = new(std::nothrow) CascadeXTSContext();
    if (!ctx) return 0;
    secure_zero(ctx, sizeof(CascadeXTSContext));

    ctx->hw_aes = detect_hw_aes();

    uint8_t k1[96], k2[96];
    env->GetByteArrayRegion(key1, 0, 96, reinterpret_cast<jbyte*>(k1));
    env->GetByteArrayRegion(key2, 0, 96, reinterpret_cast<jbyte*>(k2));

    // Primary keys: Serpent[0–31], Twofish[32–63], AES[64–95]
    serpent_set_key(k1,      ctx->sp_data_ks);
    twofish_set_key(&ctx->tf_data_key, (const u4byte*)(k1 + 32));
    aes_encrypt_key256(k1 + 64, &ctx->aes_data_enc);
    aes_decrypt_key256(k1 + 64, &ctx->aes_data_dec);

    // Secondary (tweak) keys: Serpent[0–31], Twofish[32–63], AES[64–95]
    serpent_set_key(k2,      ctx->sp_tweak_ks);
    twofish_set_key(&ctx->tf_tweak_key, (const u4byte*)(k2 + 32));
    aes_encrypt_key256(k2 + 64, &ctx->aes_tweak_enc);

    secure_zero(k1, sizeof(k1));
    secure_zero(k2, sizeof(k2));

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_destroyContext(
        JNIEnv*, jclass, jlong handle) {
    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (ctx) {
        secure_zero(ctx, sizeof(CascadeXTSContext));
        delete ctx;
    }
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_decryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    DecryptBufferXTS_CascadeSTA(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

JNIEXPORT void JNICALL
Java_com_androidcrypt_crypto_NativeCascadeSTA_1XTS_encryptSectors(
        JNIEnv* env, jclass, jlong handle, jbyteArray data,
        jint startOffset, jlong startSectorNo, jint sectorSize, jint sectorCount) {

    auto* ctx = reinterpret_cast<CascadeXTSContext*>(handle);
    if (!ctx || sectorCount <= 0 || sectorSize < 16) return;

    const jint arrayLen = env->GetArrayLength(data);

    auto* ptr = static_cast<uint8_t*>(
        env->GetPrimitiveArrayCritical(data, nullptr));
    if (!ptr) return;

    const uint64_t totalLength = (uint64_t)sectorSize * sectorCount;
    if (startOffset < 0 || (uint64_t)startOffset + totalLength > (uint64_t)arrayLen) {
        env->ReleasePrimitiveArrayCritical(data, ptr, 0);
        return;
    }
    const uint64_t startDataUnitNo =
        (uint64_t)startSectorNo * sectorSize / ENCRYPTION_DATA_UNIT_SIZE;

    EncryptBufferXTS_CascadeSTA(ctx, ptr + startOffset, totalLength, startDataUnitNo);

    env->ReleasePrimitiveArrayCritical(data, ptr, 0);
}

} // extern "C"
