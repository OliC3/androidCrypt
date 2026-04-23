/*
 * Native HMAC-PBKDF2 for hash algorithms not available in Android JCE
 * (Whirlpool, Blake2s, Streebog).
 *
 * SHA-256 and SHA-512 stay on the JVM HmacSHA* path — we only call native
 * for the three VeraCrypt PRFs that Android does not ship.
 *
 * Implementation is a textbook PBKDF2 (RFC 2898 §5.2) on top of the
 * vendored upstream VeraCrypt hash primitives.
 */

#include <jni.h>
#include <cstdint>
#include <cstring>
#include <vector>

extern "C" {
#include "Crypto/Whirlpool.h"
#include "Crypto/Streebog.h"
#include "Crypto/blake2.h"
}

namespace {

// Algorithm IDs match com.androidcrypt.crypto.NativePkcs5 constants.
constexpr int ALG_WHIRLPOOL = 1;
constexpr int ALG_BLAKE2S   = 2;
constexpr int ALG_STREEBOG  = 3;

constexpr size_t MAX_BLOCK_SIZE = 64; // all three use 64-byte blocks
constexpr size_t MAX_DIGEST_SIZE = 64; // Whirlpool/Streebog = 64; Blake2s = 32

// ----- Hash adapters -------------------------------------------------------
struct HashSpec {
    size_t blockSize;
    size_t digestSize;
    void (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*finalize)(void *ctx, uint8_t *out);
    size_t ctxSize;
};

// Whirlpool ----------------------------------------------------------------
static void wp_init(void *c) { WHIRLPOOL_init(reinterpret_cast<WHIRLPOOL_CTX *>(c)); }
static void wp_update(void *c, const uint8_t *d, size_t n) {
    WHIRLPOOL_add(d, static_cast<unsigned int>(n), reinterpret_cast<WHIRLPOOL_CTX *>(c));
}
static void wp_final(void *c, uint8_t *o) {
    WHIRLPOOL_finalize(reinterpret_cast<WHIRLPOOL_CTX *>(c), o);
}

// Streebog -----------------------------------------------------------------
static void sb_init(void *c) { STREEBOG_init(reinterpret_cast<STREEBOG_CTX *>(c)); }
static void sb_update(void *c, const uint8_t *d, size_t n) {
    STREEBOG_add(reinterpret_cast<STREEBOG_CTX *>(c), d, n);
}
static void sb_final(void *c, uint8_t *o) {
    STREEBOG_finalize(reinterpret_cast<STREEBOG_CTX *>(c), o);
}

// Blake2s ------------------------------------------------------------------
static void b2_init(void *c) { blake2s_init(reinterpret_cast<blake2s_state *>(c)); }
static void b2_update(void *c, const uint8_t *d, size_t n) {
    blake2s_update(reinterpret_cast<blake2s_state *>(c), d, n);
}
static void b2_final(void *c, uint8_t *o) {
    blake2s_final(reinterpret_cast<blake2s_state *>(c), o);
}

const HashSpec *getSpec(int alg) {
    static const HashSpec WHIRLPOOL_SPEC = {64, 64, wp_init, wp_update, wp_final, sizeof(WHIRLPOOL_CTX)};
    static const HashSpec STREEBOG_SPEC  = {64, 64, sb_init, sb_update, sb_final, sizeof(STREEBOG_CTX)};
    static const HashSpec BLAKE2S_SPEC   = {64, 32, b2_init, b2_update, b2_final, sizeof(blake2s_state)};
    switch (alg) {
        case ALG_WHIRLPOOL: return &WHIRLPOOL_SPEC;
        case ALG_STREEBOG:  return &STREEBOG_SPEC;
        case ALG_BLAKE2S:   return &BLAKE2S_SPEC;
        default: return nullptr;
    }
}

// ----- HMAC ---------------------------------------------------------------
struct HmacCtx {
    const HashSpec *spec;
    std::vector<uint8_t> innerKey;   // K' xor ipad  (blockSize bytes)
    std::vector<uint8_t> outerKey;   // K' xor opad  (blockSize bytes)
    std::vector<uint8_t> hashCtx;    // working hash context (init each call)
};

void hmacInitKey(HmacCtx &h, const HashSpec *spec, const uint8_t *key, size_t keyLen) {
    h.spec = spec;
    h.innerKey.assign(spec->blockSize, 0x36);
    h.outerKey.assign(spec->blockSize, 0x5c);
    h.hashCtx.assign(spec->ctxSize, 0);

    std::vector<uint8_t> normalizedKey;
    const uint8_t *k = key;
    size_t kLen = keyLen;
    if (keyLen > spec->blockSize) {
        normalizedKey.assign(spec->digestSize, 0);
        spec->init(h.hashCtx.data());
        spec->update(h.hashCtx.data(), key, keyLen);
        spec->finalize(h.hashCtx.data(), normalizedKey.data());
        k = normalizedKey.data();
        kLen = spec->digestSize;
    }
    for (size_t i = 0; i < kLen; ++i) {
        h.innerKey[i] ^= k[i];
        h.outerKey[i] ^= k[i];
    }
    if (!normalizedKey.empty()) {
        std::memset(normalizedKey.data(), 0, normalizedKey.size());
    }
}

// Single HMAC over arbitrary data.  Output buffer must hold spec->digestSize.
void hmacOneShot(HmacCtx &h, const uint8_t *data1, size_t len1,
                 const uint8_t *data2, size_t len2, uint8_t *out) {
    // inner: H(innerKey || data1 || data2)
    std::vector<uint8_t> innerDigest(h.spec->digestSize);
    h.spec->init(h.hashCtx.data());
    h.spec->update(h.hashCtx.data(), h.innerKey.data(), h.innerKey.size());
    if (data1 && len1) h.spec->update(h.hashCtx.data(), data1, len1);
    if (data2 && len2) h.spec->update(h.hashCtx.data(), data2, len2);
    h.spec->finalize(h.hashCtx.data(), innerDigest.data());

    // outer: H(outerKey || innerDigest)
    h.spec->init(h.hashCtx.data());
    h.spec->update(h.hashCtx.data(), h.outerKey.data(), h.outerKey.size());
    h.spec->update(h.hashCtx.data(), innerDigest.data(), innerDigest.size());
    h.spec->finalize(h.hashCtx.data(), out);

    std::memset(innerDigest.data(), 0, innerDigest.size());
}

// PBKDF2 single-block: T_i = U_1 XOR U_2 XOR ... XOR U_iter
void pbkdf2Block(HmacCtx &h, const uint8_t *salt, size_t saltLen,
                 uint32_t blockIndex, uint32_t iterations, uint8_t *out) {
    const size_t hLen = h.spec->digestSize;
    uint8_t intBlk[4];
    intBlk[0] = static_cast<uint8_t>((blockIndex >> 24) & 0xFF);
    intBlk[1] = static_cast<uint8_t>((blockIndex >> 16) & 0xFF);
    intBlk[2] = static_cast<uint8_t>((blockIndex >> 8) & 0xFF);
    intBlk[3] = static_cast<uint8_t>(blockIndex & 0xFF);

    std::vector<uint8_t> u(hLen);
    // U_1 = HMAC(P, salt || INT(blockIndex))
    hmacOneShot(h, salt, saltLen, intBlk, 4, u.data());
    std::memcpy(out, u.data(), hLen);

    // U_j = HMAC(P, U_{j-1});  T_i ^= U_j
    for (uint32_t j = 2; j <= iterations; ++j) {
        std::vector<uint8_t> next(hLen);
        hmacOneShot(h, u.data(), hLen, nullptr, 0, next.data());
        for (size_t k = 0; k < hLen; ++k) {
            out[k] ^= next[k];
        }
        std::memcpy(u.data(), next.data(), hLen);
        std::memset(next.data(), 0, hLen);
    }
    std::memset(u.data(), 0, hLen);
}

} // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_androidcrypt_crypto_NativePkcs5_pbkdf2(
        JNIEnv *env, jclass /*clazz*/,
        jint algorithm,
        jbyteArray password,
        jbyteArray salt,
        jint iterations,
        jint dkLen) {

    const HashSpec *spec = getSpec(algorithm);
    if (!spec || iterations <= 0 || dkLen <= 0 || dkLen > 4096) {
        return nullptr;
    }

    jsize pwLen = env->GetArrayLength(password);
    jsize saltLen = env->GetArrayLength(salt);
    jbyte *pwData = env->GetByteArrayElements(password, nullptr);
    jbyte *saltData = env->GetByteArrayElements(salt, nullptr);
    if (!pwData || !saltData) {
        if (pwData)   env->ReleaseByteArrayElements(password, pwData, JNI_ABORT);
        if (saltData) env->ReleaseByteArrayElements(salt, saltData, JNI_ABORT);
        return nullptr;
    }

    HmacCtx hmac;
    hmacInitKey(hmac, spec, reinterpret_cast<const uint8_t *>(pwData),
                static_cast<size_t>(pwLen));

    const size_t hLen = spec->digestSize;
    const uint32_t blocks = static_cast<uint32_t>((dkLen + hLen - 1) / hLen);
    std::vector<uint8_t> derived(static_cast<size_t>(dkLen));
    std::vector<uint8_t> blockBuf(hLen);

    for (uint32_t i = 1; i <= blocks; ++i) {
        pbkdf2Block(hmac,
                    reinterpret_cast<const uint8_t *>(saltData),
                    static_cast<size_t>(saltLen),
                    i,
                    static_cast<uint32_t>(iterations),
                    blockBuf.data());
        const size_t offset = (i - 1) * hLen;
        const size_t toCopy = (offset + hLen <= static_cast<size_t>(dkLen))
                                  ? hLen
                                  : (static_cast<size_t>(dkLen) - offset);
        std::memcpy(derived.data() + offset, blockBuf.data(), toCopy);
    }

    // Wipe sensitive material before returning to JVM.
    std::memset(blockBuf.data(), 0, blockBuf.size());
    std::memset(hmac.innerKey.data(), 0, hmac.innerKey.size());
    std::memset(hmac.outerKey.data(), 0, hmac.outerKey.size());
    std::memset(hmac.hashCtx.data(), 0, hmac.hashCtx.size());

    // GetByteArrayElements may have returned a heap COPY of the password
    // bytes (typical on ART).  Releasing with JNI_ABORT frees that copy
    // without zeroing it, leaving the password in native heap until the
    // allocator overwrites it.  Wipe both buffers explicitly first.
    if (pwData)   std::memset(pwData,   0, static_cast<size_t>(pwLen));
    if (saltData) std::memset(saltData, 0, static_cast<size_t>(saltLen));

    env->ReleaseByteArrayElements(password, pwData, JNI_ABORT);
    env->ReleaseByteArrayElements(salt, saltData, JNI_ABORT);

    jbyteArray result = env->NewByteArray(dkLen);
    if (result) {
        env->SetByteArrayRegion(result, 0, dkLen,
                                reinterpret_cast<const jbyte *>(derived.data()));
    }
    std::memset(derived.data(), 0, derived.size());
    return result;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_androidcrypt_crypto_NativePkcs5_isAvailable(JNIEnv * /*env*/, jclass /*clazz*/, jint algorithm) {
    return getSpec(algorithm) != nullptr ? JNI_TRUE : JNI_FALSE;
}
