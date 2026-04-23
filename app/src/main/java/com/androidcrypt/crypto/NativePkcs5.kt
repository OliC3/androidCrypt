package com.androidcrypt.crypto

/**
 * Bridge to native HMAC-PBKDF2 implementations for hash algorithms that
 * Android JCE does not provide:
 *   * Whirlpool
 *   * Blake2s
 *   * Streebog
 *
 * SHA-256 and SHA-512 stay on `javax.crypto.Mac.getInstance("HmacSHA*")` —
 * they are part of the standard provider set on every Android version we
 * support and the JCE path is well-trodden.
 *
 * The native side lives in `app/src/main/cpp/pbkdf2_native.cpp` and is
 * compiled into the same `libxts_aes_native.so` shared object as the rest
 * of the crypto primitives, so loading is implicit via [System.loadLibrary]
 * already performed by [XTSMode] / native cipher initialisation.
 */
internal object NativePkcs5 {

    // Algorithm IDs must match constants in pbkdf2_native.cpp
    private const val ALG_WHIRLPOOL = 1
    private const val ALG_BLAKE2S   = 2
    private const val ALG_STREEBOG  = 3

    init {
        // Same lib used by XTSMode; loadLibrary is idempotent.
        try {
            System.loadLibrary("xts_aes_native")
        } catch (_: UnsatisfiedLinkError) {
            // Tests / unusual environments load the lib through other paths
            // (e.g. NativeLibLoader for JVM unit tests).  Swallow here and
            // let the actual JNI call surface the error if it happens.
        }
    }

    /** Returns true if the given [HashAlgorithm] is implemented natively. */
    fun supports(hash: HashAlgorithm): Boolean = idFor(hash) != null

    private fun idFor(hash: HashAlgorithm): Int? = when (hash) {
        HashAlgorithm.WHIRLPOOL -> ALG_WHIRLPOOL
        HashAlgorithm.BLAKE2S   -> ALG_BLAKE2S
        HashAlgorithm.STREEBOG  -> ALG_STREEBOG
        else                    -> null
    }

    /**
     * Derive a key with PBKDF2-HMAC-[hash] entirely in native code.
     *
     * @throws IllegalArgumentException if [hash] is not a native-only
     *         algorithm; SHA-256/SHA-512 callers should keep using the JCE
     *         [javax.crypto.Mac] path.
     */
    fun deriveKey(
        hash: HashAlgorithm,
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        dkLen: Int,
    ): ByteArray {
        val id = idFor(hash)
            ?: throw IllegalArgumentException("Native PBKDF2 not implemented for $hash")
        require(iterations > 0) { "iterations must be positive" }
        require(dkLen in 1..4096) { "dkLen out of range" }
        return pbkdf2(id, password, salt, iterations, dkLen)
            ?: throw IllegalStateException("Native PBKDF2 failed for $hash")
    }

    @JvmStatic external fun pbkdf2(
        algorithm: Int,
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        dkLen: Int,
    ): ByteArray?

    @JvmStatic external fun isAvailable(algorithm: Int): Boolean
}
