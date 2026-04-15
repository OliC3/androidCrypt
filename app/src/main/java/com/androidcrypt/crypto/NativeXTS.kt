package com.androidcrypt.crypto

/**
 * JNI wrapper for the native XTS-AES implementation.
 *
 * Uses ARMv8 crypto extensions (AESE/AESD) on supported ARM64 devices
 * for 3-10× faster XTS-AES encrypt/decrypt compared to JCE.
 * Falls back to an optimised portable C T-table implementation on x86/x86_64.
 *
 * Thread safety: the native context is read-only after creation (key schedules)
 * and all per-call state lives on the native stack, so [encryptSectors] /
 * [decryptSectors] can be called concurrently from multiple threads without
 * synchronisation.
 */
object NativeXTS {
    private var loaded = false

    init {
        try {
            System.loadLibrary("xts_aes_native")
            loaded = true
        } catch (e: UnsatisfiedLinkError) {
            // Native library not available - will use Java fallback
        }
    }

    /** True when the native library is loaded and functional. */
    fun isAvailable(): Boolean = loaded && nativeIsAvailable()

    // ---- JNI functions ----

    private external fun nativeIsAvailable(): Boolean

    /** True if the device has ARMv8 hardware AES (crypto extensions). */
    external fun hasHardwareAES(): Boolean

    /**
     * Create a native XTS context from the two AES keys.
     * @param key1 Data encryption key (16 or 32 bytes for AES-128/256)
     * @param key2 Tweak encryption key (same size as key1)
     * @return Opaque handle (non-zero on success, 0 on failure)
     */
    external fun createContext(key1: ByteArray, key2: ByteArray): Long

    /**
     * Destroy a previously created context and wipe key material.
     */
    external fun destroyContext(handle: Long)

    /**
     * Decrypt sectors in-place.
     * @param handle    Context handle from [createContext]
     * @param data      Byte array containing encrypted sector data
     * @param startOffset Byte offset into [data] where sector data begins
     * @param startSectorNo XTS data-unit (sector) number of the first sector
     * @param sectorSize Size of each sector in bytes (must be multiple of 16)
     * @param sectorCount Number of consecutive sectors to decrypt
     */
    external fun decryptSectors(
        handle: Long,
        data: ByteArray,
        startOffset: Int,
        startSectorNo: Long,
        sectorSize: Int,
        sectorCount: Int
    )

    /**
     * Encrypt sectors in-place.
     * @see [decryptSectors] for parameter descriptions
     */
    external fun encryptSectors(
        handle: Long,
        data: ByteArray,
        startOffset: Int,
        startSectorNo: Long,
        sectorSize: Int,
        sectorCount: Int
    )
}
