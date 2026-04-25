package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.AssumptionViolatedException
import org.junit.Test

/**
 * Round-trip tests for native XTS cipher wrappers.
 *
 * These verify that createContext → encryptSectors → decryptSectors returns
 * the original plaintext for each supported cipher.  They require the native
 * `xts_aes_native` library; if it is not available the tests are skipped.
 */
class NativeCipherRoundTripTest {

    private val nativeAvailable: Boolean = try {
        System.loadLibrary("xts_aes_native")
        true
    } catch (_: UnsatisfiedLinkError) {
        false
    }

    private fun assumeNative() {
        if (!nativeAvailable) {
            throw AssumptionViolatedException("Native library xts_aes_native not available")
        }
    }

    // ── NativeXTS (AES) ───────────────────────────────────────────────────────

    @Test
    fun `NativeXTS isAvailable reflects load state`() {
        // This test always passes — it just documents the current state
        assertEquals(nativeAvailable, NativeXTS.isAvailable())
    }

    @Test
    fun `NativeXTS encrypt-decrypt round-trip with AES-256`() {
        assumeNative()
        val key1 = ByteArray(32) { (it + 1).toByte() }
        val key2 = ByteArray(32) { (it + 2).toByte() }
        val plaintext = ByteArray(512) { (it * 3).toByte() }

        val handle = NativeXTS.createContext(key1, key2)
        assertTrue("context creation failed", handle != 0L)

        try {
            val ciphertext = plaintext.clone()
            NativeXTS.encryptSectors(handle, ciphertext, 0, 0L, 512, 1)
            assertFalse("ciphertext should differ", ciphertext.contentEquals(plaintext))

            val decrypted = ciphertext.clone()
            NativeXTS.decryptSectors(handle, decrypted, 0, 0L, 512, 1)
            assertArrayEquals(plaintext, decrypted)
        } finally {
            NativeXTS.destroyContext(handle)
        }
    }

    @Test
    fun `NativeXTS multi-sector round-trip`() {
        assumeNative()
        val key1 = ByteArray(32) { 0x55 }
        val key2 = ByteArray(32) { 0xAA.toByte() }
        val plaintext = ByteArray(512 * 4) { (it % 256).toByte() }

        val handle = NativeXTS.createContext(key1, key2)
        assertTrue(handle != 0L)

        try {
            val ciphertext = plaintext.clone()
            NativeXTS.encryptSectors(handle, ciphertext, 0, 100L, 512, 4)

            val decrypted = ciphertext.clone()
            NativeXTS.decryptSectors(handle, decrypted, 0, 100L, 512, 4)
            assertArrayEquals(plaintext, decrypted)
        } finally {
            NativeXTS.destroyContext(handle)
        }
    }

    @Test
    fun `NativeXTS different keys produce different ciphertexts`() {
        assumeNative()
        val plaintext = ByteArray(512) { 0x42 }

        val keyA1 = ByteArray(32) { 0x01 }
        val keyA2 = ByteArray(32) { 0x02 }
        val keyB1 = ByteArray(32) { 0x03 }
        val keyB2 = ByteArray(32) { 0x04 }

        val handleA = NativeXTS.createContext(keyA1, keyA2)
        val handleB = NativeXTS.createContext(keyB1, keyB2)
        assertTrue(handleA != 0L && handleB != 0L)

        try {
            val ctA = plaintext.clone()
            NativeXTS.encryptSectors(handleA, ctA, 0, 0L, 512, 1)

            val ctB = plaintext.clone()
            NativeXTS.encryptSectors(handleB, ctB, 0, 0L, 512, 1)

            assertFalse("different keys should produce different ciphertexts", ctA.contentEquals(ctB))
        } finally {
            NativeXTS.destroyContext(handleA)
            NativeXTS.destroyContext(handleB)
        }
    }

    // ── NativeSerpentXTS ────────────────────────────────────────────────────

    @Test
    fun `NativeSerpentXTS isAvailable reflects load state`() {
        assertEquals(nativeAvailable, NativeSerpentXTS.isAvailable())
    }

    @Test
    fun `NativeSerpentXTS encrypt-decrypt round-trip`() {
        assumeNative()
        val key1 = ByteArray(32) { (it + 5).toByte() }
        val key2 = ByteArray(32) { (it + 6).toByte() }
        val plaintext = ByteArray(512) { (it * 7).toByte() }

        val handle = NativeSerpentXTS.createContext(key1, key2)
        assertTrue("Serpent context creation failed", handle != 0L)

        try {
            val ciphertext = plaintext.clone()
            NativeSerpentXTS.encryptSectors(handle, ciphertext, 0, 0L, 512, 1)
            assertFalse("ciphertext should differ", ciphertext.contentEquals(plaintext))

            val decrypted = ciphertext.clone()
            NativeSerpentXTS.decryptSectors(handle, decrypted, 0, 0L, 512, 1)
            assertArrayEquals(plaintext, decrypted)
        } finally {
            NativeSerpentXTS.destroyContext(handle)
        }
    }

    // ── NativeTwofishXTS ────────────────────────────────────────────────────

    @Test
    fun `NativeTwofishXTS isAvailable reflects load state`() {
        assertEquals(nativeAvailable, NativeTwofishXTS.isAvailable())
    }

    @Test
    fun `NativeTwofishXTS encrypt-decrypt round-trip`() {
        assumeNative()
        val key1 = ByteArray(32) { (it + 9).toByte() }
        val key2 = ByteArray(32) { (it + 10).toByte() }
        val plaintext = ByteArray(512) { (it * 11).toByte() }

        val handle = NativeTwofishXTS.createContext(key1, key2)
        assertTrue("Twofish context creation failed", handle != 0L)

        try {
            val ciphertext = plaintext.clone()
            NativeTwofishXTS.encryptSectors(handle, ciphertext, 0, 0L, 512, 1)
            assertFalse("ciphertext should differ", ciphertext.contentEquals(plaintext))

            val decrypted = ciphertext.clone()
            NativeTwofishXTS.decryptSectors(handle, decrypted, 0, 0L, 512, 1)
            assertArrayEquals(plaintext, decrypted)
        } finally {
            NativeTwofishXTS.destroyContext(handle)
        }
    }

    // ── NativeCascadeXTS (AES-Twofish-Serpent) ──────────────────────────────

    @Test
    fun `NativeCascadeXTS isAvailable reflects load state`() {
        assertEquals(nativeAvailable, NativeCascadeXTS.isAvailable())
    }

    @Test
    fun `NativeCascadeXTS encrypt-decrypt round-trip`() {
        assumeNative()
        // 96-byte keys: AES[0-31] | Twofish[32-63] | Serpent[64-95]
        val key1 = ByteArray(96) { (it + 13).toByte() }
        val key2 = ByteArray(96) { (it + 14).toByte() }
        val plaintext = ByteArray(512) { (it * 15).toByte() }

        val handle = NativeCascadeXTS.createContext(key1, key2)
        assertTrue("Cascade context creation failed", handle != 0L)

        try {
            val ciphertext = plaintext.clone()
            NativeCascadeXTS.encryptSectors(handle, ciphertext, 0, 0L, 512, 1)
            assertFalse("ciphertext should differ", ciphertext.contentEquals(plaintext))

            val decrypted = ciphertext.clone()
            NativeCascadeXTS.decryptSectors(handle, decrypted, 0, 0L, 512, 1)
            assertArrayEquals(plaintext, decrypted)
        } finally {
            NativeCascadeXTS.destroyContext(handle)
        }
    }

    // ── NativeCascadeSTA_XTS (Serpent-Twofish-AES) ───────────────────────────

    @Test
    fun `NativeCascadeSTA_XTS isAvailable reflects load state`() {
        assertEquals(nativeAvailable, NativeCascadeSTA_XTS.isAvailable())
    }

    @Test
    fun `NativeCascadeSTA_XTS encrypt-decrypt round-trip`() {
        assumeNative()
        // 96-byte keys: Serpent[0-31] | Twofish[32-63] | AES[64-95]
        val key1 = ByteArray(96) { (it + 17).toByte() }
        val key2 = ByteArray(96) { (it + 18).toByte() }
        val plaintext = ByteArray(512) { (it * 19).toByte() }

        val handle = NativeCascadeSTA_XTS.createContext(key1, key2)
        assertTrue("STA context creation failed", handle != 0L)

        try {
            val ciphertext = plaintext.clone()
            NativeCascadeSTA_XTS.encryptSectors(handle, ciphertext, 0, 0L, 512, 1)
            assertFalse("ciphertext should differ", ciphertext.contentEquals(plaintext))

            val decrypted = ciphertext.clone()
            NativeCascadeSTA_XTS.decryptSectors(handle, decrypted, 0, 0L, 512, 1)
            assertArrayEquals(plaintext, decrypted)
        } finally {
            NativeCascadeSTA_XTS.destroyContext(handle)
        }
    }

    // ── Cross-cipher independence ───────────────────────────────────────────

    @Test
    fun `AES and Serpent with same key produce different ciphertexts`() {
        assumeNative()
        val key1 = ByteArray(32) { 0x42 }
        val key2 = ByteArray(32) { 0x43 }
        val plaintext = ByteArray(512) { 0x99.toByte() }

        val handleAes = NativeXTS.createContext(key1, key2)
        val handleSerpent = NativeSerpentXTS.createContext(key1, key2)
        assertTrue(handleAes != 0L && handleSerpent != 0L)

        try {
            val ctAes = plaintext.clone()
            NativeXTS.encryptSectors(handleAes, ctAes, 0, 0L, 512, 1)

            val ctSerpent = plaintext.clone()
            NativeSerpentXTS.encryptSectors(handleSerpent, ctSerpent, 0, 0L, 512, 1)

            assertFalse("AES and Serpent should differ", ctAes.contentEquals(ctSerpent))
        } finally {
            NativeXTS.destroyContext(handleAes)
            NativeSerpentXTS.destroyContext(handleSerpent)
        }
    }

    @Test
    fun `destroyContext is safe on invalid handle`() {
        assumeNative()
        // All destroyContext methods should be safe with handle=0
        NativeXTS.destroyContext(0L)
        NativeSerpentXTS.destroyContext(0L)
        NativeTwofishXTS.destroyContext(0L)
        NativeCascadeXTS.destroyContext(0L)
        NativeCascadeSTA_XTS.destroyContext(0L)
        assertTrue(true) // If we get here without crash, the test passes
    }
}
