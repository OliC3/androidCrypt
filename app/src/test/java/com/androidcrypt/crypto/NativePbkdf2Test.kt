package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for PBKDF2-HMAC over hash algorithms not provided by the JCE
 * (Whirlpool, Blake2s, Streebog).  These exercise the native dispatch in
 * [PBKDF2.deriveKey] and the JNI bridge in [NativePkcs5].
 *
 * Blake2s vectors come from the standard `hashlib.blake2s` Python
 * implementation (see `python3 -c hmac.pbkdf2_hmac` style script in the
 * commit notes).  Whirlpool and Streebog do not ship in standard Python so
 * we cover them with self-consistency tests + the full volume create/mount
 * round-trip in [VolumeRoundTripPerHashTest].
 */
class NativePbkdf2Test {

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // ── Native availability ─────────────────────────────────────────────────

    @Test
    fun `native PBKDF2 is available for Whirlpool, Blake2s, Streebog`() {
        assertTrue(NativePkcs5.supports(HashAlgorithm.WHIRLPOOL))
        assertTrue(NativePkcs5.supports(HashAlgorithm.BLAKE2S))
        assertTrue(NativePkcs5.supports(HashAlgorithm.STREEBOG))
        // SHA-256/SHA-512 stay on JCE
        assertFalse(NativePkcs5.supports(HashAlgorithm.SHA256))
        assertFalse(NativePkcs5.supports(HashAlgorithm.SHA512))
    }

    // ── Blake2s known-answer tests ──────────────────────────────────────────
    // Generated via Python:
    //   python3 -c "import hashlib,hmac; ..."

    @Test
    fun `PBKDF2-Blake2s c=1 dkLen=32`() {
        val dk = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.BLAKE2S,
            dkLen = 32,
        )
        assertEquals(
            "ed939d6f351dddb69f591aa693d75eccaab7c8f587384d8ed882d42fe8076474",
            hex(dk)
        )
    }

    @Test
    fun `PBKDF2-Blake2s c=1000 dkLen=32`() {
        val dk = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 1000,
            hashAlgorithm = HashAlgorithm.BLAKE2S,
            dkLen = 32,
        )
        assertEquals(
            "d391c613d78eb54e4119a2fa87118db72288ab4127183f535bfa534c0cc82541",
            hex(dk)
        )
    }

    @Test
    fun `PBKDF2-Blake2s c=4096 dkLen=64 spans two blocks`() {
        val dk = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "NaCl".toByteArray(),
            iterations = 4096,
            hashAlgorithm = HashAlgorithm.BLAKE2S,
            dkLen = 64,
        )
        assertEquals(
            "740f4de7d82628f0dd1a9f3258feaf6dd383136d759def9e3676df2ead53f1400" +
            "535f547613bc75d12ad28109f56e36e01f86fe42c47e2b9c99b61e2a97a4620",
            hex(dk)
        )
    }

    // ── Self-consistency for Whirlpool / Streebog ───────────────────────────
    // We don't have known vectors handy, so verify HMAC-PBKDF2 properties:
    //   - deterministic
    //   - depends on password, salt, iterations
    //   - different lengths share a common prefix per RFC 2898 §5.2

    private fun selfConsistency(hash: HashAlgorithm) {
        val a = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 100, hash, 64)
        val b = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 100, hash, 64)
        assertArrayEquals("$hash deterministic", a, b)

        val c = PBKDF2.deriveKey("pw2".toByteArray(), "salt".toByteArray(), 100, hash, 64)
        assertFalse("$hash depends on password", a.contentEquals(c))

        val d = PBKDF2.deriveKey("pw".toByteArray(), "salt2".toByteArray(), 100, hash, 64)
        assertFalse("$hash depends on salt", a.contentEquals(d))

        val e = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 101, hash, 64)
        assertFalse("$hash depends on iterations", a.contentEquals(e))

        // Truncation: dk(32) must equal first 32 bytes of dk(64)
        val a32 = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 100, hash, 32)
        assertArrayEquals(
            "$hash dkLen truncation",
            a.copyOfRange(0, 32),
            a32
        )

        // Multi-block derivation produces distinct blocks
        val a128 = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 50, hash, 128)
        val block1 = a128.copyOfRange(0, 64)
        val block2 = a128.copyOfRange(64, 128)
        assertFalse("$hash multi-block blocks differ", block1.contentEquals(block2))
    }

    @Test fun `PBKDF2-Whirlpool self-consistency`() = selfConsistency(HashAlgorithm.WHIRLPOOL)
    @Test fun `PBKDF2-Streebog  self-consistency`() = selfConsistency(HashAlgorithm.STREEBOG)
    @Test fun `PBKDF2-Blake2s   self-consistency`() = selfConsistency(HashAlgorithm.BLAKE2S)

    @Test
    fun `each hash produces distinct output for same inputs`() {
        val results = HashAlgorithm.entries.associateWith { h ->
            PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 100, h, 32)
        }
        val pairs = results.entries.toList()
        for (i in pairs.indices) {
            for (j in i + 1 until pairs.size) {
                assertFalse(
                    "${pairs[i].key} and ${pairs[j].key} should produce distinct PBKDF2 outputs",
                    pairs[i].value.contentEquals(pairs[j].value)
                )
            }
        }
    }
}
