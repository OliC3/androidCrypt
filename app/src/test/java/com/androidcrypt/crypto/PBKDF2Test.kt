package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Tests for PBKDF2 key derivation and HashAlgorithm iteration count logic.
 *
 * PBKDF2-HMAC-SHA256 vectors come from RFC 7914 §11 (scrypt test vectors) and
 * other well-known sources. PBKDF2-HMAC-SHA512 vectors are verified against
 * the Python hashlib reference implementation.
 */
class PBKDF2Test {

    // ── Helper ──────────────────────────────────────────────────────────────

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    // ── PBKDF2-HMAC-SHA256 (RFC 7914 §11) ──────────────────────────────────

    @Test
    fun `PBKDF2-SHA256 - RFC 7914 vector - passwd salt c=1 dkLen=32`() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256("passwd", "salt", 1, 32)
        val dk = PBKDF2.deriveKey(
            password = "passwd".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA256,
            dkLen = 32
        )
        // Expected from RFC 7914 and independent verification
        assertEquals(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
            hex(dk)
        )
    }

    @Test
    fun `PBKDF2-SHA256 - Password salt c=4096 dkLen=32`() {
        // From RFC 7914 §11: PBKDF2("Password", "NaCl", 80000, 64) is given,
        // but for a faster test we use a well-known c=4096 vector.
        // PBKDF2-HMAC-SHA256("Password", "NaCl", 4096, 32)
        val dk = PBKDF2.deriveKey(
            password = "Password".toByteArray(),
            salt = "NaCl".toByteArray(),
            iterations = 4096,
            hashAlgorithm = HashAlgorithm.SHA256,
            dkLen = 32
        )
        // Verified with Python: hashlib.pbkdf2_hmac('sha256', b'Password', b'NaCl', 4096, 32).hex()
        assertEquals(
            "438b6f1df76520b1c9989ddf976545b40f1ab4d9da723a81aa5083108b0da61f",
            hex(dk)
        )
    }

    // ── PBKDF2-HMAC-SHA512 ──────────────────────────────────────────────────

    @Test
    fun `PBKDF2-SHA512 - password salt c=1 dkLen=64`() {
        // PBKDF2-HMAC-SHA512("password", "salt", 1, 64)
        // Verified with Python: hashlib.pbkdf2_hmac('sha512', b'password', b'salt', 1, 64).hex()
        val dk = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 64
        )
        assertEquals(
            "867f70cf1ade02cff3752599a3a53dc4" +
            "af34c7a669815ae5d513554e1c8cf252" +
            "c02d470a285a0501bad999bfe943c08f" +
            "050235d7d68b1da55e63f73b60a57fce",
            hex(dk)
        )
    }

    @Test
    fun `PBKDF2-SHA512 - password salt c=2 dkLen=64`() {
        val dk = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 2,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 64
        )
        assertEquals(
            "e1d9c16aa681708a45f5c7c4e215ceb6" +
            "6e011a2e9f0040713f18aefdb866d53c" +
            "f76cab2868a39b9f7840edce4fef5a82" +
            "be67335c77a6068e04112754f27ccf4e",
            hex(dk)
        )
    }

    @Test
    fun `PBKDF2-SHA512 - password salt c=4096 dkLen=64`() {
        val dk = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 4096,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 64
        )
        assertEquals(
            "d197b1b33db0143e018b12f3d1d1479e" +
            "6cdebdcc97c5c0f87f6902e072f457b5" +
            "143f30602641b3d55cd335988cb36b84" +
            "376060ecd532e039b742a239434af2d5",
            hex(dk)
        )
    }

    @Test
    fun `PBKDF2-SHA512 - derived key truncated to 32 bytes`() {
        // Verify partial output (VeraCrypt uses 192-byte keys for cascades but
        // most single ciphers use 64 bytes — test that truncation is correct)
        val dk64 = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 64
        )
        val dk32 = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 32
        )
        // First 32 bytes must match
        assertArrayEquals(dk64.copyOfRange(0, 32), dk32)
    }

    @Test
    fun `PBKDF2-SHA512 - long derived key spans multiple HMAC blocks`() {
        // Request 128 bytes = 2 HMAC-SHA512 blocks — exercises multi-block derivation
        val dk = PBKDF2.deriveKey(
            password = "test".toByteArray(),
            salt = "saltsalt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 128
        )
        assertEquals(128, dk.size)
        // First 64 bytes = block 1, next 64 bytes = block 2 — they must differ
        val block1 = dk.copyOfRange(0, 64)
        val block2 = dk.copyOfRange(64, 128)
        assertFalse("Two PBKDF2 blocks should not be identical", block1.contentEquals(block2))
    }

    // ── HashAlgorithm.getIterationCount() ───────────────────────────────────

    @Test
    fun `SHA512 default iterations - non-system`() {
        assertEquals(500_000, HashAlgorithm.SHA512.getIterationCount(0))
    }

    @Test
    fun `SHA512 custom PIM iterations - non-system`() {
        // Formula: 15000 + (pim * 1000)
        assertEquals(15_000 + 10_000, HashAlgorithm.SHA512.getIterationCount(10))
        assertEquals(15_000 + 1_000, HashAlgorithm.SHA512.getIterationCount(1))
        assertEquals(15_000 + 485_000, HashAlgorithm.SHA512.getIterationCount(485))
    }

    @Test
    fun `SHA256 default iterations - non-system`() {
        assertEquals(500_000, HashAlgorithm.SHA256.getIterationCount(0))
    }

    @Test
    fun `SHA256 custom PIM iterations - non-system`() {
        assertEquals(15_000 + 10_000, HashAlgorithm.SHA256.getIterationCount(10))
    }

    @Test
    fun `SHA512 system encryption default iterations`() {
        assertEquals(200_000, HashAlgorithm.SHA512.getIterationCount(0, isSystemEncryption = true))
    }

    @Test
    fun `SHA512 system encryption custom PIM`() {
        // Formula: pim * 2048
        assertEquals(2048, HashAlgorithm.SHA512.getIterationCount(1, isSystemEncryption = true))
        assertEquals(20_480, HashAlgorithm.SHA512.getIterationCount(10, isSystemEncryption = true))
    }

    @Test
    fun `all hash algorithms have same iteration formula`() {
        // VeraCrypt uses the same formula for all hash algorithms
        for (hash in HashAlgorithm.entries) {
            assertEquals("${hash.name} default", 500_000, hash.getIterationCount(0))
            assertEquals("${hash.name} pim=5", 20_000, hash.getIterationCount(5))
            assertEquals("${hash.name} sys default", 200_000, hash.getIterationCount(0, isSystemEncryption = true))
            assertEquals("${hash.name} sys pim=10", 20_480, hash.getIterationCount(10, isSystemEncryption = true))
        }
    }

    // ── Edge cases ──────────────────────────────────────────────────────────

    @Test(expected = IllegalArgumentException::class)
    fun `empty password`() {
        // SecretKeySpec rejects empty key – verify the exception propagates
        PBKDF2.deriveKey(
            password = ByteArray(0),
            salt = "salt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 64
        )
    }

    @Test
    fun `empty salt`() {
        val result = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = ByteArray(0),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 64
        )
        assertEquals(64, result.size)
        assertTrue(result.any { it != 0.toByte() })
    }

    @Test
    fun `large dkLen spanning multiple HMAC blocks`() {
        // SHA-512 output is 64 bytes; requesting 256 bytes requires 4 blocks
        val result = PBKDF2.deriveKey(
            password = "password".toByteArray(),
            salt = "salt".toByteArray(),
            iterations = 1,
            hashAlgorithm = HashAlgorithm.SHA512,
            dkLen = 256
        )
        assertEquals(256, result.size)
        // All 4 blocks should be different
        val block1 = result.copyOfRange(0, 64)
        val block2 = result.copyOfRange(64, 128)
        val block3 = result.copyOfRange(128, 192)
        val block4 = result.copyOfRange(192, 256)
        assertFalse("Blocks 1 and 2 should differ", block1.contentEquals(block2))
        assertFalse("Blocks 2 and 3 should differ", block2.contentEquals(block3))
        assertFalse("Blocks 3 and 4 should differ", block3.contentEquals(block4))
    }

    @Test
    fun `single iteration vs multiple iterations differ`() {
        val r1 = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 1, HashAlgorithm.SHA512, 64)
        val r2 = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 2, HashAlgorithm.SHA512, 64)
        assertFalse("Different iteration counts should give different results", r1.contentEquals(r2))
    }

    @Test
    fun `different salts produce different keys`() {
        val r1 = PBKDF2.deriveKey("pw".toByteArray(), "salt1".toByteArray(), 1, HashAlgorithm.SHA512, 64)
        val r2 = PBKDF2.deriveKey("pw".toByteArray(), "salt2".toByteArray(), 1, HashAlgorithm.SHA512, 64)
        assertFalse("Different salts should give different results", r1.contentEquals(r2))
    }

    @Test
    fun `SHA256 and SHA512 produce different results`() {
        val r256 = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 1, HashAlgorithm.SHA256, 32)
        val r512 = PBKDF2.deriveKey("pw".toByteArray(), "salt".toByteArray(), 1, HashAlgorithm.SHA512, 32)
        assertFalse("SHA256 vs SHA512 should differ", r256.contentEquals(r512))
    }

    @Test
    fun `negative PIM falls back to default iterations`() {
        // The code treats pim <= 0 as "use defaults", so negative PIM is safe —
        // it produces the same high iteration count as PIM=0.
        val iterations = HashAlgorithm.SHA512.getIterationCount(-5)
        assertEquals("Negative PIM should use default", 500_000, iterations)
        val sysIterations = HashAlgorithm.SHA512.getIterationCount(-1, isSystemEncryption = true)
        assertEquals("Negative system PIM should use default", 200_000, sysIterations)
    }
}
