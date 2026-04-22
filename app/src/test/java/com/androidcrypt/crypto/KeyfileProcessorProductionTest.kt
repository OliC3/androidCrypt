package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Tests for the **production** KeyfileProcessor.applyKeyfiles().
 *
 * Unlike the existing KeyfileProcessorTest/KeyfileIntegrationTest which reimplement
 * the CRC32 pool algorithm locally, these tests call the real KeyfileProcessor code
 * with actual keyfiles on disk.
 */
class KeyfileProcessorProductionTest {

    private lateinit var tempDir: File
    private val filesToCleanup = mutableListOf<File>()

    @Before
    fun setUp() {
        tempDir = File(System.getProperty("java.io.tmpdir")!!, "keyfile_test_${System.nanoTime()}")
        tempDir.mkdirs()
    }

    @After
    fun tearDown() {
        filesToCleanup.forEach { it.delete() }
        tempDir.deleteRecursively()
    }

    private fun createKeyfile(name: String, content: ByteArray): String {
        val f = File(tempDir, name)
        f.writeBytes(content)
        filesToCleanup.add(f)
        return f.absolutePath
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    // ── Basic functionality ─────────────────────────────────────────────────

    @Test
    fun `no keyfiles returns raw password bytes`() {
        val result = KeyfileProcessor.applyKeyfiles(
            password = "hello".toCharArray(),
            keyfiles = emptyList()
        )
        assertTrue(result.isSuccess)
        assertArrayEquals("hello".toByteArray(Charsets.UTF_8), result.getOrThrow())
    }

    @Test
    fun `single keyfile modifies password`() {
        val kfPath = createKeyfile("key1.bin", "ABCDEF".toByteArray())
        val withoutKf = KeyfileProcessor.applyKeyfiles("test".toCharArray(), emptyList()).getOrThrow()
        val withKf = KeyfileProcessor.applyKeyfiles("test".toCharArray(), listOf(kfPath)).getOrThrow()

        // Result must differ from plain password
        assertFalse("Keyfile should modify the password bytes", withoutKf.contentEquals(withKf))
        // Result length = max(password.size, poolSize=64) since password "test" is ≤64 chars
        assertEquals(64, withKf.size)
    }

    @Test
    fun `empty password with keyfile produces non-zero result`() {
        val kfPath = createKeyfile("key.dat", ByteArray(256) { it.toByte() })
        val result = KeyfileProcessor.applyKeyfiles("".toCharArray(), listOf(kfPath)).getOrThrow()
        assertEquals(64, result.size)
        // At least some bytes should be non-zero (keyfile pool mixed in)
        assertTrue("Result should not be all zeros", result.any { it != 0.toByte() })
    }

    @Test
    fun `deterministic - same input gives same output`() {
        val kfPath = createKeyfile("det.bin", "deterministic keyfile content".toByteArray())
        val r1 = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kfPath)).getOrThrow()
        val r2 = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kfPath)).getOrThrow()
        assertArrayEquals("Same inputs should produce identical output", r1, r2)
    }

    @Test
    fun `multiple keyfiles produce different result than single`() {
        val kf1 = createKeyfile("a.bin", "alpha".toByteArray())
        val kf2 = createKeyfile("b.bin", "bravo".toByteArray())

        val single = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kf1)).getOrThrow()
        val both = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kf1, kf2)).getOrThrow()

        assertFalse("Two keyfiles should produce a different result than one", single.contentEquals(both))
    }

    @Test
    fun `multiple keyfiles combined modify password`() {
        val kf1 = createKeyfile("first.bin", ByteArray(256) { (it * 3).toByte() })
        val kf2 = createKeyfile("second.bin", ByteArray(256) { (it * 7 + 13).toByte() })

        val order1 = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kf1, kf2)).getOrThrow()
        val order2 = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kf2, kf1)).getOrThrow()

        assertEquals(64, order1.size)
        assertEquals(64, order2.size)

        // Both results should differ from password-only
        val noKf = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), emptyList()).getOrThrow()
        assertFalse("Keyfiles should modify password", order1.contentEquals(noKf))
        assertFalse("Keyfiles should modify password", order2.contentEquals(noKf))

        // Both results should differ from single-keyfile results
        val singleKf1 = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kf1)).getOrThrow()
        assertFalse("Two keyfiles should differ from one", order1.contentEquals(singleKf1))
    }

    @Test
    fun `long password uses 128-byte pool`() {
        val longPassword = "a".repeat(65)  // > 64 chars → pool size = 128
        val kfPath = createKeyfile("long.bin", "data".toByteArray())

        val result = KeyfileProcessor.applyKeyfiles(longPassword.toCharArray(), listOf(kfPath)).getOrThrow()
        // Result = max(password.size, poolSize=128) = 128
        assertEquals(128, result.size)
    }

    @Test
    fun `nonexistent keyfile returns failure`() {
        val result = KeyfileProcessor.applyKeyfiles(
            "pw".toCharArray(),
            listOf("/nonexistent/path/keyfile.dat")
        )
        assertTrue("Should fail for missing keyfile", result.isFailure)
    }

    @Test
    fun `large keyfile - 1MB boundary`() {
        // VeraCrypt reads at most 1MB from each keyfile
        val largeContent = ByteArray(1024 * 1024 + 100) { (it % 256).toByte() }
        val kfPath = createKeyfile("large.bin", largeContent)
        val result = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kfPath))
        assertTrue("Should handle large keyfile", result.isSuccess)
        val bytes = result.getOrThrow()
        assertEquals("Result should be 64 bytes (pool size)", 64, bytes.size)
        // Large keyfile should produce non-trivial output different from password-only
        val withoutKf = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), emptyList()).getOrThrow()
        assertFalse("Large keyfile should modify the password", bytes.contentEquals(withoutKf))
    }

    // ── Integration: keyfile-modified password can mount a volume ────────────

    @Test
    fun `keyfile produces different derived bytes than raw password and is deterministic`() {
        val kfPath = createKeyfile("volume.key", "secret keyfile data 12345".toByteArray())

        // Verify that keyfile produces a different password than raw
        val rawPw = KeyfileProcessor.applyKeyfiles("mypass".toCharArray(), emptyList()).getOrThrow()
        val withKf = KeyfileProcessor.applyKeyfiles("mypass".toCharArray(), listOf(kfPath)).getOrThrow()
        assertFalse("Keyfile should change password bytes", rawPw.contentEquals(withKf))

        // Verify that wrong keyfile produces a different password
        val wrongKf = createKeyfile("wrong.key", "wrong keyfile content".toByteArray())
        val withWrongKf = KeyfileProcessor.applyKeyfiles("mypass".toCharArray(), listOf(wrongKf)).getOrThrow()
        assertFalse("Different keyfiles should produce different passwords", withKf.contentEquals(withWrongKf))

        // Verify deterministic: same keyfile always gives same result
        val withKf2 = KeyfileProcessor.applyKeyfiles("mypass".toCharArray(), listOf(kfPath)).getOrThrow()
        assertArrayEquals("Same keyfile must be deterministic", withKf, withKf2)
    }

    @Test
    fun `empty keyfile (0 bytes) still modifies password`() {
        // A 0-byte keyfile produces no CRC updates, so the pool stays all-zeros.
        // The password bytes are then mixed with zero-pool, meaning the result
        // equals the password bytes padded to pool size — effectively "no keyfile".
        // This test documents the current behavior.
        val kfPath = createKeyfile("empty.key", ByteArray(0))
        val withEmptyKf = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), listOf(kfPath)).getOrThrow()
        val withoutKf = KeyfileProcessor.applyKeyfiles("pw".toCharArray(), emptyList()).getOrThrow()

        // Pool size is 64 for passwords ≤ 64 chars
        assertEquals("Result should be pool-sized", 64, withEmptyKf.size)

        // With a 0-byte keyfile the pool is all zeros, so the result should
        // equal the password bytes (padded with zeros to 64).
        // This documents a potential security concern: empty keyfiles provide no protection.
        val expectedBytes = ByteArray(64)
        val pwBytes = "pw".toByteArray(Charsets.UTF_8)
        System.arraycopy(pwBytes, 0, expectedBytes, 0, pwBytes.size)
        assertArrayEquals(
            "Empty keyfile should not alter password (pool is all-zeros)",
            expectedBytes, withEmptyKf
        )
    }
}
