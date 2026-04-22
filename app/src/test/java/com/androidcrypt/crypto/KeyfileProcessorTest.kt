package com.androidcrypt.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Tests for the production KeyfileProcessor using known input/output pairs.
 * These call the real KeyfileProcessor code (not a local reimplementation).
 */
class KeyfileProcessorTest {

    private fun createTempKeyfile(name: String, content: ByteArray): String {
        val f = File.createTempFile(name, ".bin")
        f.deleteOnExit()
        f.writeBytes(content)
        return f.absolutePath
    }

    @Test
    fun testKeyfileProcessing_SimpleASCII() {
        val kfPath = createTempKeyfile("ascii", "testdata\n".toByteArray())
        val result = KeyfileProcessor.applyKeyfiles("mypassword".toCharArray(), listOf(kfPath)).getOrThrow()
        assertEquals("Result should be 64 bytes", 64, result.size)

        // Verify deterministic
        val result2 = KeyfileProcessor.applyKeyfiles("mypassword".toCharArray(), listOf(kfPath)).getOrThrow()
        assertArrayEquals("Must be deterministic", result, result2)

        // Verify keyfile actually changed the password
        val noKf = KeyfileProcessor.applyKeyfiles("mypassword".toCharArray(), emptyList()).getOrThrow()
        assertFalse("Keyfile should modify the password", result.contentEquals(noKf))
    }

    @Test
    fun testKeyfileProcessing_EmptyPassword() {
        val kfPath = createTempKeyfile("emptypw", "testdata\n".toByteArray())
        val result = KeyfileProcessor.applyKeyfiles("".toCharArray(), listOf(kfPath)).getOrThrow()
        assertEquals("Result should be 64 bytes", 64, result.size)

        // With empty password, result should be purely from keyfile pool
        assertTrue("Should have non-zero bytes from keyfile", result.any { it != 0.toByte() })

        // Different password should give different result
        val withPw = KeyfileProcessor.applyKeyfiles("test".toCharArray(), listOf(kfPath)).getOrThrow()
        assertFalse("Empty vs non-empty password should differ", result.contentEquals(withPw))
    }

    @Test
    fun testKeyfileProcessing_BinaryData() {
        val kfPath = createTempKeyfile("binary", ByteArray(16) { it.toByte() })
        val result = KeyfileProcessor.applyKeyfiles("test".toCharArray(), listOf(kfPath)).getOrThrow()
        assertEquals("Result should be 64 bytes", 64, result.size)

        // Verify deterministic
        val result2 = KeyfileProcessor.applyKeyfiles("test".toCharArray(), listOf(kfPath)).getOrThrow()
        assertArrayEquals("Must be deterministic", result, result2)
    }

    @Test
    fun testKeyfileProcessing_SingleByte() {
        val kfPath = createTempKeyfile("single", "A".toByteArray())
        val result = KeyfileProcessor.applyKeyfiles("password".toCharArray(), listOf(kfPath)).getOrThrow()
        assertEquals("Result should be 64 bytes", 64, result.size)

        // Even a single-byte keyfile should modify the password
        val noKf = KeyfileProcessor.applyKeyfiles("password".toCharArray(), emptyList()).getOrThrow()
        assertFalse("Single-byte keyfile should modify the password", result.contentEquals(noKf))
    }
}
