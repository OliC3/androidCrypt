package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Integration test: keyfile-modified password used for encrypt/decrypt round-trip.
 * Uses the production KeyfileProcessor (not a local reimplementation).
 */
class KeyfileIntegrationTest {

    companion object {
        private const val SALT_SIZE = 64
    }

    @Test
    fun testEncryptDecryptWithKeyfile() {
        val keyfileContent = "this is my keyfile content\n".toByteArray()
        val kfPath = createTempKeyfile("integ", keyfileContent)
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }

        // Apply keyfile to password (creation side)
        val passwordBytes1 = KeyfileProcessor.applyKeyfiles("testpassword".toCharArray(), listOf(kfPath)).getOrThrow()

        // Derive key for encryption
        val key1 = PBKDF2.deriveKey(passwordBytes1, salt, 1000, HashAlgorithm.SHA512, 64)

        // Encrypt test data
        val testData = "VERA".toByteArray() + ByteArray(28)
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key1.copyOf(32), "AES"))
        val encrypted = cipher.doFinal(testData)
        assertFalse("Ciphertext should differ from plaintext", encrypted.contentEquals(testData))

        // Simulate reading: apply keyfile again
        val passwordBytes2 = KeyfileProcessor.applyKeyfiles("testpassword".toCharArray(), listOf(kfPath)).getOrThrow()
        assertArrayEquals("Keyfile application should be deterministic", passwordBytes1, passwordBytes2)

        // Derive key for decryption
        val key2 = PBKDF2.deriveKey(passwordBytes2, salt, 1000, HashAlgorithm.SHA512, 64)
        assertArrayEquals("Keys should match", key1, key2)

        // Decrypt and verify
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key2.copyOf(32), "AES"))
        val decrypted = cipher.doFinal(encrypted)
        assertArrayEquals("Decrypted data should match original", testData, decrypted)
        assertEquals("Magic should be VERA", "VERA", String(decrypted.copyOf(4)))
    }

    @Test
    fun testKeyfileOnlyNoPassword() {
        val kfPath = createTempKeyfile("nopass", "keyfile_content_123".toByteArray())
        val salt = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }

        val passwordBytes = KeyfileProcessor.applyKeyfiles("".toCharArray(), listOf(kfPath)).getOrThrow()
        assertEquals("With no password, result should be pool size", 64, passwordBytes.size)
        assertTrue("Keyfile-only result should have non-zero bytes", passwordBytes.any { it != 0.toByte() })

        // Full encrypt/decrypt round-trip
        val key = PBKDF2.deriveKey(passwordBytes, salt, 1000, HashAlgorithm.SHA512, 64)
        val testData = ByteArray(32) { it.toByte() }
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.copyOf(32), "AES"))
        val encrypted = cipher.doFinal(testData)
        assertFalse("Ciphertext should differ from plaintext", encrypted.contentEquals(testData))
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key.copyOf(32), "AES"))
        val decrypted = cipher.doFinal(encrypted)
        assertArrayEquals("Round-trip should match", testData, decrypted)
    }

    private fun createTempKeyfile(name: String, content: ByteArray): String {
        val f = File.createTempFile(name, ".bin")
        f.deleteOnExit()
        f.writeBytes(content)
        return f.absolutePath
    }
}
