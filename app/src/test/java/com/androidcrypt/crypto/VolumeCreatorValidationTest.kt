package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Unit tests for [VolumeCreator.createContainer] input validation.
 *
 * These tests exercise the early-failure paths (file exists, empty credentials,
 * size too small) without creating full containers, so they run quickly and
 * need no native dependencies.
 */
class VolumeCreatorValidationTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val password = "testPassword123".toCharArray()

    // ── file already exists ─────────────────────────────────────────────────

    @Test
    fun `createContainer fails when file already exists`() {
        val existing = tempFolder.newFile("already_here.hc")
        assertTrue(existing.exists())

        val result = VolumeCreator.createContainer(
            containerPath = existing.absolutePath,
            password = password,
            sizeInMB = 4L
        )

        assertTrue("should fail", result.isFailure)
        assertTrue(
            "error should mention 'already exists'",
            result.exceptionOrNull()?.message?.contains("already exists", ignoreCase = true) == true
        )
    }

    // ── empty credentials ───────────────────────────────────────────────────

    @Test
    fun `createContainer fails when password is empty and no keyfiles`() {
        val file = File(tempFolder.root, "no_creds.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = charArrayOf(),
            sizeInMB = 4L,
            keyfileUris = emptyList()
        )

        assertTrue("should fail", result.isFailure)
        assertTrue(
            "error should mention password or keyfiles",
            result.exceptionOrNull()?.message?.contains("Password or keyfiles required", ignoreCase = true) == true
        )
    }

    @Test
    fun `createContainer succeeds when password is empty but keyfiles provided`() {
        // This path requires a real Context to resolve URIs, so it will fail
        // at the keyfile-processing stage rather than the validation stage.
        // We verify the validation gate is NOT the failure reason.
        val file = File(tempFolder.root, "keyfiles_only.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = charArrayOf(),
            sizeInMB = 4L,
            keyfileUris = listOf(android.net.Uri.parse("content://test/keyfile")),
            context = null   // null context → keyfile processing will fail
        )

        // Should NOT fail with "Password or keyfiles required"
        val msg = result.exceptionOrNull()?.message ?: ""
        assertFalse(
            "should not fail with credential validation error",
            msg.contains("Password or keyfiles required", ignoreCase = true)
        )
    }

    // ── size validation ─────────────────────────────────────────────────────

    @Test
    fun `createContainer fails when size is zero`() {
        val file = File(tempFolder.root, "zero_size.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 0L
        )

        assertTrue("should fail", result.isFailure)
        assertTrue(
            "error should mention size",
            result.exceptionOrNull()?.message?.contains("at least 1 MB", ignoreCase = true) == true
        )
    }

    @Test
    fun `createContainer fails when size is negative`() {
        val file = File(tempFolder.root, "negative_size.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = -1L
        )

        assertTrue("should fail", result.isFailure)
        assertTrue(
            "error should mention size",
            result.exceptionOrNull()?.message?.contains("at least 1 MB", ignoreCase = true) == true
        )
    }

    @Test
    fun `createContainer succeeds with minimum size 1 MB`() {
        val file = File(tempFolder.root, "one_mb.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 1L
        )

        assertTrue("1 MB should be valid: ${result.exceptionOrNull()?.message}", result.isSuccess)
        assertTrue(file.exists())
        assertEquals(1L * 1024 * 1024, file.length())
    }

    // ── algorithm and hash combinations ─────────────────────────────────────

    @Test
    fun `createContainer with AES algorithm succeeds`() {
        val file = File(tempFolder.root, "aes_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 2L,
            algorithm = EncryptionAlgorithm.AES
        )

        assertTrue("AES should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createContainer with Serpent algorithm succeeds`() {
        val file = File(tempFolder.root, "serpent_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 2L,
            algorithm = EncryptionAlgorithm.SERPENT
        )

        assertTrue("Serpent should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createContainer with Twofish algorithm succeeds`() {
        val file = File(tempFolder.root, "twofish_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 2L,
            algorithm = EncryptionAlgorithm.TWOFISH
        )

        assertTrue("Twofish should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createContainer with AES-Twofish-Serpent cascade succeeds`() {
        val file = File(tempFolder.root, "cascade_ats_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 4L,
            algorithm = EncryptionAlgorithm.AES_TWOFISH_SERPENT
        )

        assertTrue("AES-Twofish-Serpent should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createContainer with Serpent-Twofish-AES cascade succeeds`() {
        val file = File(tempFolder.root, "cascade_sta_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 4L,
            algorithm = EncryptionAlgorithm.SERPENT_TWOFISH_AES
        )

        assertTrue("Serpent-Twofish-AES should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createContainer with SHA256 hash succeeds`() {
        val file = File(tempFolder.root, "sha256_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 2L,
            hashAlgorithm = HashAlgorithm.SHA256
        )

        assertTrue("SHA256 should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createContainer with SHA512 hash succeeds`() {
        val file = File(tempFolder.root, "sha512_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 2L,
            hashAlgorithm = HashAlgorithm.SHA512
        )

        assertTrue("SHA512 should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createContainer with nondefault PIM succeeds`() {
        val file = File(tempFolder.root, "pim_vol.hc")

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 2L,
            pim = 5
        )

        assertTrue("PIM=5 should succeed: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    // ── file size verification ──────────────────────────────────────────────

    @Test
    fun `created container has exact requested size`() {
        val file = File(tempFolder.root, "exact_size.hc")
        val sizeMB = 3L

        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = sizeMB
        )

        assertTrue(result.isSuccess)
        assertEquals(sizeMB * 1024 * 1024, file.length())
    }

    @Test
    fun `created container is not empty`() {
        val file = File(tempFolder.root, "non_empty.hc")

        VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = password,
            sizeInMB = 2L
        )

        val content = file.readBytes()
        // At minimum the salt + header should be non-zero (salt is random)
        val allZero = content.all { it == 0.toByte() }
        assertFalse("container should not be all zeros", allZero)
    }
}
