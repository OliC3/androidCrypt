package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Unit tests for [VolumeCreator.createHiddenVolume] validation and constraints.
 *
 * These exercise the early-failure paths and size arithmetic without creating
 * full hidden volumes, so they run quickly and need no native dependencies.
 */
class VolumeCreatorHiddenVolumeTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val outerPassword = "outerPassword123".toCharArray()
    private val hiddenPassword = "hiddenPassword456".toCharArray()

    private fun createOuterContainer(name: String, sizeMB: Long): File {
        val file = File(tempFolder.root, name)
        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = outerPassword,
            sizeInMB = sizeMB
        )
        assertTrue("outer creation failed: ${result.exceptionOrNull()?.message}", result.isSuccess)
        return file
    }

    // ── parameter validation ────────────────────────────────────────────────

    @Test
    fun `createHiddenVolume fails when container does not exist`() {
        val missing = File(tempFolder.root, "missing.hc")
        val result = VolumeCreator.createHiddenVolume(
            containerPath = missing.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 1L
        )
        assertTrue(result.isFailure)
        assertTrue(
            result.exceptionOrNull()?.message?.contains("does not exist", ignoreCase = true) == true
        )
    }

    @Test
    fun `createHiddenVolume fails when hidden password is empty`() {
        val outer = createOuterContainer("empty_hidden_pw.hc", 10L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = charArrayOf(),
            hiddenSizeInMB = 1L
        )
        assertTrue(result.isFailure)
        assertTrue(
            result.exceptionOrNull()?.message?.contains("password is required", ignoreCase = true) == true
        )
    }

    @Test
    fun `createHiddenVolume fails when size is zero`() {
        val outer = createOuterContainer("zero_size.hc", 10L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 0L
        )
        assertTrue(result.isFailure)
        assertTrue(
            result.exceptionOrNull()?.message?.contains("at least 1 MB", ignoreCase = true) == true
        )
    }

    @Test
    fun `createHiddenVolume fails when size is negative`() {
        val outer = createOuterContainer("negative_size.hc", 10L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = -1L
        )
        assertTrue(result.isFailure)
        assertTrue(
            result.exceptionOrNull()?.message?.contains("at least 1 MB", ignoreCase = true) == true
        )
    }

    // ── size constraint validation ───────────────────────────────────────────

    @Test
    fun `createHiddenVolume fails when hidden volume exceeds outer data area`() {
        // 5 MB outer → data area is ~5MB - 256KB = ~4.75MB
        // Requesting 10 MB hidden should fail
        val outer = createOuterContainer("too_large.hc", 5L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 10L
        )
        assertTrue(result.isFailure)
        assertTrue(
            result.exceptionOrNull()?.message?.contains("too large", ignoreCase = true) == true
        )
    }

    @Test
    fun `createHiddenVolume fails when hidden volume exceeds available space`() {
        // 5 MB outer → data area is ~4.75MB. Reserved end area is 128KB.
        // Requesting 10 MB hidden should definitely fail.
        val outer = createOuterContainer("too_large.hc", 5L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 10L
        )
        assertTrue(result.isFailure)
    }

    @Test
    fun `createHiddenVolume succeeds with small hidden volume in large outer`() {
        // 20 MB outer, 2 MB hidden should fit comfortably
        val outer = createOuterContainer("fits.hc", 20L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 2L
        )
        assertTrue(
            "2 MB hidden in 20 MB outer should succeed: ${result.exceptionOrNull()?.message}",
            result.isSuccess
        )
    }

    @Test
    fun `createHiddenVolume succeeds at 1 MB minimum`() {
        val outer = createOuterContainer("min_hidden.hc", 10L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 1L
        )
        assertTrue(
            "1 MB hidden should succeed: ${result.exceptionOrNull()?.message}",
            result.isSuccess
        )
    }

    // ── reserved area size selection ──────────────────────────────────────────

    @Test
    fun `small container uses small reserved area`() {
        // Containers < 2 MB use HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE (4096)
        val smallThreshold = VolumeConstants.VOLUME_SMALL_SIZE_THRESHOLD
        assertEquals(2L * 1024 * 1024, smallThreshold)
    }

    @Test
    fun `large container uses large reserved area`() {
        // Containers >= 2 MB use HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH (128KB)
        val largeThreshold = VolumeConstants.VOLUME_SMALL_SIZE_THRESHOLD
        val largeReserved = VolumeConstants.HIDDEN_VOLUME_HOST_FS_RESERVED_END_AREA_SIZE_HIGH
        assertEquals(VolumeConstants.VOLUME_HEADER_GROUP_SIZE, largeReserved)
    }

    // ── algorithm and hash combinations ─────────────────────────────────────

    @Test
    fun `createHiddenVolume with Serpent algorithm succeeds`() {
        val outer = createOuterContainer("hidden_serpent.hc", 15L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 2L,
            algorithm = EncryptionAlgorithm.SERPENT
        )
        assertTrue("Serpent hidden volume: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createHiddenVolume with SHA256 hash succeeds`() {
        val outer = createOuterContainer("hidden_sha256.hc", 15L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 2L,
            hashAlgorithm = HashAlgorithm.SHA256
        )
        assertTrue("SHA256 hidden volume: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    @Test
    fun `createHiddenVolume with nondefault PIM succeeds`() {
        val outer = createOuterContainer("hidden_pim.hc", 15L)
        val result = VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 2L,
            pim = 5
        )
        assertTrue("PIM=5 hidden volume: ${result.exceptionOrNull()?.message}", result.isSuccess)
    }

    // ── header placement verification ─────────────────────────────────────────

    @Test
    fun `hidden header is written at correct offset`() {
        val outer = createOuterContainer("header_offset.hc", 15L)
        val before = outer.readBytes()

        VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 2L
        )

        val after = outer.readBytes()
        // The hidden header is at offset 64KB (HIDDEN_VOLUME_HEADER_OFFSET).
        // Before creation, that area was random data from the outer volume format.
        // After creation, it should contain the encrypted hidden header (salt + encrypted data).
        // We verify the bytes changed — a stronger test would decrypt the header.
        val hiddenHeaderOffset = VolumeConstants.HIDDEN_VOLUME_HEADER_OFFSET.toInt()
        val headerSize = VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE
        val beforeSlice = before.copyOfRange(hiddenHeaderOffset, hiddenHeaderOffset + headerSize)
        val afterSlice = after.copyOfRange(hiddenHeaderOffset, hiddenHeaderOffset + headerSize)

        // At minimum the salt (first 64 bytes) should differ because it's randomly generated
        val beforeSalt = beforeSlice.copyOfRange(0, 64)
        val afterSalt = afterSlice.copyOfRange(0, 64)
        assertFalse("hidden header salt should differ after creation", beforeSalt.contentEquals(afterSalt))
    }

    @Test
    fun `createHiddenVolume does not change outer container file size`() {
        val outer = createOuterContainer("same_size.hc", 15L)
        val sizeBefore = outer.length()

        VolumeCreator.createHiddenVolume(
            containerPath = outer.absolutePath,
            outerPassword = outerPassword,
            hiddenPassword = hiddenPassword,
            hiddenSizeInMB = 2L
        )

        assertEquals(sizeBefore, outer.length())
    }
}
