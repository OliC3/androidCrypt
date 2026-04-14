package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * JVM unit tests for volume creation, mounting, and file I/O.
 *
 * Covers both normal sizes and the specific sizes that triggered integer-overflow
 * crashes in mountFromPath / mountFromUri:
 *
 *   volumeSize = N × 2^20 bytes.  The old code called volumeSize.toInt() which
 *   truncates to the lower 32 bits:  lower32 = (N mod 4096) × 2^20
 *
 *   • N mod 4096 == 0      → toInt() = 0    → ByteArray(0)        → IndexOutOfBoundsException
 *                                              "toIndex(64) is greater than size(0)"
 *   • N mod 4096 ∈ [2048, 4095] → toInt() < 0 → ByteArray(negative) → NegativeArraySizeException
 *   • N mod 4096 ∈ [1, 2047]   → toInt() > 0, accidentally works
 *
 * Container files are created in a temp directory and deleted after every test.
 */
class VolumeCreationMountTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_tests")
        private const val PASSWORD = "TestPassword123!"
        private const val TEST_FILENAME = "hello.txt"
        private const val TEST_CONTENT = "Hello from VolumeCreationMountTest!\nLine 2: the quick brown fox."
    }

    private val filesToCleanup = mutableListOf<File>()

    @After
    fun cleanup() {
        filesToCleanup.forEach { it.delete() }
        filesToCleanup.clear()
        TEST_DIR.delete() // removes the dir only when empty
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private fun tempFile(tag: String): File {
        TEST_DIR.mkdirs()
        return File(TEST_DIR, "test_${tag}_${System.nanoTime()}.hc")
            .also { filesToCleanup.add(it) }
    }

    private fun createAndMount(sizeInMB: Long, tag: String) {
        val file = tempFile(tag)
        val expectedBytes = sizeInMB * 1024L * 1024L

        // ── Create ────────────────────────────────────────────────────────────
        val createResult = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray(),
            sizeInMB = sizeInMB
        )
        assertTrue(
            "[$tag] creation failed: ${createResult.exceptionOrNull()?.message}",
            createResult.isSuccess
        )
        assertTrue("[$tag] container file does not exist after creation", file.exists())
        assertEquals("[$tag] on-disk file size is wrong", expectedBytes, file.length())

        // ── Mount ─────────────────────────────────────────────────────────────
        val reader = VolumeReader(file.absolutePath)
        try {
            val mountResult = reader.mount(PASSWORD.toCharArray())
            assertTrue(
                "[$tag] mount failed: ${mountResult.exceptionOrNull()?.message}",
                mountResult.isSuccess
            )
            val info = mountResult.getOrThrow()
            assertTrue("[$tag] isMounted should be true", info.isMounted)
            assertTrue("[$tag] dataAreaSize should be > 0", info.dataAreaSize > 0)
            assertEquals("[$tag] sectorSize should be 512", 512, info.sectorSize)
            // VeraCrypt data area always starts at 128 KB (2 × 64 KB headers)
            assertEquals("[$tag] dataAreaOffset should be 131072", 131_072L, info.dataAreaOffset)

            // ── Write a text file into the volume ─────────────────────────────
            val fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()

            assertFalse("[$tag] file should not exist yet", fs.exists("/$TEST_FILENAME"))

            fs.createFile("/", TEST_FILENAME).getOrThrow()
            val written = TEST_CONTENT.toByteArray(Charsets.UTF_8)
            fs.writeFile("/$TEST_FILENAME", written).getOrThrow()

            // ── Read it back and verify byte-for-byte equality ────────────────
            val readBack = fs.readFile("/$TEST_FILENAME").getOrThrow()
            assertArrayEquals(
                "[$tag] file content read back does not match what was written",
                written,
                readBack
            )
            assertEquals(
                "[$tag] file content as string should match original",
                TEST_CONTENT,
                readBack.toString(Charsets.UTF_8)
            )
        } finally {
            reader.unmount() // safe to call even if mount failed — nulls file handles
        }
    }

    // ── Small volumes (regression guard — always worked) ─────────────────────

    @Test
    fun `10 MB volume can be created and mounted`() = createAndMount(10, "10MB")

    @Test
    fun `100 MB volume can be created and mounted`() = createAndMount(100, "100MB")

    @Test
    fun `1024 MB volume can be created and mounted`() = createAndMount(1024, "1024MB")

    // ── Overflow-triggering sizes ─────────────────────────────────────────────

    @Test
    fun `4096 MB volume - exact 4 GiB, toInt zero overflow`() =
        // 4096 mod 4096 = 0  →  old volumeSize.toInt() = 0  →  ByteArray(0)
        // →  IndexOutOfBoundsException: "toIndex(64) is greater than size(0)"
        createAndMount(4096, "4096MB")

    @Test
    fun `6144 MB volume - toInt negative overflow`() =
        // 6144 mod 4096 = 2048  →  old volumeSize.toInt() = Int.MIN_VALUE (-2147483648)
        // →  NegativeArraySizeException: -2146304000
        createAndMount(6144, "6144MB")

    // ── Large volume (the exact size reported as broken) ─────────────────────
    //
    // 80 GiB = 81920 MB.  81920 mod 4096 = 0, so this hits the same zero-overflow
    // path as 4096 MB above.  The container is created as a sparse file on Linux
    // (raf.setLength triggers fallocate/ftruncate, not physical writes), so only
    // the FAT sectors — roughly 2 × 145 KB × 512 B ≈ 149 MB — are physically
    // written; the test typically completes in under 30 s on modern hardware.

    @Test(timeout = 300_000L) // 5-minute ceiling
    fun `80 GiB volume - exact 80 GiB, toInt zero overflow`() =
        createAndMount(81_920, "80GiB")

    // ── Wrong password ────────────────────────────────────────────────────────

    @Test
    fun `mount with wrong password fails`() {
        val file = tempFile("wrongpass")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 10L).getOrThrow()

        val reader = VolumeReader(file.absolutePath)
        try {
            val mountResult = reader.mount("wrongPassword!".toCharArray())
            assertTrue("mount with wrong password should fail", mountResult.isFailure)
        } finally {
            reader.unmount()
        }
    }
}
