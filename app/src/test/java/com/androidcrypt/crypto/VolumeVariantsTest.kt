package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.File

/**
 * Tests for volume creation and mounting with non-default configurations:
 * - Hidden volumes (create, mount, write protection)
 * - Non-AES ciphers (Serpent, Twofish, AES-Twofish-Serpent, Serpent-Twofish-AES)
 * - SHA-256 hash algorithm
 * - Custom PIM
 *
 * All tests create real containers on disk, mount them, write/read files,
 * and verify correctness. Containers are sparse files so they don't consume
 * much actual disk space.
 */
class VolumeVariantsTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_variant_tests")
        private const val PASSWORD = "VariantTestPass!"
        private const val HIDDEN_PASSWORD = "HiddenVolPassword!"
        private const val TEST_CONTENT = "Hello from variant test!"
    }

    private val filesToCleanup = mutableListOf<File>()

    @After
    fun cleanup() {
        filesToCleanup.forEach { it.delete() }
        filesToCleanup.clear()
        TEST_DIR.delete()
    }

    private fun tempFile(tag: String): File {
        TEST_DIR.mkdirs()
        return File(TEST_DIR, "test_${tag}_${System.nanoTime()}.hc")
            .also { filesToCleanup.add(it) }
    }

    /**
     * Helper: create a volume with the given algorithm, mount it, write+read a file.
     */
    private fun roundTripWithAlgorithm(
        algorithm: EncryptionAlgorithm,
        sizeInMB: Long = 10,
        pim: Int = 0
    ) {
        val tag = "${algorithm.algorithmName}-pim$pim"
        val file = tempFile(tag)

        // Create
        val createResult = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray(),
            sizeInMB = sizeInMB,
            pim = pim,
            algorithm = algorithm
        )
        assertTrue(
            "[$tag] creation failed: ${createResult.exceptionOrNull()?.message}",
            createResult.isSuccess
        )
        assertEquals("[$tag] file size", sizeInMB * 1024 * 1024, file.length())

        // Mount
        val reader = VolumeReader(file.absolutePath)
        try {
            val mountResult = reader.mount(PASSWORD.toCharArray(), pim = pim)
            assertTrue(
                "[$tag] mount failed: ${mountResult.exceptionOrNull()?.message}",
                mountResult.isSuccess
            )
            val info = mountResult.getOrThrow()
            assertTrue("[$tag] should be mounted", info.isMounted)
            assertFalse("[$tag] should not be hidden", info.isHiddenVolume)

            // Write and read a file
            val fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()
            fs.createFile("/", "test.txt").getOrThrow()
            fs.writeFile("/test.txt", TEST_CONTENT.toByteArray()).getOrThrow()
            val readBack = fs.readFile("/test.txt").getOrThrow()
            assertEquals("[$tag] content", TEST_CONTENT, String(readBack))
        } finally {
            reader.unmount()
        }

        // Wrong password should fail
        val reader2 = VolumeReader(file.absolutePath)
        try {
            val badMount = reader2.mount("wrong".toCharArray(), pim = pim)
            assertTrue("[$tag] wrong password should fail", badMount.isFailure)
        } finally {
            reader2.unmount()
        }
    }

    // ── Non-AES cipher tests ────────────────────────────────────────────────

    @Test
    fun `Serpent volume create and mount`() {
        roundTripWithAlgorithm(EncryptionAlgorithm.SERPENT)
    }

    @Test
    fun `Twofish volume create and mount`() {
        roundTripWithAlgorithm(EncryptionAlgorithm.TWOFISH)
    }

    @Test
    fun `AES-Twofish-Serpent cascade volume create and mount`() {
        roundTripWithAlgorithm(EncryptionAlgorithm.AES_TWOFISH_SERPENT)
    }

    @Test
    fun `Serpent-Twofish-AES cascade volume create and mount`() {
        roundTripWithAlgorithm(EncryptionAlgorithm.SERPENT_TWOFISH_AES)
    }

    // ── PIM tests ───────────────────────────────────────────────────────────

    @Test
    fun `AES volume with custom PIM=1`() {
        roundTripWithAlgorithm(EncryptionAlgorithm.AES, pim = 1)
    }

    @Test
    fun `AES volume with custom PIM=10`() {
        roundTripWithAlgorithm(EncryptionAlgorithm.AES, pim = 10)
    }

    @Test
    fun `PIM mismatch prevents mount`() {
        val file = tempFile("pim-mismatch")
        VolumeCreator.createContainer(
            file.absolutePath, PASSWORD.toCharArray(), 10, pim = 5,
            algorithm = EncryptionAlgorithm.AES
        ).getOrThrow()

        val reader = VolumeReader(file.absolutePath)
        try {
            // Mount with wrong PIM should fail
            val result = reader.mount(PASSWORD.toCharArray(), pim = 99)
            assertTrue("Wrong PIM should fail mount", result.isFailure)
        } finally {
            reader.unmount()
        }

        // Mount with correct PIM should succeed
        val reader2 = VolumeReader(file.absolutePath)
        try {
            val result = reader2.mount(PASSWORD.toCharArray(), pim = 5)
            assertTrue(
                "Correct PIM should succeed: ${result.exceptionOrNull()?.message}",
                result.isSuccess
            )
        } finally {
            reader2.unmount()
        }
    }

    // ── Hidden volume tests ─────────────────────────────────────────────────

    @Test
    fun `hidden volume create and mount`() {
        val file = tempFile("hidden")

        // Create outer volume (50 MB to have room for hidden)
        VolumeCreator.createContainer(
            file.absolutePath, PASSWORD.toCharArray(), 50
        ).getOrThrow()

        // Create hidden volume inside (10 MB)
        val hiddenResult = VolumeCreator.createHiddenVolume(
            containerPath = file.absolutePath,
            outerPassword = PASSWORD.toCharArray(),
            hiddenPassword = HIDDEN_PASSWORD.toCharArray(),
            hiddenSizeInMB = 10
        )
        assertTrue(
            "Hidden volume creation failed: ${hiddenResult.exceptionOrNull()?.message}",
            hiddenResult.isSuccess
        )

        // Mount the hidden volume
        val reader = VolumeReader(file.absolutePath)
        try {
            val mountResult = reader.mount(
                HIDDEN_PASSWORD.toCharArray(),
                useHiddenVolume = true
            )
            assertTrue(
                "Hidden mount failed: ${mountResult.exceptionOrNull()?.message}",
                mountResult.isSuccess
            )
            val info = mountResult.getOrThrow()
            assertTrue("Should be mounted", info.isMounted)
            assertTrue("Should be hidden volume", info.isHiddenVolume)
            assertTrue("Hidden volume data area should be > 0", info.dataAreaSize > 0)

            // Write + read inside hidden volume
            val fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()
            fs.createFile("/", "secret.txt").getOrThrow()
            fs.writeFile("/secret.txt", "Hidden secret!".toByteArray()).getOrThrow()
            val readBack = fs.readFile("/secret.txt").getOrThrow()
            assertEquals("Hidden secret!", String(readBack))
        } finally {
            reader.unmount()
        }

        // Outer volume should still be mountable with outer password
        val reader2 = VolumeReader(file.absolutePath)
        try {
            val outerMount = reader2.mount(PASSWORD.toCharArray())
            assertTrue(
                "Outer mount should succeed: ${outerMount.exceptionOrNull()?.message}",
                outerMount.isSuccess
            )
            assertFalse("Should not be hidden", outerMount.getOrThrow().isHiddenVolume)
        } finally {
            reader2.unmount()
        }
    }

    @Test
    fun `hidden volume - wrong password fails`() {
        val file = tempFile("hidden-wrongpw")

        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 50).getOrThrow()
        VolumeCreator.createHiddenVolume(
            file.absolutePath, PASSWORD.toCharArray(),
            HIDDEN_PASSWORD.toCharArray(), 10
        ).getOrThrow()

        val reader = VolumeReader(file.absolutePath)
        try {
            val result = reader.mount("totallyWrong!".toCharArray(), useHiddenVolume = true)
            assertTrue("Wrong hidden password should fail", result.isFailure)
        } finally {
            reader.unmount()
        }
    }

    @Test
    fun `hidden volume with write protection`() {
        val file = tempFile("hidden-protect")

        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 50).getOrThrow()
        VolumeCreator.createHiddenVolume(
            file.absolutePath, PASSWORD.toCharArray(),
            HIDDEN_PASSWORD.toCharArray(), 10
        ).getOrThrow()

        // Mount outer with hidden volume protection
        val reader = VolumeReader(file.absolutePath)
        try {
            val mountResult = reader.mount(
                PASSWORD.toCharArray(),
                hiddenVolumeProtectionPassword = HIDDEN_PASSWORD.toCharArray()
            )
            assertTrue(
                "Outer mount with protection failed: ${mountResult.exceptionOrNull()?.message}",
                mountResult.isSuccess
            )
            val info = mountResult.getOrThrow()
            assertFalse("Should be outer volume", info.isHiddenVolume)
            assertTrue("Should have protection size > 0", info.outerVolumeProtectedSize > 0)
        } finally {
            reader.unmount()
        }
    }

    @Test
    fun `hidden volume too large for container fails`() {
        val file = tempFile("hidden-toolarge")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 10).getOrThrow()

        // Try to create hidden volume larger than the outer data area
        val result = VolumeCreator.createHiddenVolume(
            file.absolutePath, PASSWORD.toCharArray(),
            HIDDEN_PASSWORD.toCharArray(), 50 // way too big
        )
        assertTrue("Hidden volume too large should fail", result.isFailure)
        assertTrue(
            "Error should mention size",
            result.exceptionOrNull()?.message?.contains("too large", ignoreCase = true) == true
        )
    }

    // ── Serpent hidden volume ────────────────────────────────────────────────

    @Test
    fun `hidden volume with Serpent encryption`() {
        val file = tempFile("hidden-serpent")
        VolumeCreator.createContainer(
            file.absolutePath, PASSWORD.toCharArray(), 50,
            algorithm = EncryptionAlgorithm.SERPENT
        ).getOrThrow()

        VolumeCreator.createHiddenVolume(
            file.absolutePath, PASSWORD.toCharArray(),
            HIDDEN_PASSWORD.toCharArray(), 10,
            algorithm = EncryptionAlgorithm.SERPENT
        ).getOrThrow()

        val reader = VolumeReader(file.absolutePath)
        try {
            val mountResult = reader.mount(HIDDEN_PASSWORD.toCharArray(), useHiddenVolume = true)
            assertTrue(
                "Serpent hidden mount failed: ${mountResult.exceptionOrNull()?.message}",
                mountResult.isSuccess
            )
            assertTrue(mountResult.getOrThrow().isHiddenVolume)

            val fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()
            fs.createFile("/", "serpent.txt").getOrThrow()
            fs.writeFile("/serpent.txt", "Serpent hidden!".toByteArray()).getOrThrow()
            assertEquals("Serpent hidden!", String(fs.readFile("/serpent.txt").getOrThrow()))
        } finally {
            reader.unmount()
        }
    }

    // ── VolumeCreator input validation ──────────────────────────────────────

    @Test
    fun `createContainer with size 0 fails`() {
        val file = tempFile("size0")
        val result = VolumeCreator.createContainer(file.absolutePath, "pw".toCharArray(), 0)
        assertTrue("Size 0 should fail", result.isFailure)
    }

    @Test
    fun `createContainer with negative size fails`() {
        val file = tempFile("negsize")
        val result = VolumeCreator.createContainer(file.absolutePath, "pw".toCharArray(), -5)
        assertTrue("Negative size should fail", result.isFailure)
    }

    @Test
    fun `createContainer file already exists fails`() {
        val file = tempFile("exists")
        VolumeCreator.createContainer(file.absolutePath, "pw".toCharArray(), 10).getOrThrow()
        val result = VolumeCreator.createContainer(file.absolutePath, "pw".toCharArray(), 10)
        assertTrue("Existing file should fail", result.isFailure)
    }

    @Test
    fun `createContainer empty password and no keyfiles fails`() {
        val file = tempFile("nopw")
        val result = VolumeCreator.createContainer(file.absolutePath, charArrayOf(), 10)
        assertTrue("Empty password with no keyfiles should fail", result.isFailure)
    }

    @Test
    fun `EncryptionAlgorithm getDerivedKeySize matches keySize`() {
        for (alg in EncryptionAlgorithm.entries) {
            assertEquals("${alg.name} derived key size", alg.keySize, alg.getDerivedKeySize())
        }
    }

    @Test
    fun `EncryptionAlgorithm properties`() {
        assertEquals(64, EncryptionAlgorithm.AES.keySize)
        assertEquals(16, EncryptionAlgorithm.AES.blockSize)
        assertEquals(64, EncryptionAlgorithm.SERPENT.keySize)
        assertEquals(64, EncryptionAlgorithm.TWOFISH.keySize)
        assertEquals(192, EncryptionAlgorithm.AES_TWOFISH_SERPENT.keySize)
        assertEquals(192, EncryptionAlgorithm.SERPENT_TWOFISH_AES.keySize)
    }

    // ── Hidden volume write protection enforcement ───────────────────────────

    @Test
    fun `hidden volume write protection blocks writes to protected area`() {
        val file = tempFile("hidden-write-block")

        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 50).getOrThrow()
        VolumeCreator.createHiddenVolume(
            file.absolutePath, PASSWORD.toCharArray(),
            HIDDEN_PASSWORD.toCharArray(), 10
        ).getOrThrow()

        // Mount outer with hidden volume protection
        val reader = VolumeReader(file.absolutePath)
        try {
            val mountResult = reader.mount(
                PASSWORD.toCharArray(),
                hiddenVolumeProtectionPassword = HIDDEN_PASSWORD.toCharArray()
            )
            assertTrue("Outer mount with protection should succeed", mountResult.isSuccess)
            val info = mountResult.getOrThrow()
            assertTrue("Protection size should be > 0", info.outerVolumeProtectedSize > 0)

            // Compute a sector that falls in the protected area
            // protectedStart = dataAreaSize - outerVolumeProtectedSize
            // We want a sector number beyond protectedStart
            val protectedStartSector = (info.dataAreaSize - info.outerVolumeProtectedSize) / 512
            val protectedSector = protectedStartSector + 10

            // Writing to this sector should fail
            val data = ByteArray(512) { 0x42 }
            val writeResult = reader.writeSector(protectedSector, data)
            assertTrue(
                "Write to protected area should fail",
                writeResult.isFailure
            )
            assertTrue(
                "Error should mention hidden volume",
                writeResult.exceptionOrNull()?.message?.contains("hidden volume", ignoreCase = true) == true
            )

            // Writing to a safe sector (sector 0) should succeed
            val safeWrite = reader.writeSector(0, data)
            assertTrue("Write to safe area should succeed", safeWrite.isSuccess)
        } finally {
            reader.unmount()
        }
    }
}
