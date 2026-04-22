package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Tests for VolumeContainer: create/open/read/write/close lifecycle,
 * wrong password handling, and key material cleanup.
 */
class VolumeContainerTest {

    private lateinit var tempDir: File

    @Before
    fun setUp() {
        tempDir = File(System.getProperty("java.io.tmpdir")!!, "vc_test_${System.nanoTime()}")
        tempDir.mkdirs()
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    // ── Create and open ─────────────────────────────────────────────────────

    @Test
    fun `create and open round-trip`() {
        val file = File(tempDir, "test.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE

        container.create("password".toCharArray(), size)

        val info = container.getInfo()
        assertNotNull("Info should be available after create", info)
        assertTrue("Size should be positive", info!!.sizeBytes > 0)
        assertEquals("AES", info.encryptionAlgorithm)
        assertEquals("SHA-512", info.hashAlgorithm)
        assertEquals(512, info.sectorSize)

        container.close()
    }

    @Test
    fun `open existing volume with correct password`() {
        val file = File(tempDir, "test.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("mypass".toCharArray(), size)
        container.close()

        // Re-open
        val container2 = VolumeContainer(file)
        assertTrue("Should open with correct password", container2.open("mypass".toCharArray()))
        assertNotNull(container2.getInfo())
        container2.close()
    }

    @Test
    fun `open with wrong password returns false`() {
        val file = File(tempDir, "test.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("correct".toCharArray(), size)
        container.close()

        val container2 = VolumeContainer(file)
        assertFalse("Should fail with wrong password", container2.open("wrong".toCharArray()))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `open nonexistent file throws`() {
        val container = VolumeContainer(File(tempDir, "nonexistent.hc"))
        container.open("pw".toCharArray())
    }

    // ── Read and write ──────────────────────────────────────────────────────

    @Test
    fun `write and read data round-trip`() {
        val file = File(tempDir, "rw.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        // Write a sector-aligned block
        val data = ByteArray(512) { (it % 256).toByte() }
        container.write(0, data)

        // Read it back
        val readBack = container.read(0, 512)
        assertArrayEquals("Read should match write", data, readBack)

        container.close()
    }

    @Test
    fun `write and read multiple sectors`() {
        val file = File(tempDir, "multisec.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        val data = ByteArray(4 * 512) { ((it * 7 + 3) % 256).toByte() }
        container.write(0, data)

        val readBack = container.read(0, 4 * 512)
        assertArrayEquals("Multi-sector round-trip", data, readBack)

        container.close()
    }

    @Test
    fun `write at offset and read back`() {
        val file = File(tempDir, "offset.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        // Write at sector 10 (offset 5120)
        val data = ByteArray(512) { 0xAB.toByte() }
        container.write(5120, data)

        val readBack = container.read(5120, 512)
        assertArrayEquals("Offset write round-trip", data, readBack)

        container.close()
    }

    @Test
    fun `read sub-sector range`() {
        val file = File(tempDir, "subsector.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        // Write a full sector
        val data = ByteArray(512) { (it % 256).toByte() }
        container.write(0, data)

        // Read just 100 bytes from offset 50
        val partial = container.read(50, 100)
        assertEquals(100, partial.size)
        assertArrayEquals("Partial read", data.copyOfRange(50, 150), partial)

        container.close()
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    @Test(expected = IllegalArgumentException::class)
    fun `read before open throws`() {
        val file = File(tempDir, "closed.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)
        container.close()

        val container2 = VolumeContainer(file)
        container2.read(0, 512)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `write before open throws`() {
        val file = File(tempDir, "closed.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)
        container.close()

        val container2 = VolumeContainer(file)
        container2.write(0, ByteArray(512))
    }

    @Test
    fun `double close is safe`() {
        val file = File(tempDir, "dblclose.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        container.close()
        container.close() // Should not throw
    }

    @Test
    fun `getInfo returns null when closed`() {
        val file = File(tempDir, "info.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)
        container.close()

        assertNull("Info should be null when closed", container.getInfo())
    }

    @Test
    fun `re-open after close works`() {
        val file = File(tempDir, "reopen.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        // Write data
        val data = ByteArray(512) { 0x42 }
        container.write(0, data)
        container.close()

        // Re-open and read
        assertTrue(container.open("pw".toCharArray()))
        val readBack = container.read(0, 512)
        assertArrayEquals("Data should persist across close/reopen", data, readBack)
        container.close()
    }

    // ── VolumeInfo ──────────────────────────────────────────────────────────

    @Test
    fun `VolumeInfo toString does not leak sensitive data`() {
        val file = File(tempDir, "info2.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        val info = container.getInfo()!!
        val str = info.toString()
        // Verify it produces meaningful output
        assertTrue("Should start with VolumeInfo(", str.startsWith("VolumeInfo("))
        // Verify the actual field values that could leak are absent
        assertFalse("Should not contain encryption algorithm name", str.contains(info.encryptionAlgorithm))
        assertFalse("Should not contain hash algorithm name", str.contains(info.hashAlgorithm))
        assertFalse("Should not contain creation time", str.contains(info.creationTime.toString()))
        assertFalse("Should not contain sector size", str.contains(info.sectorSize.toString()))
        assertFalse("Should not expose field names", str.contains("sectorSize"))
        assertTrue("Should contain MB for safe summary", str.contains("MB"))

        container.close()
    }

    // ── Size validation ─────────────────────────────────────────────────────

    @Test(expected = IllegalArgumentException::class)
    fun `create with too-small size throws`() {
        val file = File(tempDir, "tiny.hc")
        val container = VolumeContainer(file)
        container.create("pw".toCharArray(), 1000) // Way too small
    }

    // ── Key zeroing ─────────────────────────────────────────────────────────

    @Test
    fun `close zeros key material`() {
        val file = File(tempDir, "zeroing.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size)

        // Capture the actual byte array references before close
        val mkField = VolumeContainer::class.java.getDeclaredField("masterKey")
        mkField.isAccessible = true
        val masterKeyBytes = mkField.get(container) as ByteArray
        assertTrue("masterKey should have non-zero bytes before close",
            masterKeyBytes.any { it != 0.toByte() })

        val xtsField = VolumeContainer::class.java.getDeclaredField("xtsMode")
        xtsField.isAccessible = true
        assertNotNull("xtsMode should be non-null before close", xtsField.get(container))

        container.close()

        // The captured byte array should now be zeroed (not just the reference nulled)
        assertTrue("masterKey bytes should be zeroed after close",
            masterKeyBytes.all { it == 0.toByte() })
        // References should be nulled
        assertNull("masterKey ref should be null after close", mkField.get(container))
        assertNull("xtsMode should be null after close", xtsField.get(container))
        assertNull("headerData should be null after close", container.getInfo())
    }

    // ── Non-AES via VolumeContainer ─────────────────────────────────────────

    @Test
    fun `create and open Serpent volume`() {
        val file = File(tempDir, "serpent.hc")
        val container = VolumeContainer(file)
        val size = 2L * 1024 * 1024 + VolumeConstants.VOLUME_HEADER_GROUP_SIZE
        container.create("pw".toCharArray(), size, encryptionAlg = EncryptionAlgorithm.SERPENT)

        val info = container.getInfo()!!
        assertEquals("Serpent", info.encryptionAlgorithm)
        container.close()

        // Re-open should work (parseHeader now tries all algorithms)
        val container2 = VolumeContainer(file)
        assertTrue("Should open Serpent volume", container2.open("pw".toCharArray()))
        assertEquals("Serpent", container2.getInfo()!!.encryptionAlgorithm)
        container2.close()
    }
}
