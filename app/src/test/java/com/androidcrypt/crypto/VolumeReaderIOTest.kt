package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

/**
 * Tests for VolumeReader sector-level I/O:
 * - readSector / readSectors / writeSector / writeSectors
 * - writeData / readData (byte-offset API)
 * - writeSectorsInPlace
 * - Boundary conditions (first sector, last sector, out-of-bounds)
 * - Unmount behavior (operations fail gracefully after unmount)
 * - Concurrent parallel reads
 */
class VolumeReaderIOTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_io_tests")
        private const val PASSWORD = "IOTestPassword!"
        private const val SECTOR_SIZE = 512
    }

    private lateinit var containerFile: File
    private lateinit var reader: VolumeReader

    @Before
    fun setUp() {
        TEST_DIR.mkdirs()
        containerFile = File(TEST_DIR, "io_test_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(containerFile.absolutePath, PASSWORD.toCharArray(), 10).getOrThrow()
        reader = VolumeReader(containerFile.absolutePath)
        reader.mount(PASSWORD.toCharArray()).getOrThrow()
    }

    @After
    fun tearDown() {
        try { reader.unmount() } catch (_: Exception) {}
        containerFile.delete()
        TEST_DIR.delete()
    }

    // ── Single sector read/write ────────────────────────────────────────────

    @Test
    fun `write and read single sector`() {
        val data = ByteArray(SECTOR_SIZE) { (it % 256).toByte() }
        reader.writeSector(0, data).getOrThrow()

        val readBack = reader.readSector(0).getOrThrow()
        assertArrayEquals("Single sector round-trip", data, readBack)
    }

    @Test
    fun `write and read sector at offset 100`() {
        val data = ByteArray(SECTOR_SIZE) { ((it * 3 + 7) % 256).toByte() }
        reader.writeSector(100, data).getOrThrow()

        val readBack = reader.readSector(100).getOrThrow()
        assertArrayEquals("Sector 100 round-trip", data, readBack)
    }

    @Test
    fun `sector data isolation - writing one sector does not affect neighbors`() {
        val data0 = ByteArray(SECTOR_SIZE) { 0xAA.toByte() }
        val data1 = ByteArray(SECTOR_SIZE) { 0xBB.toByte() }
        val data2 = ByteArray(SECTOR_SIZE) { 0xCC.toByte() }

        reader.writeSector(10, data0).getOrThrow()
        reader.writeSector(11, data1).getOrThrow()
        reader.writeSector(12, data2).getOrThrow()

        assertArrayEquals("Sector 10", data0, reader.readSector(10).getOrThrow())
        assertArrayEquals("Sector 11", data1, reader.readSector(11).getOrThrow())
        assertArrayEquals("Sector 12", data2, reader.readSector(12).getOrThrow())
    }

    // ── Multi-sector read/write ─────────────────────────────────────────────

    @Test
    fun `write and read multiple sectors`() {
        val sectorCount = 8
        val data = ByteArray(sectorCount * SECTOR_SIZE) { (it % 256).toByte() }
        reader.writeSectors(0, data).getOrThrow()

        val readBack = reader.readSectors(0, sectorCount).getOrThrow()
        assertArrayEquals("Multi-sector round-trip", data, readBack)
    }

    @Test
    fun `write and read 64 sectors`() {
        val sectorCount = 64
        val data = ByteArray(sectorCount * SECTOR_SIZE) { ((it * 13 + 5) % 256).toByte() }
        reader.writeSectors(50, data).getOrThrow()

        val readBack = reader.readSectors(50, sectorCount).getOrThrow()
        assertArrayEquals("64-sector round-trip", data, readBack)
    }

    // ── writeSectorsInPlace ─────────────────────────────────────────────────

    @Test
    fun `writeSectorsInPlace basic`() {
        val sectorCount = 4
        val data = ByteArray(sectorCount * SECTOR_SIZE) { (it % 256).toByte() }
        val expected = data.copyOf()
        reader.writeSectorsInPlace(0, data, 0, data.size).getOrThrow()

        val readBack = reader.readSectors(0, sectorCount).getOrThrow()
        assertArrayEquals("writeSectorsInPlace round-trip", expected, readBack)
    }

    @Test
    fun `writeSectorsInPlace with offset`() {
        // Write 2 sectors starting at byte offset 1024 within a larger array
        val fullArray = ByteArray(4 * SECTOR_SIZE) { (it % 256).toByte() }
        val expected = fullArray.copyOfRange(SECTOR_SIZE, 3 * SECTOR_SIZE)
        reader.writeSectorsInPlace(10, fullArray, SECTOR_SIZE, 2 * SECTOR_SIZE).getOrThrow()

        val readBack = reader.readSectors(10, 2).getOrThrow()
        assertArrayEquals("writeSectorsInPlace with offset", expected, readBack)
    }

    @Test
    fun `writeSectorsInPlace large - triggers parallel path`() {
        // 64 sectors should trigger the parallel encryption path (threshold is 32)
        val sectorCount = 64
        val data = ByteArray(sectorCount * SECTOR_SIZE) { ((it * 7) % 256).toByte() }
        val expected = data.copyOf()
        reader.writeSectorsInPlace(0, data, 0, data.size).getOrThrow()

        val readBack = reader.readSectors(0, sectorCount).getOrThrow()
        assertArrayEquals("Large writeSectorsInPlace round-trip", expected, readBack)
    }

    // ── Byte-offset writeData / readData ────────────────────────────────────

    @Test
    fun `writeData and readData at byte offset`() {
        val data = "Hello, raw data!".toByteArray()
        reader.writeData(1024, data).getOrThrow()  // byte offset 1024

        val readBack = reader.readData(1024, data.size).getOrThrow()
        assertArrayEquals("Byte-offset round-trip", data, readBack)
    }

    @Test
    fun `writeData at sector-unaligned offset`() {
        // Write at offset 100 (not sector-aligned) — should still work via read-modify-write
        val data = "unaligned".toByteArray()
        reader.writeData(100, data).getOrThrow()

        val readBack = reader.readData(100, data.size).getOrThrow()
        assertArrayEquals("Unaligned write", data, readBack)
    }

    // ── Boundary conditions ─────────────────────────────────────────────────

    @Test
    fun `read first sector`() {
        // Write known data to sector 0, then read it back
        val expected = ByteArray(SECTOR_SIZE) { 0x42 }
        reader.writeSector(0, expected).getOrThrow()

        val result = reader.readSector(0)
        assertTrue("Should read sector 0 successfully", result.isSuccess)
        val readBack = result.getOrThrow()
        assertEquals("Sector should be 512 bytes", SECTOR_SIZE, readBack.size)
        assertArrayEquals("Sector 0 content should match written data", expected, readBack)
    }

    @Test
    fun `writeSector with wrong size data fails`() {
        val tooSmall = ByteArray(100)
        val result = reader.writeSector(0, tooSmall)
        assertTrue("Wrong-size sector write should fail", result.isFailure)
    }

    @Test
    fun `writeSectors with non-sector-aligned data fails`() {
        val unaligned = ByteArray(SECTOR_SIZE + 100)
        val result = reader.writeSectors(0, unaligned)
        assertTrue("Unaligned multi-sector write should fail", result.isFailure)
    }

    // ── Unmount behavior ────────────────────────────────────────────────────

    @Test
    fun `read after unmount fails gracefully`() {
        reader.unmount()
        val result = reader.readSector(0)
        assertTrue("Read after unmount should fail", result.isFailure)
    }

    @Test
    fun `write after unmount fails gracefully`() {
        reader.unmount()
        val data = ByteArray(SECTOR_SIZE)
        val result = reader.writeSector(0, data)
        assertTrue("Write after unmount should fail", result.isFailure)
    }

    @Test
    fun `readSectors after unmount fails gracefully`() {
        reader.unmount()
        val result = reader.readSectors(0, 4)
        assertTrue("readSectors after unmount should fail", result.isFailure)
    }

    @Test
    fun `writeSectors after unmount fails gracefully`() {
        reader.unmount()
        val result = reader.writeSectors(0, ByteArray(4 * SECTOR_SIZE))
        assertTrue("writeSectors after unmount should fail", result.isFailure)
    }

    @Test
    fun `double unmount is safe`() {
        reader.unmount()
        // Second unmount should not throw
        reader.unmount()
        // Volume should still be in unmounted state — reads should fail
        assertTrue("Read after double unmount should fail", reader.readSector(0).isFailure)
    }

    @Test
    fun `sync after unmount is safe`() {
        reader.unmount()
        // Should not throw
        reader.sync()
        // Volume should still be in unmounted state
        assertTrue("Read after sync-after-unmount should fail", reader.readSector(0).isFailure)
    }

    // ── Data area info ──────────────────────────────────────────────────────

    @Test
    fun `mount info reports reasonable data area size`() {
        // Re-mount to get MountedVolumeInfo
        reader.unmount()
        reader = VolumeReader(containerFile.absolutePath)
        val info = reader.mount(PASSWORD.toCharArray()).getOrThrow()
        val sizeMB = info.getDataAreaSizeMB()
        // 10 MB container minus headers ≈ ~9.7 MB data area
        assertTrue("Data area should be > 9 MB", sizeMB >= 9)
        assertTrue("Data area should be <= 10 MB", sizeMB <= 10)
    }

    // ── Concurrent reads ────────────────────────────────────────────────────

    @Test
    fun `concurrent reads do not corrupt data`() {
        // Write known data to several sectors
        val sectors = 16
        val data = ByteArray(sectors * SECTOR_SIZE) { (it % 256).toByte() }
        reader.writeSectors(0, data).getOrThrow()

        // Read from multiple threads concurrently
        val threadCount = 4
        val latch = CountDownLatch(threadCount)
        val errors = CopyOnWriteArrayList<String>()
        val executor = Executors.newFixedThreadPool(threadCount)

        for (t in 0 until threadCount) {
            executor.execute {
                try {
                    for (iter in 0 until 10) {
                        val readBack = reader.readSectors(0, sectors).getOrThrow()
                        if (!readBack.contentEquals(data)) {
                            errors.add("Thread $t iter $iter: data mismatch")
                        }
                    }
                } catch (e: Exception) {
                    errors.add("Thread $t exception: ${e.message}")
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()
        assertTrue("Concurrent read errors: $errors", errors.isEmpty())
    }

    @Test
    fun `concurrent reads and writes`() {
        // Write initial data
        val sectors = 8
        val initialData = ByteArray(sectors * SECTOR_SIZE) { 0x00 }
        reader.writeSectors(0, initialData).getOrThrow()

        // Run readers and a writer concurrently — should not crash
        val threadCount = 4
        val latch = CountDownLatch(threadCount)
        val errors = CopyOnWriteArrayList<String>()
        val executor = Executors.newFixedThreadPool(threadCount)

        // 3 reader threads that validate content
        for (t in 0 until 3) {
            executor.execute {
                try {
                    for (iter in 0 until 20) {
                        val readBack = reader.readSectors(0, sectors).getOrThrow()
                        if (readBack.size != sectors * SECTOR_SIZE) {
                            errors.add("Reader $t iter $iter: wrong size ${readBack.size}")
                        }
                        // Verify each byte is either 0x00 (initial) or from the writer
                        // (writer writes to sectors 100+, so sectors 0-7 should stay 0x00)
                        if (!readBack.all { it == 0x00.toByte() }) {
                            errors.add("Reader $t iter $iter: sectors 0-7 modified unexpectedly")
                        }
                    }
                } catch (e: Exception) {
                    errors.add("Reader $t: ${e.message}")
                } finally {
                    latch.countDown()
                }
            }
        }

        // 1 writer thread writing to different sectors
        executor.execute {
            try {
                for (iter in 0 until 10) {
                    val d = ByteArray(SECTOR_SIZE) { iter.toByte() }
                    reader.writeSector((100 + iter).toLong(), d).getOrThrow()
                }
            } catch (e: Exception) {
                errors.add("Writer: ${e.message}")
            } finally {
                latch.countDown()
            }
        }

        latch.await()
        executor.shutdown()
        assertTrue("Concurrent R/W errors: $errors", errors.isEmpty())
    }

    // ── Additional boundary tests ───────────────────────────────────────────

    @Test
    fun `readSectors with count zero`() {
        val result = reader.readSectors(0, 0)
        // Zero sectors should succeed with empty array
        assertTrue("readSectors(0, 0) should succeed", result.isSuccess)
        assertEquals("Zero sectors should give empty data", 0, result.getOrThrow().size)
    }

    @Test
    fun `writeData spanning 3 sector boundaries`() {
        // Write data that spans from mid-sector across 3 sector boundaries
        val offset = 256L // mid-first-sector
        val data = ByteArray(SECTOR_SIZE * 3) { ((it * 11 + 5) % 256).toByte() }
        reader.writeData(offset, data).getOrThrow()

        val readBack = reader.readData(offset, data.size).getOrThrow()
        assertArrayEquals("Cross-boundary write/read", data, readBack)
    }

    @Test
    fun `readData with length zero`() {
        val result = reader.readData(0, 0)
        // Zero-length read should succeed with empty array
        assertTrue("readData(0, 0) should succeed", result.isSuccess)
        assertEquals("Zero-length read should give empty data", 0, result.getOrThrow().size)
    }

    @Test
    fun `write and read at high sector offset`() {
        // Write to a sector far into the data area
        val sectorNum = 1000L
        val data = ByteArray(SECTOR_SIZE) { 0x77 }
        reader.writeSector(sectorNum, data).getOrThrow()

        val readBack = reader.readSector(sectorNum).getOrThrow()
        assertArrayEquals("High-sector round-trip", data, readBack)
    }

    // ── Out-of-bounds ────────────────────────────────────────────────────────

    @Test
    fun `readSector beyond volume bounds fails`() {
        // Data area is ~10MB ≈ ~20000 sectors; sector 1_000_000 is way out of bounds
        val result = reader.readSector(1_000_000L)
        assertTrue("Out-of-bounds read should fail", result.isFailure)
    }

    @Test
    fun `writeSector beyond volume bounds fails`() {
        val data = ByteArray(SECTOR_SIZE) { 0x42 }
        val result = reader.writeSector(1_000_000L, data)
        assertTrue("Out-of-bounds write should fail", result.isFailure)
    }

    @Test
    fun `readSectors spanning past end fails`() {
        // Read starting at a valid sector but requesting too many
        val result = reader.readSectors(18_000, 5000)
        assertTrue("Read spanning past volume end should fail", result.isFailure)
    }

    @Test
    fun `writeSectors spanning past end fails`() {
        val data = ByteArray(5000 * SECTOR_SIZE)
        val result = reader.writeSectors(18_000, data)
        assertTrue("Write spanning past volume end should fail", result.isFailure)
    }

    // ── Read-modify-write integrity ──────────────────────────────────────────

    @Test
    fun `writeData at unaligned offset preserves surrounding data`() {
        // Write known data to sector 0
        val sectorData = ByteArray(SECTOR_SIZE) { (it % 256).toByte() }
        reader.writeSector(0, sectorData).getOrThrow()

        // Now write 10 bytes at offset 100 (mid-sector) via writeData
        val patch = ByteArray(10) { 0xFF.toByte() }
        reader.writeData(100, patch).getOrThrow()

        // Read the full sector back
        val readBack = reader.readSector(0).getOrThrow()

        // Bytes 0-99 should be unchanged
        for (i in 0 until 100) {
            assertEquals("Byte $i should be preserved", sectorData[i], readBack[i])
        }
        // Bytes 100-109 should be the patch
        for (i in 0 until 10) {
            assertEquals("Byte ${100 + i} should be patched", 0xFF.toByte(), readBack[100 + i])
        }
        // Bytes 110-511 should be unchanged
        for (i in 110 until SECTOR_SIZE) {
            assertEquals("Byte $i should be preserved", sectorData[i], readBack[i])
        }
    }

    // ── Concurrent same-sector writes ────────────────────────────────────────

    @Test
    fun `concurrent writes to same sector do not corrupt file`() {
        val targetSector = 50L
        val threadCount = 4
        val iterationsPerThread = 20
        val latch = CountDownLatch(threadCount)
        val errors = CopyOnWriteArrayList<String>()
        val executor = Executors.newFixedThreadPool(threadCount)

        for (t in 0 until threadCount) {
            executor.execute {
                try {
                    for (iter in 0 until iterationsPerThread) {
                        val data = ByteArray(SECTOR_SIZE) { ((t * 37 + iter) % 256).toByte() }
                        reader.writeSector(targetSector, data).getOrThrow()
                    }
                } catch (e: Exception) {
                    errors.add("Thread $t: ${e.message}")
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        executor.shutdown()
        assertTrue("Concurrent same-sector write errors: $errors", errors.isEmpty())

        // After all writes, the sector should contain valid data from one of the writers
        // (not corrupted). Read it back and verify it matches one of the known patterns.
        val final_ = reader.readSector(targetSector).getOrThrow()
        assertEquals("Sector should be 512 bytes", SECTOR_SIZE, final_.size)
        // Each writer wrote ByteArray(SECTOR_SIZE) { ((t * 37 + iter) % 256).toByte() }
        // The final content must match one such pattern (all bytes identical modulo pattern)
        val firstByte = final_[0]
        val isConsistentPattern = final_.all { it == firstByte }
        assertTrue(
            "Sector content should be a consistent pattern from one writer, not corrupted",
            isConsistentPattern
        )
    }

    // ── Unmount key zeroing ──────────────────────────────────────────────────

    @Test
    fun `unmount nulls key material and XTS context`() {
        // After mount(), masterKey is deliberately zeroed and nulled (L-2 security fix)
        // — the key material lives only in the native XTS key schedules.
        // Verify masterKey is already null (proving the L-2 fix is active).
        val mkField = VolumeReader::class.java.getDeclaredField("masterKey")
        mkField.isAccessible = true
        assertNull("masterKey should already be null after mount (L-2 security fix)", mkField.get(reader))

        // xtsMode should be non-null (holds the native key schedules)
        val xtsField = VolumeReader::class.java.getDeclaredField("xtsMode")
        xtsField.isAccessible = true
        assertNotNull("xtsMode should be set before unmount", xtsField.get(reader))

        // Verify the volume is functional before unmount
        val readResult = reader.readSector(0)
        assertTrue("Should be able to read before unmount", readResult.isSuccess)

        reader.unmount()

        // After unmount, xtsMode should be nulled (and its close() called to zero native key schedules)
        assertNull("xtsMode should be null after unmount", xtsField.get(reader))
        assertNull("masterKey should remain null after unmount", mkField.get(reader))
        assertNull("volumeInfo should be null after unmount", reader.volumeInfo)

        // Verify the volume is no longer functional
        val postResult = reader.readSector(0)
        assertTrue("Should fail to read after unmount", postResult.isFailure)
    }
}
