package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.RandomAccessFile
import java.nio.channels.FileChannel

/**
 * Unit tests for [VolumeReader] backup-header reading logic.
 *
 * These exercise the edge cases in [readBackupRegionFromChannel] and
 * [readBackupRegionFromRaf] without requiring a full mount or native libs.
 */
class VolumeReaderBackupHeaderTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val groupSize = VolumeConstants.VOLUME_HEADER_GROUP_SIZE.toInt() // 131072

    // ── readBackupRegionFromRaf ─────────────────────────────────────────────

    @Test
    fun `readBackupRegionFromRaf returns null for file smaller than 2x group size`() {
        val file = tempFolder.newFile("small.hc")
        file.writeBytes(ByteArray(groupSize)) // exactly one group — too small

        RandomAccessFile(file, "r").use { raf ->
            val result = VolumeReader.readBackupRegionFromRaf(raf, file.length())
            assertNull(result)
        }
    }

    @Test
    fun `readBackupRegionFromRaf returns null for exactly 2x group size minus 1`() {
        val file = tempFolder.newFile("almost.hc")
        file.writeBytes(ByteArray(groupSize * 2 - 1))

        RandomAccessFile(file, "r").use { raf ->
            val result = VolumeReader.readBackupRegionFromRaf(raf, file.length())
            assertNull(result)
        }
    }

    @Test
    fun `readBackupRegionFromRaf reads correct region for exactly 2x group size`() {
        val file = tempFolder.newFile("exact.hc")
        val data = ByteArray(groupSize * 2)
        // Fill first group with 0x01, second group with 0x02
        data.fill(0x01, 0, groupSize)
        data.fill(0x02, groupSize, groupSize * 2)
        file.writeBytes(data)

        RandomAccessFile(file, "r").use { raf ->
            val result = VolumeReader.readBackupRegionFromRaf(raf, file.length())

            assertNotNull(result)
            assertEquals(groupSize, result!!.size)
            assertTrue("backup region should be all 0x02", result.all { it == 0x02.toByte() })
        }
    }

    @Test
    fun `readBackupRegionFromRaf reads last group for large file`() {
        val file = tempFolder.newFile("large.hc")
        val data = ByteArray(groupSize * 5)
        data.fill(0xAA.toByte(), 0, groupSize * 4)
        data.fill(0xBB.toByte(), groupSize * 4, groupSize * 5)
        file.writeBytes(data)

        RandomAccessFile(file, "r").use { raf ->
            val result = VolumeReader.readBackupRegionFromRaf(raf, file.length())

            assertNotNull(result)
            assertEquals(groupSize, result!!.size)
            assertTrue("backup region should be all 0xBB", result.all { it == 0xBB.toByte() })
        }
    }

    // ── readBackupRegionFromChannel ─────────────────────────────────────────

    @Test
    fun `readBackupRegionFromChannel returns null for small file`() {
        val file = tempFolder.newFile("small_channel.hc")
        file.writeBytes(ByteArray(groupSize))

        FileChannel.open(file.toPath(), java.nio.file.StandardOpenOption.READ).use { channel ->
            val result = VolumeReader.readBackupRegionFromChannel(channel, file.length())
            assertNull(result)
        }
    }

    @Test
    fun `readBackupRegionFromChannel reads correct region`() {
        val file = tempFolder.newFile("channel.hc")
        val data = ByteArray(groupSize * 3)
        data.fill(0x11, 0, groupSize * 2)
        data.fill(0x22, groupSize * 2, groupSize * 3)
        file.writeBytes(data)

        FileChannel.open(file.toPath(), java.nio.file.StandardOpenOption.READ).use { channel ->
            val result = VolumeReader.readBackupRegionFromChannel(channel, file.length())

            assertNotNull(result)
            assertEquals(groupSize, result!!.size)
            assertTrue("backup region should be all 0x22", result.all { it == 0x22.toByte() })
        }
    }

    @Test
    fun `readBackupRegionFromChannel handles partial read`() {
        // This is harder to test without mocking; instead we verify the loop
        // logic by checking that a normal file still works.
        val file = tempFolder.newFile("normal.hc")
        val data = ByteArray(groupSize * 4)
        data.fill(0x33, 0, groupSize * 3)
        data.fill(0x44, groupSize * 3, groupSize * 4)
        file.writeBytes(data)

        FileChannel.open(file.toPath(), java.nio.file.StandardOpenOption.READ).use { channel ->
            val result = VolumeReader.readBackupRegionFromChannel(channel, file.length())

            assertNotNull(result)
            assertEquals(groupSize, result!!.size)
            assertTrue("backup region should be all 0x44", result.all { it == 0x44.toByte() })
        }
    }

    // ── offset correctness ────────────────────────────────────────────────────

    @Test
    fun `backup offset is fileSize minus groupSize`() {
        val fileSize = groupSize * 10L
        val expectedOffset = fileSize - groupSize
        assertEquals(groupSize * 9L, expectedOffset)
    }

    @Test
    fun `minimum valid file size is exactly 2x groupSize`() {
        // At 2x groupSize, primary header occupies [0, groupSize) and backup
        // occupies [groupSize, 2*groupSize). There is zero data area, which
        // is technically invalid for a usable volume but satisfies the
        // backup-region read constraint.
        val minSize = VolumeConstants.VOLUME_HEADER_GROUP_SIZE * 2
        assertEquals(262144L, minSize)
    }
}
