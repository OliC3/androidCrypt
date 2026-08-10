package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Regression test for issue #13 — plausible deniability of the free-space
 * display.
 *
 * Mounting the OUTER volume must show the same free space before and after a
 * hidden volume is created inside the container. If the hidden area were
 * subtracted (or marked allocated in the outer FAT), the drop in displayed
 * free space would exactly equal the hidden volume's size and thereby reveal
 * its existence to anyone reading the numbers.
 *
 * (The reporter's "Free: 1 GB" on a 2048/1024 MB setup was actually integer
 * truncation in the UI's size formatter — 1824 MB rendered as "1 GB"; see
 * FormatFileSizeTest. This test guards the real invariant underneath: the
 * FAT-level free count must not change when a hidden volume is created.)
 */
class HiddenVolumeFreeSpaceTest {

    private val testDir = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_hidden_freespace")
    private lateinit var containerFile: File

    @Before
    fun setUp() {
        testDir.mkdirs()
        containerFile = File(testDir, "hidden_${System.nanoTime()}.hc")
    }

    @After
    fun tearDown() {
        containerFile.delete()
    }

    private fun mountOuterAndMeasure(): Triple<Long, Long, VolumeReader> {
        val reader = VolumeReader(containerFile.absolutePath)
        reader.mount("OuterPass!".toCharArray()).getOrThrow()
        val fs = FAT32Reader(reader)
        fs.initialize().getOrThrow()
        val freeBytes = fs.countFreeClusters().toLong() * fs.getClusterSize()
        val totalBytes = fs.getTotalSpaceBytes()
        return Triple(freeBytes, totalBytes, reader)
    }

    @Test
    fun `outer mount free space does not subtract hidden volume`() {
        val outerMB = 48L
        val hiddenMB = 16L

        VolumeCreator.createContainer(
            containerFile.absolutePath, "OuterPass!".toCharArray(), outerMB
        ).getOrThrow()

        val (freeBefore, totalBefore, r1) = mountOuterAndMeasure()
        r1.unmount()

        VolumeCreator.createHiddenVolume(
            containerPath = containerFile.absolutePath,
            outerPassword = "OuterPass!".toCharArray(),
            hiddenPassword = "HiddenPass!".toCharArray(),
            hiddenSizeInMB = hiddenMB
        ).getOrThrow()

        // Mount OUTER again — free space must be (nearly) unchanged.
        val (freeAfter, totalAfter, r2) = mountOuterAndMeasure()
        r2.unmount()

        assertEquals("total space changed after hidden creation", totalBefore, totalAfter)
        // A tiny drop is fine (a cluster or two of slack at most), but dropping
        // ~the hidden volume size (16 MB here) would leak its existence.
        val drop = freeBefore - freeAfter
        assertTrue(
            "Outer free space dropped by ${drop / 1024} KB after hidden volume " +
                "creation — reveals the ${hiddenMB} MB hidden volume",
            drop < hiddenMB * 1024 * 1024 / 4
        )
    }
}
