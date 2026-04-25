package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * **FAT32 boundary-condition PBTs.** Targets edge cases the existing PBTs
 * don't directly hit:
 *
 *   - **T20** the very last addressable cluster (N+1) is allocatable, can
 *     be written to, and the bytes survive a remount.
 *   - **T23** a directory's own chain spans more than one cluster when
 *     enough entries are added.
 *   - **T24** zero-byte files: `firstCluster == 0`, no allocation, round-
 *     trips correctly through write/read/remount.
 *   - **T25** `moveEntry` preserves the file's cluster chain and content
 *     byte-for-byte.
 *   - **T35** filling the volume to capacity returns a clean failure on
 *     the next write, leaves on-disk state consistent.
 */
class FAT32BoundaryPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_boundary_pbt")
        private const val PASSWORD = "BoundaryPBT!"

        @BeforeClass @JvmStatic fun setUp() { TEST_DIR.mkdirs() }
        @AfterClass @JvmStatic fun tearDown() {
            TEST_DIR.listFiles()?.forEach { it.delete() }
            TEST_DIR.delete()
        }
    }

    private data class Volume(val container: File, val reader: VolumeReader, val fs: FAT32Reader,
                              val bytesPerSector: Int, val sectorsPerCluster: Int,
                              val reservedSectors: Int, val numFATs: Int, val sectorsPerFAT: Long,
                              val totalClusters: Int, val clusterBytes: Int)

    private fun openVolume(sizeMb: Long, tag: String): Volume {
        val f = File(TEST_DIR, "${tag}_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(f.absolutePath, PASSWORD.toCharArray(), sizeMb).getOrThrow()
        val r = VolumeReader(f.absolutePath); r.mount(PASSWORD.toCharArray()).getOrThrow()
        val fs = FAT32Reader(r); fs.initialize().getOrThrow()
        val bs = r.readSector(0).getOrThrow()
        val bps = (bs[11].toInt() and 0xFF) or ((bs[12].toInt() and 0xFF) shl 8)
        val spc = bs[13].toInt() and 0xFF
        val rsv = (bs[14].toInt() and 0xFF) or ((bs[15].toInt() and 0xFF) shl 8)
        val nfat = bs[16].toInt() and 0xFF
        val spfat = ByteBuffer.wrap(bs, 36, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
        val totalSectors = ByteBuffer.wrap(bs, 32, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
        val firstDataSector = rsv + nfat * spfat
        val totalClusters = ((totalSectors - firstDataSector) / spc).toInt()
        return Volume(f, r, fs, bps, spc, rsv, nfat, spfat, totalClusters, spc * bps)
    }

    private fun closeVolume(v: Volume) {
        try { v.reader.unmount() } catch (_: Exception) {}
        v.container.delete()
    }

    /** Walk a chain starting at [start], return the set of clusters visited. */
    private fun walkChain(v: Volume, start: Int): Set<Int> {
        val s = LinkedHashSet<Int>()
        var c = start
        while (c in 2..(v.totalClusters + 1) && c < 0x0FFFFFF8) {
            if (!s.add(c)) break  // cycle guard
            val fatOff = v.reservedSectors.toLong() + (c.toLong() * 4) / v.bytesPerSector
            val sec = v.reader.readSector(fatOff).getOrThrow()
            val byteInSec = ((c.toLong() * 4) % v.bytesPerSector).toInt()
            c = ByteBuffer.wrap(sec, byteInSec, 4).order(ByteOrder.LITTLE_ENDIAN).int and 0x0FFFFFFF
        }
        return s
    }

    // ── T20 ─────────────────────────────────────────────────────────────────
    /**
     * Fill the volume with a single large file so the very last data cluster
     * (cluster index N+1) is allocated. Then verify (a) the cluster chain
     * actually contains cluster N+1, (b) the file's byte content survives an
     * unmount/remount cycle.
     */
    @Test
    fun `last addressable cluster N+1 is allocatable and persists across remount`(): Unit = runBlocking {
        val v = openVolume(4L, "lastcluster")
        try {
            val freeBefore = v.fs.countFreeClusters()
            // Write a payload whose size occupies *all* free clusters. Round
            // down to a clean cluster boundary so we don't run into the
            // partial-last-cluster case (still tested below).
            val payloadSize = freeBefore.toLong() * v.clusterBytes
            val payload = ByteArray(payloadSize.toInt()).also {
                java.util.Random(0xBEEFL).nextBytes(it)
            }
            v.fs.createFile("/", "fill.bin").getOrThrow()
            v.fs.writeFile("/fill.bin", payload).getOrThrow()
            v.reader.sync()

            val info = v.fs.getFileInfoWithClusterPublic("/fill.bin").getOrThrow()
            val chain = walkChain(v, info.firstCluster)
            assertEquals(
                "expected file to occupy all free clusters; " +
                        "freeBefore=$freeBefore chain=${chain.size}",
                freeBefore, chain.size
            )
            assertTrue(
                "file chain does not include the last addressable cluster N+1=" +
                        "${v.totalClusters + 1}; chain max=${chain.max()}, " +
                        "totalClusters=${v.totalClusters}. The off-by-one bug fix " +
                        "must let the last cluster actually get allocated.",
                (v.totalClusters + 1) in chain
            )
            assertEquals(
                "free count not zero after fill",
                0, v.fs.countFreeClusters()
            )

            // Remount and read back.
            v.reader.unmount()
            val r2 = VolumeReader(v.container.absolutePath)
            r2.mount(PASSWORD.toCharArray()).getOrThrow()
            val fs2 = FAT32Reader(r2); fs2.initialize().getOrThrow()
            try {
                val readBack = fs2.readFile("/fill.bin").getOrThrow()
                assertArrayEquals(
                    "filled-volume payload corrupted across remount " +
                            "(includes last cluster N+1=${v.totalClusters + 1})",
                    payload, readBack
                )
            } finally { try { r2.unmount() } catch (_: Exception) {} }
        } finally { closeVolume(v) }
    }

    // ── T35 ─────────────────────────────────────────────────────────────────
    @Test
    fun `writing past free space fails cleanly without breaking the filesystem`(): Unit = runBlocking {
        val v = openVolume(4L, "exhaust")
        try {
            // Fill to capacity
            val freeBefore = v.fs.countFreeClusters()
            val fillSize = freeBefore.toLong() * v.clusterBytes
            val fill = ByteArray(fillSize.toInt())
            v.fs.createFile("/", "fill.bin").getOrThrow()
            v.fs.writeFile("/fill.bin", fill).getOrThrow()
            v.reader.sync()
            assertEquals("fill should consume all clusters", 0, v.fs.countFreeClusters())

            // Now try one more write — must fail (no clusters left).
            v.fs.createFile("/", "overflow.bin").getOrThrow()
            val overflowResult = v.fs.writeFile("/overflow.bin", ByteArray(v.clusterBytes))
            assertTrue(
                "writeFile beyond free space should fail; got success",
                overflowResult.isFailure
            )

            // Filesystem must still be intact: original fill file survives
            // and remount works.
            v.reader.sync()
            v.reader.unmount()
            val r2 = VolumeReader(v.container.absolutePath)
            assertTrue(
                "remount failed after free-space exhaustion — out-of-space path corrupted FS",
                r2.mount(PASSWORD.toCharArray()).isSuccess
            )
            try {
                val fs2 = FAT32Reader(r2); fs2.initialize().getOrThrow()
                val rb = fs2.readFile("/fill.bin").getOrThrow()
                assertEquals(
                    "fill file size changed after a failed overflow write",
                    fillSize.toInt(), rb.size
                )
            } finally { try { r2.unmount() } catch (_: Exception) {} }
        } finally { closeVolume(v) }
    }

    // ── T23 ─────────────────────────────────────────────────────────────────
    /**
     * One FAT32 directory cluster of 4 KB holds 4096/32 = 128 directory
     * entries. With LFN, each user-visible name typically consumes 2-3
     * 32-byte slots. Writing >100 long-named files should force the
     * directory's own chain to grow into a second cluster.
     */
    @Test
    fun `directory chain grows past one cluster as entries are added`(): Unit = runBlocking {
        val v = openVolume(8L, "dirgrow")
        try {
            v.fs.createDirectory("/", "big").getOrThrow()
            val dirInfo0 = v.fs.getFileInfoWithClusterPublic("/big").getOrThrow()
            val initialChainLen = walkChain(v, dirInfo0.firstCluster).size
            assertEquals("freshly-created directory should occupy exactly 1 cluster",
                1, initialChainLen)

            // Use long names so each entry consumes ≥ 2 32-byte slots.
            val n = 200
            for (i in 1..n) {
                v.fs.createFile("/big", "long_name_for_directory_growth_$i.bin").getOrThrow()
            }
            v.reader.sync()
            val dirInfoNow = v.fs.getFileInfoWithClusterPublic("/big").getOrThrow()
            val chainNow = walkChain(v, dirInfoNow.firstCluster)
            assertTrue(
                "directory chain only ${chainNow.size} cluster(s) after $n LFN entries; " +
                        "expected >= 2. Either dir-grow path is broken or each entry " +
                        "is consuming fewer slots than expected.",
                chainNow.size >= 2
            )
            // All entries listable
            val listed = v.fs.listDirectory("/big").getOrThrow().map { it.name }.toSet()
            for (i in 1..n) {
                assertTrue("entry $i missing after dir grew across clusters",
                    "long_name_for_directory_growth_$i.bin" in listed)
            }
        } finally { closeVolume(v) }
    }

    // ── T24 ─────────────────────────────────────────────────────────────────
    @Test
    fun `zero-byte file allocates no cluster and round-trips`(): Unit = runBlocking {
        val v = openVolume(4L, "empty")
        try {
            val freeBefore = v.fs.countFreeClusters()
            v.fs.createFile("/", "empty.bin").getOrThrow()
            v.fs.writeFile("/empty.bin", ByteArray(0)).getOrThrow()
            v.reader.sync()

            val info = v.fs.getFileInfoWithClusterPublic("/empty.bin").getOrThrow()
            assertEquals(
                "zero-byte file size should be 0 (got ${info.size})",
                0L, info.size
            )
            assertEquals(
                "zero-byte file should NOT have a first cluster (got ${info.firstCluster})",
                0, info.firstCluster
            )
            val freeAfter = v.fs.countFreeClusters()
            assertEquals(
                "zero-byte file allocated ${freeBefore - freeAfter} cluster(s) — " +
                        "should be zero",
                freeBefore, freeAfter
            )

            // Remount + read returns empty array
            v.reader.unmount()
            val r2 = VolumeReader(v.container.absolutePath)
            r2.mount(PASSWORD.toCharArray()).getOrThrow()
            val fs2 = FAT32Reader(r2); fs2.initialize().getOrThrow()
            try {
                val rb = fs2.readFile("/empty.bin").getOrThrow()
                assertEquals("zero-byte file came back non-empty", 0, rb.size)
            } finally { try { r2.unmount() } catch (_: Exception) {} }
        } finally { closeVolume(v) }
    }

    // ── T25 ─────────────────────────────────────────────────────────────────
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `moveEntry preserves cluster chain and content`(): Unit = runBlocking {
        val v = openVolume(4L, "move")
        try {
            v.fs.createDirectory("/", "src").getOrThrow()
            v.fs.createDirectory("/", "dst").getOrThrow()
            checkAll(
                PropTestConfig(iterations = 4, seed = 0xC0DEDA7AL),
                Arb.byteArray(Arb.int(64, 16_384), Arb.byte()),
            ) { payload ->
                val name = "f_${System.nanoTime()}.bin"
                val src = "/src/$name"
                val dst = "/dst/$name"
                v.fs.createFile("/src", name).getOrThrow()
                v.fs.writeFile(src, payload).getOrThrow()
                v.reader.sync()
                val infoBefore = v.fs.getFileInfoWithClusterPublic(src).getOrThrow()
                val chainBefore = walkChain(v, infoBefore.firstCluster)

                val moveRes = v.fs.moveEntry(src, "/dst")
                assertTrue("moveEntry failed: ${moveRes.exceptionOrNull()?.message}", moveRes.isSuccess)
                v.reader.sync()

                assertFalse("source still exists after move", v.fs.exists(src))
                assertTrue("destination missing after move", v.fs.exists(dst))

                val infoAfter = v.fs.getFileInfoWithClusterPublic(dst).getOrThrow()
                assertEquals(
                    "moveEntry must preserve firstCluster (rename of dirent only)",
                    infoBefore.firstCluster, infoAfter.firstCluster
                )
                val chainAfter = walkChain(v, infoAfter.firstCluster)
                assertEquals("cluster chain changed across moveEntry",
                    chainBefore, chainAfter)
                val readBack = v.fs.readFile(dst).getOrThrow()
                assertArrayEquals(
                    "content corrupted across moveEntry",
                    payload, readBack
                )
                v.fs.delete(dst).getOrNull()
                v.reader.sync()
            }
        } finally { closeVolume(v) }
    }
}
