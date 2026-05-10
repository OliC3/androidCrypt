package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Property-based tests that exercise three orthogonal aspects of
 * [FAT32Reader] beyond what [FAT32StatefulPropertyTest] covers:
 *
 *   • [`writeFile equals writeFileStreaming`]
 *     For arbitrary payloads, the two write paths must produce
 *     bit-identical files. They use different code (whole-buffer write vs
 *     chunked stream write into the FAT chain), so any divergence is a
 *     bug. This is a regression target for the 2-phase write architecture
 *     that was introduced under the writeLock — easy to get wrong on edge
 *     payload lengths (cluster boundaries, sector boundaries, empty data).
 *
 *   • [`countFreeClusters matches direct FAT scan`]
 *     The cached / cluster-prefetch implementation in `countFreeClusters`
 *     must agree with a brute-force scan of the FAT region read directly
 *     from disk via `volumeReader.readSectors`. Drift between these two
 *     numbers caused user-visible "free space" bugs in the past.
 *
 *   • [`concurrent reader observes only complete writes`]
 *     A second thread reading a file under continuous overwriting must
 *     never observe a torn payload — at any moment it sees either a
 *     previous full payload or the new full payload, never a half-applied
 *     mix. This is a stress test for the H-3 sync ordering and the
 *     2-phase metadata/data write split.
 *
 * The container is created once per test class to amortise the multi-second
 * format / mount cost.
 */
class FAT32AdditionalPropertyTests {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_fat32_extra_pbt")
        private const val PASSWORD = "FAT32ExtraPBT!"
        private lateinit var containerFile: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader

        // Geometry (parsed from BPB).
        private var bytesPerSector: Int = 0
        private var reservedSectors: Int = 0
        private var numFATs: Int = 0
        private var sectorsPerFAT: Long = 0
        private var sectorsPerCluster: Int = 0
        private var totalSectors: Long = 0

        @BeforeClass
        @JvmStatic
        fun classSetUp() {
            TEST_DIR.mkdirs()
            containerFile = File(TEST_DIR, "fat32_extra_pbt_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(
                containerFile.absolutePath, PASSWORD.toCharArray(), 12
            ).getOrThrow()
            reader = VolumeReader(containerFile.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()

            val bs = reader.readSector(0).getOrThrow()
            bytesPerSector = (bs[11].toInt() and 0xFF) or ((bs[12].toInt() and 0xFF) shl 8)
            sectorsPerCluster = bs[13].toInt() and 0xFF
            reservedSectors = (bs[14].toInt() and 0xFF) or ((bs[15].toInt() and 0xFF) shl 8)
            numFATs = bs[16].toInt() and 0xFF
            sectorsPerFAT = ((bs[36].toLong() and 0xFF)
                or ((bs[37].toLong() and 0xFF) shl 8)
                or ((bs[38].toLong() and 0xFF) shl 16)
                or ((bs[39].toLong() and 0xFF) shl 24))
            totalSectors = ((bs[32].toLong() and 0xFF)
                or ((bs[33].toLong() and 0xFF) shl 8)
                or ((bs[34].toLong() and 0xFF) shl 16)
                or ((bs[35].toLong() and 0xFF) shl 24))
        }

        @AfterClass
        @JvmStatic
        fun classTearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            containerFile.delete()
            TEST_DIR.delete()
        }
    }

    // Common helpers ─────────────────────────────────────────────────────────

    private fun payloadArb(maxBytes: Int = 8 * 1024): Arb<ByteArray> =
        Arb.byteArray(Arb.int(0, maxBytes), Arb.byte())

    private fun cleanWorkdir(workdir: String) {
        runCatching {
            for (e in fs.listDirectory(workdir).getOrThrow()) {
                fs.delete("$workdir/${e.name}")
            }
            fs.delete(workdir)
        }
    }

    // ── Property: writeFile == writeFileStreaming ──────────────────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `writeFile and writeFileStreaming produce identical bytes`(): Unit = runBlocking {
        val workdir = "/eq_test"
        fs.createDirectory("/", "eq_test").getOrThrow()
        try {
            checkAll(
                PropTestConfig(iterations = 24, seed = 0x57EA31D6L),
                payloadArb(),
            ) { payload ->
                val pathBulk = "$workdir/bulk.bin"
                val pathStream = "$workdir/stream.bin"

                if (fs.exists(pathBulk)) fs.delete(pathBulk).getOrThrow()
                if (fs.exists(pathStream)) fs.delete(pathStream).getOrThrow()

                fs.createFile(workdir, "bulk.bin").getOrThrow()
                fs.writeFile(pathBulk, payload).getOrThrow()

                fs.createFile(workdir, "stream.bin").getOrThrow()
                fs.writeFileStreaming(
                    path = pathStream,
                    inputStream = payload.inputStream(),
                    fileSize = payload.size.toLong(),
                    onProgress = null,
                ).getOrThrow()

                val readBulk = fs.readFile(pathBulk).getOrThrow()
                val readStream = fs.readFile(pathStream).getOrThrow()
                assertArrayEquals(
                    "writeFile vs writeFileStreaming diverged at size=${payload.size}",
                    readBulk, readStream
                )
                assertArrayEquals("bulk read != original (size=${payload.size})", payload, readBulk)
                assertArrayEquals("stream read != original (size=${payload.size})", payload, readStream)
            }
        } finally {
            cleanWorkdir(workdir)
        }
    }

    // ── Property: on-disk free count is restored by write+delete ───────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `on-disk FAT scan restores after write+delete`(): Unit = runBlocking {
        // Pure on-disk invariant — sidesteps the cached free-cluster scalar
        // (which is decremented at allocation time, before the FAT entries
        // are committed; a parallel verification of the cache/disk
        // coherence is left to a future deep-dive). Direct FAT scan must
        // see exactly the same number of free entries before vs after a
        // (createFile, writeFile, delete) trio. This is the regression
        // test that pairs with the freeClusters() fix that frees the
        // file's data chain on delete (without it, every iteration would
        // permanently lose `ceil(payload/clusterSize)` clusters).
        val workdir = "/fc_test"
        fs.createDirectory("/", "fc_test").getOrThrow()
        try {
            checkAll(
                PropTestConfig(iterations = 12, seed = 0xF1EE0001L),
                payloadArb(maxBytes = 6 * 1024),
            ) { payload ->
                val name = "f.bin"
                val path = "$workdir/$name"
                if (fs.exists(path)) fs.delete(path).getOrThrow()
                val before = scanFreeClusters()
                fs.createFile(workdir, name).getOrThrow()
                fs.writeFile(path, payload).getOrThrow()
                val mid = scanFreeClusters()
                fs.delete(path).getOrThrow()
                val after = scanFreeClusters()

                // Every byte written must consume at least zero clusters and
                // at most ceil(size/clusterSize)+1 (the +1 accounts for
                // potential one-time directory growth).
                val clusterBytes = sectorsPerCluster * bytesPerSector
                val maxConsumed = ((payload.size + clusterBytes - 1) / clusterBytes) + 1
                val consumed = before - mid
                assertTrue(
                    "implausible cluster consumption: $consumed for ${payload.size}B " +
                        "(clusterBytes=$clusterBytes, max=$maxConsumed)",
                    consumed in 0..maxConsumed
                )

                // After delete, free count must recover to its pre-write
                // value. Any drift means delete() leaked data clusters
                // (the bug fixed by H-3 era work).
                assertEquals(
                    "FAT scan free-count drifted after write+delete of ${payload.size}B " +
                        "(before=$before mid=$mid after=$after)",
                    before, after
                )
            }
        } finally {
            cleanWorkdir(workdir)
        }
    }

    /** Read FAT1 directly from sector storage and count entries equal to 0
     *  (skipping the two reserved entries at indices 0 and 1, and any
     *  trailing entries beyond the addressable cluster range). */
    private fun scanFreeClusters(): Int {
        // The FAT region is rounded up to a whole number of sectors, so it
        // typically contains a few "extra" entries past the last addressable
        // cluster. Those entries are always 0 but do NOT correspond to real
        // clusters and must NOT be counted as free \u2014 otherwise this scan
        // disagrees with countFreeClusters() (which iterates 2..totalClusters).
        val firstDataSector = reservedSectors + numFATs * sectorsPerFAT
        val totalClusters = ((totalSectors - firstDataSector) / sectorsPerCluster).toInt()
        // Valid FAT entry indices for real clusters: 2 .. totalClusters+1
        // inclusive (totalClusters is the *count* of data clusters; cluster
        // numbers run 2..N+1 because entries 0 and 1 are reserved). The FAT
        // may have trailing slack entries beyond cluster totalClusters+1 —
        // those must NOT be counted.
        val lastValidEntryIndex = totalClusters + 1
        var free = 0
        var sectorOffset: Long = 0
        var entryIndex = 0
        val chunkSectors = 32
        var remaining = sectorsPerFAT
        while (remaining > 0) {
            val n = minOf(remaining, chunkSectors.toLong()).toInt()
            val data = reader.readSectors(reservedSectors + sectorOffset, n).getOrThrow()
            val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            val entriesInChunk = (n * bytesPerSector) / 4
            for (i in 0 until entriesInChunk) {
                val v = buf.int and 0x0FFFFFFF
                if (entryIndex in 2..lastValidEntryIndex && v == 0) free++
                entryIndex++
            }
            sectorOffset += n
            remaining -= n
        }
        return free
    }

    // ── Property: cached free-cluster count == on-disk FAT scan ────────────

    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `cached free-cluster count matches on-disk FAT scan`(): Unit = runBlocking {
        // After every mutation the cached scalar (returned by
        // countFreeClusters) MUST equal the number of zero entries in the
        // on-disk FAT region. Drift here is a real bug \u2014 it manifests as
        // bogus "not enough space" errors or, in the other direction, as
        // overwriting clusters that the cache still thinks are free.
        // We do NOT pre-invalidate the cache: the whole point of this
        // property is to verify that the INCREMENTAL cache updates inside
        // allocateClusters() and freeClusters() stay coherent with the FAT.
        val workdir = "/cc_parity"
        if (fs.exists(workdir)) fs.delete(workdir).getOrThrow()
        fs.createDirectory("/", "cc_parity").getOrThrow()
        try {
            checkAll(
                PropTestConfig(iterations = 16, seed = 0xCACE0001L),
                payloadArb(maxBytes = 6 * 1024),
            ) { payload ->
                val name = "p.bin"
                val path = "$workdir/$name"
                if (fs.exists(path)) fs.delete(path).getOrThrow()

                fun assertParity(label: String) {
                    val cached = fs.countFreeClusters()
                    val onDisk = scanFreeClusters()
                    assertEquals(
                        "[$label] cache vs FAT drift (size=${payload.size})",
                        onDisk, cached
                    )
                }

                assertParity("before-create")
                fs.createFile(workdir, name).getOrThrow()
                assertParity("after-create")
                fs.writeFile(path, payload).getOrThrow()
                assertParity("after-write")
                fs.delete(path).getOrThrow()
                assertParity("after-delete")
            }
        } finally {
            cleanWorkdir(workdir)
        }
    }

    // ── Regression: delete frees clusters when directoryCache is stale ─────

    /**
     * Regression test for the bug where delete() leaked all data clusters
     * because getFileInfoWithCluster returned a stale directoryCache entry
     * with firstCluster=0, causing the `if (firstCluster >= 2)` guard to
     * skip freeClusters entirely.
     *
     * The scenario (matches what happens via SAF when a file picker lists a
     * directory, a user copies a file in, then deletes it):
     *   1. createFile     → dir entry on disk has firstCluster=0
     *   2. listDirectory  → populates directoryCache with that entry
     *   3. Data is written ON DISK (firstCluster updated), but
     *      directoryCache still holds the stale firstCluster=0 entry
     *   4. delete() is called
     *
     * Step (3) is reproduced by writing directly via volumeReader so that
     * no FAT32Reader cache is invalidated — the stale directoryCache
     * entry from step (2) survives untouched.
     */
    @Test
    fun `delete frees clusters when directory cache holds stale firstCluster`() {
        val workdir = "/sc_test"
        fs.createDirectory("/", "sc_test").getOrThrow()
        try {
            val name = "s.bin"
            val path = "$workdir/$name"
            val clusterBytes = sectorsPerCluster * bytesPerSector
            val firstDataSector = reservedSectors + numFATs * sectorsPerFAT
            val fatStart = reservedSectors.toLong()

            val before = scanFreeClusters()

            // Step 1: create the file entry (firstCluster=0 on disk).
            fs.createFile(workdir, name).getOrThrow()

            // Step 2: list the workdir — directoryCache now holds an entry
            //         with firstCluster=0.
            val entries1 = fs.listDirectory(workdir).getOrThrow()
            val staleEntry = entries1.find { it.name == name }
            assertTrue("entry must be found after createFile", staleEntry != null)
            assertEquals(
                "stale cache entry must have firstCluster=0 before write",
                0, staleEntry!!.firstCluster
            )

            // Step 3: allocate ONE cluster ON DISK, going around FAT32Reader
            // entirely so that directoryCache is never invalidated.

            // 3a. Find a free cluster in FAT sector 0.
            val fatSector = reader.readSector(fatStart).getOrThrow()
            val buf = java.nio.ByteBuffer.wrap(fatSector).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            var allocatedCluster = -1
            for (c in 3..999) {
                val v = buf.getInt(c * 4) and 0x0FFFFFFF
                if (v == 0) { allocatedCluster = c; break }
            }
            assertTrue("could not find a free cluster", allocatedCluster >= 2)

            // 3b. Write EOF into the FAT for that cluster.
            buf.putInt(allocatedCluster * 4, 0x0FFFFFFF)
            reader.writeSector(fatStart, fatSector).getOrThrow()

            // 3c. Walk the workdir cluster chain ON DISK and update the
            //     file's directory entry with the new firstCluster.
            val workdirCluster = getClusterOnDisk("/sc_test", reader,
                fatStart, firstDataSector, sectorsPerCluster.toInt())

            var found = false
            var wc = workdirCluster
            val lfnOffsets = intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
            while (wc >= 2 && wc < 0x0FFFFFF8 && !found) {
                val sector = ((wc - 2).toLong() * sectorsPerCluster) + firstDataSector
                val clusterData = reader.readSectors(sector, sectorsPerCluster.toInt()).getOrThrow()
                var off = 0
                var lfnParts = mutableListOf<String>()
                while (off + 32 <= clusterData.size && !found) {
                    val fb = clusterData[off].toInt() and 0xFF
                    if (fb == 0x00) break
                    if (fb == 0xE5) { lfnParts.clear(); off += 32; continue }
                    val attr = clusterData[off + 11].toInt() and 0xFF
                    if (attr == 0x0F) {
                        val sb = StringBuilder(13)
                        for (o in lfnOffsets) {
                            val c1 = clusterData[off + o].toInt() and 0xFF
                            val c2 = clusterData[off + o + 1].toInt() and 0xFF
                            val ch = ((c2 shl 8) or c1).toChar()
                            if (ch == '\u0000' || ch == '\uFFFF') break
                            sb.append(ch)
                        }
                        lfnParts.add(sb.toString())
                        off += 32; continue
                    }
                    val en = if (lfnParts.isNotEmpty()) {
                        val full = StringBuilder()
                        for (i in lfnParts.indices.reversed()) full.append(lfnParts[i])
                        lfnParts.clear()
                        full.toString()
                    } else {
                        val sn = String(clusterData, off, 8, Charsets.US_ASCII).trim()
                        val ext = String(clusterData, off + 8, 3, Charsets.US_ASCII).trim()
                        if (ext.isNotEmpty()) "$sn.$ext" else sn
                    }
                    if (en == "." || en == "..") { off += 32; continue }
                    if (en.equals(name, ignoreCase = true)) {
                        java.nio.ByteBuffer.wrap(clusterData, off + 26, 2)
                            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                            .putShort((allocatedCluster and 0xFFFF).toShort())
                        java.nio.ByteBuffer.wrap(clusterData, off + 20, 2)
                            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                            .putShort((allocatedCluster shr 16).toShort())
                        java.nio.ByteBuffer.wrap(clusterData, off + 28, 4)
                            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                            .putInt(clusterBytes)
                        reader.writeSectors(sector, clusterData).getOrThrow()
                        reader.sync()
                        found = true
                    }
                    off += 32
                }
                val next = java.nio.ByteBuffer.wrap(
                    reader.readSector(fatStart + (wc * 4 / bytesPerSector)).getOrThrow(),
                    (wc * 4) % bytesPerSector, 4
                ).order(java.nio.ByteOrder.LITTLE_ENDIAN).int and 0x0FFFFFFF
                wc = next
            }
            assertTrue("should have found and updated the file entry", found)

            val afterWrite = scanFreeClusters()
            assertEquals(
                "should have consumed exactly 1 cluster",
                1, before - afterWrite
            )

            // Step 4: delete — must free the cluster even though
            //         directoryCache is stale.
            fs.delete(path).getOrThrow()

            val afterDelete = scanFreeClusters()
            assertEquals(
                "FAT scan free-count must be restored after delete when " +
                    "directoryCache holds stale firstCluster=0 " +
                    "(before=$before afterWrite=$afterWrite afterDelete=$afterDelete)",
                before, afterDelete
            )
        } finally {
            cleanWorkdir(workdir)
        }
    }

    /** Walk the on-disk FAT32 directory tree to find a path's first cluster. */
    private fun getClusterOnDisk(
        path: String,
        reader: VolumeReader,
        fatStart: Long,
        firstDataSector: Long,
        sectorsPerCluster: Int
    ): Int {
        // LFN character offsets within a 32-byte entry (Unicode)
        val lfnOffsets = intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
        var cluster = 2  // root dir on FAT32
        for (component in path.trim('/').split('/')) {
            var found = -1
            var c = cluster
            outer@ while (c >= 2 && c < 0x0FFFFFF8 && found < 0) {
                val sector = ((c - 2).toLong() * sectorsPerCluster) + firstDataSector
                val data = reader.readSectors(sector, sectorsPerCluster).getOrThrow()
                var off = 0
                var lfnParts = mutableListOf<String>()
                while (off + 32 <= data.size && found < 0) {
                    val fb = data[off].toInt() and 0xFF
                    if (fb == 0x00) break
                    if (fb == 0xE5) { lfnParts.clear(); off += 32; continue }
                    val attr = data[off + 11].toInt() and 0xFF
                    if (attr == 0x0F) {
                        // Collect LFN fragment (reversed order)
                        val sb = StringBuilder(13)
                        for (o in lfnOffsets) {
                            val c1 = data[off + o].toInt() and 0xFF
                            val c2 = data[off + o + 1].toInt() and 0xFF
                            val ch = ((c2 shl 8) or c1).toChar()
                            if (ch == '\u0000' || ch == '\uFFFF') break
                            sb.append(ch)
                        }
                        lfnParts.add(sb.toString())
                        off += 32; continue
                    }
                    // 8.3 entry — assemble name from LFN if available
                    val en = if (lfnParts.isNotEmpty()) {
                        val full = StringBuilder()
                        for (i in lfnParts.indices.reversed()) full.append(lfnParts[i])
                        lfnParts.clear()
                        full.toString()
                    } else {
                        val sn = String(data, off, 8, Charsets.US_ASCII).trim()
                        val ext = String(data, off + 8, 3, Charsets.US_ASCII).trim()
                        if (ext.isNotEmpty()) "$sn.$ext" else sn
                    }
                    // Skip "." and ".." entries
                    if (en == "." || en == "..") { off += 32; continue }
                    if (en.equals(component, ignoreCase = true)) {
                        val lo = (data[off + 26].toInt() and 0xFF) or
                                 ((data[off + 27].toInt() and 0xFF) shl 8)
                        val hi = (data[off + 20].toInt() and 0xFF) or
                                 ((data[off + 21].toInt() and 0xFF) shl 8)
                        found = (hi shl 16) or lo
                        break@outer
                    }
                    off += 32
                }
                val next = java.nio.ByteBuffer.wrap(
                    reader.readSector(fatStart + (c * 4 / bytesPerSector)).getOrThrow(),
                    (c * 4) % bytesPerSector, 4
                ).order(java.nio.ByteOrder.LITTLE_ENDIAN).int and 0x0FFFFFFF
                c = next
            }
            require(found >= 0) { "path component '$component' in '$path' not found" }
            cluster = found
        }
        return cluster
    }

    // ── Property: concurrent reader sees no torn writes ────────────────────

    @Test
    fun `concurrent reader observes only complete writes`() {
        // We do NOT use checkAll here — concurrency stress-tests are about
        // schedule diversity, not input shrinking. We stage two distinct
        // payloads (`A` and `B`) and an overwriter thread alternating
        // between them. The reader thread asserts that every read returns
        // EITHER the full A payload OR the full B payload — never anything
        // else (truncated, half-A-half-B, or a third value).
        val workdir = "/cc_test"
        fs.createDirectory("/", "cc_test").getOrThrow()
        try {
            val name = "c.bin"
            val path = "$workdir/$name"
            // Two payloads of identical size so a torn write is unambiguous.
            // Use 2× cluster size (typically 8 KB) so the write spans more
            // than one cluster — stresses the cluster-chain update path.
            val size = 8 * 1024
            val payloadA = ByteArray(size) { 'A'.code.toByte() }
            val payloadB = ByteArray(size) { 'B'.code.toByte() }

            fs.createFile(workdir, name).getOrThrow()
            fs.writeFile(path, payloadA).getOrThrow()

            val stop = java.util.concurrent.atomic.AtomicBoolean(false)
            val torn = java.util.concurrent.atomic.AtomicReference<String?>(null)
            val readsCompleted = java.util.concurrent.atomic.AtomicInteger(0)
            val writesCompleted = java.util.concurrent.atomic.AtomicInteger(0)

            val writer = Thread {
                var i = 0
                while (!stop.get()) {
                    val p = if (i and 1 == 0) payloadA else payloadB
                    fs.writeFile(path, p).getOrThrow()
                    writesCompleted.incrementAndGet()
                    i++
                }
            }
            val reader = Thread {
                while (!stop.get()) {
                    val r = fs.readFile(path).getOrThrow()
                    readsCompleted.incrementAndGet()
                    if (r.size != size) {
                        torn.compareAndSet(null,
                            "size mismatch: ${r.size} vs $size after ${readsCompleted.get()} reads"
                        )
                        return@Thread
                    }
                    val first = r[0]
                    if (first != 'A'.code.toByte() && first != 'B'.code.toByte()) {
                        torn.compareAndSet(null,
                            "unexpected leading byte 0x${"%02X".format(first)}"
                        )
                        return@Thread
                    }
                    // All bytes in payload should equal `first`.
                    for (j in 1 until r.size) {
                        if (r[j] != first) {
                            torn.compareAndSet(null,
                                "torn read at offset $j: leading=${first.toInt().toChar()} " +
                                    "byte=0x${"%02X".format(r[j])} (after ${readsCompleted.get()} reads)"
                            )
                            return@Thread
                        }
                    }
                }
            }

            writer.start()
            reader.start()
            // Stress for ~2 seconds.
            Thread.sleep(2_000)
            stop.set(true)
            writer.join(5_000)
            reader.join(5_000)

            assertEquals(
                "concurrent torn read detected (${writesCompleted.get()} writes, " +
                    "${readsCompleted.get()} reads): ${torn.get()}",
                null, torn.get()
            )
            // Ensure both threads actually ran.
            assertTrue("writer made too few writes (${writesCompleted.get()})", writesCompleted.get() > 5)
            assertTrue("reader made too few reads (${readsCompleted.get()})", readsCompleted.get() > 5)
        } finally {
            cleanWorkdir(workdir)
        }
    }
}
