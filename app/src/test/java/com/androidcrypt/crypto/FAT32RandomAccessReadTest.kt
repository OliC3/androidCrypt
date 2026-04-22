package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Integration tests for the random-access read path used by
 * [VeraCryptDocumentsProvider.EncryptedFileProxyCallback] on cache misses.
 *
 * These tests exercise [FAT32Reader.readFileRangeByCluster], the hot path
 * driven by Glide's GIF decoder when it seeks backward / forward through
 * frames. The forward-only sliding window in the proxy callback means each
 * such seek causes a fresh `readFileRangeByCluster` call against the
 * underlying encrypted volume; correctness here is critical for the GIF
 * caching fix to behave correctly when a frame falls outside the sliding
 * window.
 */
class FAT32RandomAccessReadTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_fat32_random_tests")
        private const val PASSWORD = "RandomReadPass!"
        // Larger than several FAT32 clusters so we exercise multi-cluster reads
        // and intra-cluster offsets.
        private const val FILE_SIZE = 512 * 1024 // 512 KiB
    }

    private lateinit var containerFile: File
    private lateinit var reader: VolumeReader
    private lateinit var fs: FAT32Reader

    /** Deterministic, position-dependent data so any byte misalignment is caught. */
    private val payload: ByteArray by lazy {
        ByteArray(FILE_SIZE).apply {
            for (i in indices) this[i] = ((i * 31 + 17) and 0xFF).toByte()
        }
    }

    private fun sha256(b: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(b).joinToString("") { "%02x".format(it) }
    }

    @Before
    fun setUp() {
        TEST_DIR.mkdirs()
        containerFile = File(TEST_DIR, "fat32_random_${System.nanoTime()}.hc")

        VolumeCreator.createContainer(
            containerFile.absolutePath, PASSWORD.toCharArray(), 10
        ).getOrThrow()

        reader = VolumeReader(containerFile.absolutePath)
        reader.mount(PASSWORD.toCharArray()).getOrThrow()
        fs = FAT32Reader(reader)
        fs.initialize().getOrThrow()

        fs.createFile("/", "blob.bin").getOrThrow()
        fs.writeFile("/blob.bin", payload).getOrThrow()
    }

    @After
    fun tearDown() {
        try { reader.unmount() } catch (_: Exception) {}
        containerFile.delete()
        TEST_DIR.delete()
    }

    private fun firstClusterFor(path: String): Int =
        fs.getFileInfoWithClusterPublic(path).getOrThrow().firstCluster

    // ── Basic correctness ──────────────────────────────────────────────────

    @Test
    fun `readFileRangeByCluster reads the entire file correctly`() {
        val cluster = firstClusterFor("/blob.bin")
        val data = fs.readFileRangeByCluster(cluster, FILE_SIZE.toLong(), 0L, FILE_SIZE).getOrThrow()
        assertEquals("Length must match", FILE_SIZE, data.size)
        assertEquals("Whole-file hash must match", sha256(payload), sha256(data))
    }

    @Test
    fun `readFileRangeByCluster at zero length returns empty`() {
        val cluster = firstClusterFor("/blob.bin")
        val data = fs.readFileRangeByCluster(cluster, FILE_SIZE.toLong(), 0L, 0).getOrThrow()
        assertEquals(0, data.size)
    }

    @Test
    fun `readFileRangeByCluster past EOF returns empty`() {
        val cluster = firstClusterFor("/blob.bin")
        val data = fs.readFileRangeByCluster(
            cluster, FILE_SIZE.toLong(), FILE_SIZE.toLong(), 4096
        ).getOrThrow()
        assertEquals(0, data.size)
    }

    @Test
    fun `readFileRangeByCluster clamps reads that straddle EOF`() {
        val cluster = firstClusterFor("/blob.bin")
        val offset = (FILE_SIZE - 100).toLong()
        val data = fs.readFileRangeByCluster(cluster, FILE_SIZE.toLong(), offset, 4096).getOrThrow()
        assertEquals("Should be clamped to the remaining 100 bytes", 100, data.size)
        for (i in 0 until 100) {
            assertEquals(payload[FILE_SIZE - 100 + i], data[i])
        }
    }

    @Test
    fun `readFileRangeByCluster with invalid first cluster fails`() {
        val r = fs.readFileRangeByCluster(0, FILE_SIZE.toLong(), 0L, 1024)
        assertTrue("Cluster 0 must be rejected", r.isFailure)
        val r2 = fs.readFileRangeByCluster(1, FILE_SIZE.toLong(), 0L, 1024)
        assertTrue("Cluster 1 must be rejected (reserved)", r2.isFailure)
    }

    // ── Random-access / GIF-decoder simulation ─────────────────────────────

    @Test
    fun `random-offset reads return correct bytes (GIF decoder seek pattern)`() {
        val cluster = firstClusterFor("/blob.bin")
        val rng = java.util.Random(0xDEADBEEFL) // deterministic
        val attempts = 200

        repeat(attempts) {
            val length = 1 + rng.nextInt(8 * 1024) // 1..8KiB chunks
            val offset = rng.nextInt(FILE_SIZE - length).toLong()

            val data = fs.readFileRangeByCluster(
                cluster, FILE_SIZE.toLong(), offset, length
            ).getOrThrow()

            assertEquals("Length mismatch at offset=$offset len=$length", length, data.size)
            for (i in 0 until length) {
                if (data[i] != payload[(offset + i).toInt()]) {
                    fail("Byte mismatch at file offset=${offset + i} (chunk offset=$offset, len=$length)")
                }
            }
        }
    }

    @Test
    fun `backward seeks return correct bytes (Glide GIF backward-frame pattern)`() {
        val cluster = firstClusterFor("/blob.bin")
        // Walk the file backward in 4 KiB chunks — this is the worst case for
        // the proxy callback's forward-only sliding window: every read misses
        // the cache and must hit readFileRangeByCluster.
        val chunk = 4096
        var offset = (FILE_SIZE - chunk).toLong()
        while (offset >= 0) {
            val data = fs.readFileRangeByCluster(
                cluster, FILE_SIZE.toLong(), offset, chunk
            ).getOrThrow()
            assertEquals(chunk, data.size)
            for (i in 0 until chunk) {
                if (data[i] != payload[(offset + i).toInt()]) {
                    fail("Backward-seek byte mismatch at offset=${offset + i}")
                }
            }
            offset -= chunk
        }
    }

    @Test
    fun `intra-cluster offsets are honored`() {
        val cluster = firstClusterFor("/blob.bin")
        // Hit a bunch of unaligned offsets within the first few clusters.
        for (offset in listOf(1L, 7L, 511L, 513L, 4095L, 4097L, 8000L)) {
            val len = 333
            val data = fs.readFileRangeByCluster(
                cluster, FILE_SIZE.toLong(), offset, len
            ).getOrThrow()
            assertEquals(len, data.size)
            for (i in 0 until len) {
                if (data[i] != payload[(offset + i).toInt()]) {
                    fail("Intra-cluster mismatch at offset=$offset i=$i")
                }
            }
        }
    }

    @Test
    fun `concurrent random reads from multiple threads return correct bytes`() {
        val cluster = firstClusterFor("/blob.bin")
        val threads = 8
        val perThread = 50
        val errors = java.util.concurrent.ConcurrentLinkedQueue<String>()

        val workers = (0 until threads).map { threadId ->
            Thread {
                val rng = java.util.Random((0xC0FFEEL + threadId).toLong())
                repeat(perThread) {
                    val length = 1 + rng.nextInt(16 * 1024)
                    val offset = rng.nextInt(FILE_SIZE - length).toLong()
                    val r = fs.readFileRangeByCluster(
                        cluster, FILE_SIZE.toLong(), offset, length
                    )
                    if (r.isFailure) {
                        errors.add("read failed @ offset=$offset len=$length: ${r.exceptionOrNull()}")
                        return@repeat
                    }
                    val data = r.getOrThrow()
                    if (data.size != length) {
                        errors.add("length mismatch @ offset=$offset: got=${data.size} expected=$length")
                        return@repeat
                    }
                    for (i in 0 until length) {
                        if (data[i] != payload[(offset + i).toInt()]) {
                            errors.add("byte mismatch @ ${offset + i}")
                            return@repeat
                        }
                    }
                }
            }.apply { start() }
        }
        workers.forEach { it.join() }
        assertTrue("Concurrent read errors: ${errors.take(5)}", errors.isEmpty())
    }
}
