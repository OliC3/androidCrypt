package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.element
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

/**
 * **Long-name boundary PBTs.**
 *
 *  - **T21** LFN lengths at 1, 13, 14, 26, 27, 39, 40, 254, 255 (FAT32
 *    LFN entries hold up to 13 UTF-16 code units each — every multiple of 13
 *    is a chain-boundary that historically catches off-by-one bugs in LFN
 *    construction). All names must round-trip through write/read.
 *  - **T22** names containing characters legal in LFN but illegal in 8.3
 *    (`+ , ; = [ ]` plus space-in-stem) must NOT be lost or aliased; their
 *    long form must round-trip and they must not collide with each other.
 */
class FAT32LongNameBoundaryPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_lfn_pbt")
        private const val PASSWORD = "LfnPBT!"
        private lateinit var container: File
        private lateinit var reader: VolumeReader
        private lateinit var fs: FAT32Reader

        @BeforeClass @JvmStatic
        fun setUp() {
            TEST_DIR.mkdirs()
            container = File(TEST_DIR, "lfn_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(container.absolutePath, PASSWORD.toCharArray(), 8L).getOrThrow()
            reader = VolumeReader(container.absolutePath)
            reader.mount(PASSWORD.toCharArray()).getOrThrow()
            fs = FAT32Reader(reader); fs.initialize().getOrThrow()
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            try { reader.unmount() } catch (_: Exception) {}
            TEST_DIR.listFiles()?.forEach { it.delete() }
            TEST_DIR.delete()
        }
    }

    // ── T21 ─────────────────────────────────────────────────────────────────
    @Test
    fun `LFN lengths at every 13-char boundary round-trip`(): Unit = runBlocking {
        // FAT32 LFN: each LFN entry holds up to 13 UCS-2 chars; off-by-one
        // bugs in chain construction surface at multiples of 13 and at the
        // 255 max.
        val pivots = listOf(1, 12, 13, 14, 25, 26, 27, 38, 39, 40, 130, 200, 250, 254, 255)
        fs.createDirectory("/", "lens").getOrThrow()
        for (len in pivots) {
            // Build a name of exactly `len` chars; reserve room for ".bin" → if
            // len <= 4 just use a stem.
            val stemLen = (len - 4).coerceAtLeast(1)
            val name = if (len >= 5) ("a".repeat(stemLen) + ".bin").also {
                check(it.length == len) { "name length ${it.length} != $len" }
            } else "a".repeat(len)
            val payload = "len=$len:${name}".toByteArray(Charsets.UTF_8)

            fs.createFile("/lens", name).getOrThrow()
            fs.writeFile("/lens/$name", payload).getOrThrow()
            reader.sync()

            assertTrue("len=$len name '$name' missing after write", fs.exists("/lens/$name"))
            val rb = fs.readFile("/lens/$name").getOrThrow()
            assertArrayEquals("len=$len: content corrupted for '$name'", payload, rb)
        }
        // All pivot names listable in one go
        val listed = fs.listDirectory("/lens").getOrThrow().map { it.name }.toSet()
        for (len in pivots) {
            val name = if (len >= 5) "a".repeat(len - 4) + ".bin" else "a".repeat(len)
            assertTrue("len=$len name '$name' missing from listDirectory", name in listed)
        }
    }

    // ── T22 ─────────────────────────────────────────────────────────────────
    /** Characters legal in LFN but illegal in 8.3 short names per the FAT
     *  spec are: `+ , ; = [ ]` (plus any non-ASCII char). When such a
     *  filename is created, the implementation MUST mangle the 8.3 stem
     *  (typically replacing each illegal char with `_`) and add a `~N`
     *  tail. The long form must still be the canonical name. */
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `names with reserved 8 dot 3 chars round-trip via LFN`(): Unit = runBlocking {
        fs.createDirectory("/", "rsv").getOrThrow()
        val rsvChars = listOf('+', ',', ';', '=', '[', ']')
        checkAll(
            PropTestConfig(iterations = 6, seed = 0x7E517E51L),
            Arb.element(rsvChars),
            Arb.int(1, 5),  // how many copies of the reserved char
        ) { c, n ->
            val name = "name${c.toString().repeat(n)}stem.txt"
            val payload = name.toByteArray(Charsets.UTF_8)
            fs.createFile("/rsv", name).getOrThrow()
            fs.writeFile("/rsv/$name", payload).getOrThrow()
            reader.sync()
            assertTrue("name '$name' missing after create", fs.exists("/rsv/$name"))
            val listed = fs.listDirectory("/rsv").getOrThrow().map { it.name }.toSet()
            assertTrue("name '$name' missing from listDirectory", name in listed)
            val rb = fs.readFile("/rsv/$name").getOrThrow()
            assertArrayEquals("content corrupted for reserved-char name '$name'", payload, rb)
            fs.delete("/rsv/$name").getOrNull()
            reader.sync()
        }
    }
}
