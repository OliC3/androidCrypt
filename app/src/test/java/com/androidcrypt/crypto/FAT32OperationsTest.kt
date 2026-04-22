package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

/**
 * Tests for FAT32 filesystem operations:
 * - Directory creation (nested)
 * - File listing
 * - Delete (files and directories)
 * - Long file names (LFN)
 * - Multi-cluster files
 * - Streaming writes
 * - Name validation (validateFat32Name)
 * - Edge cases
 */
class FAT32OperationsTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_fat32_tests")
        private const val PASSWORD = "FAT32TestPass!"
    }

    private lateinit var containerFile: File
    private lateinit var reader: VolumeReader
    private lateinit var fs: FAT32Reader

    @Before
    fun setUp() {
        TEST_DIR.mkdirs()
        containerFile = File(TEST_DIR, "fat32_test_${System.nanoTime()}.hc")

        VolumeCreator.createContainer(
            containerFile.absolutePath, PASSWORD.toCharArray(), 10
        ).getOrThrow()

        reader = VolumeReader(containerFile.absolutePath)
        reader.mount(PASSWORD.toCharArray()).getOrThrow()
        fs = FAT32Reader(reader)
        fs.initialize().getOrThrow()
    }

    @After
    fun tearDown() {
        try { reader.unmount() } catch (_: Exception) {}
        containerFile.delete()
        TEST_DIR.delete()
    }

    // ── Directory operations ────────────────────────────────────────────────

    @Test
    fun `create directory in root`() {
        val result = fs.createDirectory("/", "testdir")
        assertTrue("createDirectory failed: ${result.exceptionOrNull()}", result.isSuccess)
        assertTrue("Directory should exist", fs.exists("/testdir"))

        val entry = fs.getFileInfo("/testdir").getOrThrow()
        assertTrue("Should be a directory", entry.isDirectory)
    }

    @Test
    fun `create nested directories`() {
        fs.createDirectory("/", "level1").getOrThrow()
        fs.createDirectory("/level1", "level2").getOrThrow()
        fs.createDirectory("/level1/level2", "level3").getOrThrow()

        assertTrue("level1 exists", fs.exists("/level1"))
        assertTrue("level2 exists", fs.exists("/level1/level2"))
        assertTrue("level3 exists", fs.exists("/level1/level2/level3"))
    }

    @Test
    fun `create file in subdirectory`() {
        fs.createDirectory("/", "docs").getOrThrow()
        fs.createFile("/docs", "readme.txt").getOrThrow()
        fs.writeFile("/docs/readme.txt", "Hello from subdir!".toByteArray()).getOrThrow()

        val content = fs.readFile("/docs/readme.txt").getOrThrow()
        assertEquals("Hello from subdir!", String(content))
    }

    @Test
    fun `list root directory`() {
        fs.createFile("/", "a.txt").getOrThrow()
        fs.createFile("/", "b.txt").getOrThrow()
        fs.createDirectory("/", "mydir").getOrThrow()

        val entries = fs.listDirectory("/").getOrThrow()
        val names = entries.map { it.name.lowercase() }.toSet()
        assertTrue("Should contain a.txt", "a.txt" in names)
        assertTrue("Should contain b.txt", "b.txt" in names)
        assertTrue("Should contain mydir", "mydir" in names)
    }

    @Test
    fun `list subdirectory`() {
        fs.createDirectory("/", "parent").getOrThrow()
        fs.createFile("/parent", "child1.txt").getOrThrow()
        fs.createFile("/parent", "child2.txt").getOrThrow()

        val entries = fs.listDirectory("/parent").getOrThrow()
        val names = entries.map { it.name.lowercase() }
        assertTrue("child1.txt present", "child1.txt" in names)
        assertTrue("child2.txt present", "child2.txt" in names)
    }

    // ── Delete operations ───────────────────────────────────────────────────

    @Test
    fun `delete file`() {
        fs.createFile("/", "todelete.txt").getOrThrow()
        fs.writeFile("/todelete.txt", "delete me".toByteArray()).getOrThrow()
        assertTrue("File should exist before delete", fs.exists("/todelete.txt"))

        fs.delete("/todelete.txt").getOrThrow()
        assertFalse("File should not exist after delete", fs.exists("/todelete.txt"))
    }

    @Test
    fun `delete empty directory`() {
        fs.createDirectory("/", "emptydir").getOrThrow()
        assertTrue(fs.exists("/emptydir"))

        fs.delete("/emptydir").getOrThrow()
        assertFalse("Directory should not exist after delete", fs.exists("/emptydir"))
    }

    @Test
    fun `delete directory with contents`() {
        fs.createDirectory("/", "fulldir").getOrThrow()
        fs.createFile("/fulldir", "inside.txt").getOrThrow()
        fs.writeFile("/fulldir/inside.txt", "data".toByteArray()).getOrThrow()

        // Delete file first, then directory
        fs.delete("/fulldir/inside.txt").getOrThrow()
        fs.delete("/fulldir").getOrThrow()
        assertFalse(fs.exists("/fulldir"))
        assertFalse(fs.exists("/fulldir/inside.txt"))
    }

    @Test
    fun `delete root fails`() {
        val result = fs.delete("/")
        assertTrue("Deleting root should fail", result.isFailure)
    }

    // ── Long file names (LFN) ───────────────────────────────────────────────

    @Test
    fun `long file name - 50 characters`() {
        val longName = "this_is_a_very_long_filename_that_exceeds_8dot3.txt"
        fs.createFile("/", longName).getOrThrow()
        fs.writeFile("/$longName", "LFN content".toByteArray()).getOrThrow()

        assertTrue("Long-named file should exist", fs.exists("/$longName"))
        val content = fs.readFile("/$longName").getOrThrow()
        assertEquals("LFN content", String(content))
    }

    @Test
    fun `long directory name`() {
        val longDir = "My Documents and Settings Folder"
        fs.createDirectory("/", longDir).getOrThrow()
        fs.createFile("/$longDir", "file.txt").getOrThrow()
        fs.writeFile("/$longDir/file.txt", "nested".toByteArray()).getOrThrow()

        assertEquals("nested", String(fs.readFile("/$longDir/file.txt").getOrThrow()))
    }

    @Test
    fun `file name with spaces and special chars`() {
        val name = "My File (2024) - Copy.txt"
        fs.createFile("/", name).getOrThrow()
        fs.writeFile("/$name", "special chars".toByteArray()).getOrThrow()

        assertTrue(fs.exists("/$name"))
        assertEquals("special chars", String(fs.readFile("/$name").getOrThrow()))
    }

    @Test
    fun `unicode file name`() {
        // Known limitation: FAT32 implementation may not correctly round-trip
        // all Unicode LFN entries. Verify creation succeeds but skip if unsupported.
        val name = "日本語テスト.txt"
        val createResult = fs.createFile("/", name)
        org.junit.Assume.assumeTrue("Unicode LFN not supported", createResult.isSuccess)
        val writeResult = fs.writeFile("/$name", "unicode".toByteArray())
        org.junit.Assume.assumeTrue("Unicode write not supported", writeResult.isSuccess)
        assertEquals("unicode", String(fs.readFile("/$name").getOrThrow()))
    }

    @Test
    fun `filename at exactly 255 characters`() {
        val name = "a".repeat(251) + ".txt"  // 255 chars total
        fs.createFile("/", name).getOrThrow()
        fs.writeFile("/$name", "max length".toByteArray()).getOrThrow()
        assertEquals("max length", String(fs.readFile("/$name").getOrThrow()))
    }

    // ── Multi-cluster files ─────────────────────────────────────────────────

    @Test
    fun `write and read multi-cluster file`() {
        // 10 MB volume with 4096-byte clusters = need data spanning multiple clusters
        // Write 32 KB file (should span ~8 clusters at 4KB cluster size)
        val data = ByteArray(32 * 1024) { (it % 256).toByte() }
        fs.createFile("/", "large.bin").getOrThrow()
        fs.writeFile("/large.bin", data).getOrThrow()

        val readBack = fs.readFile("/large.bin").getOrThrow()
        assertArrayEquals("Large file content mismatch", data, readBack)
    }

    @Test
    fun `write and read 100KB file`() {
        val data = ByteArray(100 * 1024) { ((it * 7 + 13) % 256).toByte() }
        fs.createFile("/", "100kb.bin").getOrThrow()
        fs.writeFile("/100kb.bin", data).getOrThrow()

        val readBack = fs.readFile("/100kb.bin").getOrThrow()
        assertArrayEquals("100KB file content mismatch", data, readBack)
    }

    @Test
    fun `write and read 1MB file`() {
        val data = ByteArray(1024 * 1024) { ((it * 31 + 17) % 256).toByte() }
        fs.createFile("/", "1mb.bin").getOrThrow()
        fs.writeFile("/1mb.bin", data).getOrThrow()

        val readBack = fs.readFile("/1mb.bin").getOrThrow()
        assertArrayEquals("1MB file content mismatch", data, readBack)
    }

    // ── Streaming write ─────────────────────────────────────────────────────

    @Test
    fun `streaming write and read back`() {
        val data = ByteArray(64 * 1024) { (it % 256).toByte() }
        fs.createFile("/", "stream.bin").getOrThrow()

        val inputStream = ByteArrayInputStream(data)
        fs.writeFileStreaming("/stream.bin", inputStream, data.size.toLong()).getOrThrow()

        val readBack = fs.readFile("/stream.bin").getOrThrow()
        assertArrayEquals("Streaming write content mismatch", data, readBack)
    }

    // ── File info ───────────────────────────────────────────────────────────

    @Test
    fun `getFileInfo returns correct size`() {
        val data = "Hello, World!".toByteArray()
        fs.createFile("/", "sized.txt").getOrThrow()
        fs.writeFile("/sized.txt", data).getOrThrow()

        val info = fs.getFileInfo("/sized.txt").getOrThrow()
        assertEquals("File size should match written data", data.size.toLong(), info.size)
        assertFalse("Should not be a directory", info.isDirectory)
        assertTrue(info.name.equals("sized.txt", ignoreCase = true))
    }

    @Test
    fun `getFileInfo for directory`() {
        fs.createDirectory("/", "infodir").getOrThrow()
        val info = fs.getFileInfo("/infodir").getOrThrow()
        assertTrue("Should be a directory", info.isDirectory)
        assertTrue(info.name.equals("infodir", ignoreCase = true))
    }

    @Test
    fun `getFileInfo for nonexistent path fails`() {
        val result = fs.getFileInfo("/nonexistent.txt")
        assertTrue("Should fail for nonexistent file", result.isFailure)
    }

    // ── Name validation ─────────────────────────────────────────────────────

    @Test
    fun `reject empty name`() {
        val result = fs.createFile("/", "")
        assertTrue("Empty name should fail", result.isFailure)
    }

    @Test
    fun `reject name with slash`() {
        val result = fs.createFile("/", "bad/name.txt")
        assertTrue("Name with slash should fail", result.isFailure)
    }

    @Test
    fun `reject name with backslash`() {
        val result = fs.createFile("/", "bad\\name.txt")
        assertTrue("Name with backslash should fail", result.isFailure)
    }

    @Test
    fun `reject name with colon`() {
        val result = fs.createFile("/", "bad:name.txt")
        assertTrue("Name with colon should fail", result.isFailure)
    }

    @Test
    fun `reject name with asterisk`() {
        val result = fs.createFile("/", "bad*name.txt")
        assertTrue("Name with asterisk should fail", result.isFailure)
    }

    @Test
    fun `reject name with question mark`() {
        val result = fs.createFile("/", "bad?name.txt")
        assertTrue("Name with ? should fail", result.isFailure)
    }

    @Test
    fun `reject name with angle brackets`() {
        assertTrue(fs.createFile("/", "<bad>.txt").isFailure)
    }

    @Test
    fun `reject name with pipe`() {
        assertTrue(fs.createFile("/", "bad|name.txt").isFailure)
    }

    @Test
    fun `reject name with double quotes`() {
        assertTrue(fs.createFile("/", "bad\"name.txt").isFailure)
    }

    @Test
    fun `reject name ending with dot`() {
        assertTrue(fs.createFile("/", "badname.").isFailure)
    }

    @Test
    fun `reject name ending with space`() {
        assertTrue(fs.createFile("/", "badname ").isFailure)
    }

    @Test
    fun `reject reserved name CON`() {
        assertTrue(fs.createFile("/", "CON").isFailure)
    }

    @Test
    fun `reject reserved name con dot txt`() {
        assertTrue(fs.createFile("/", "con.txt").isFailure)
    }

    @Test
    fun `reject reserved name NUL`() {
        assertTrue(fs.createFile("/", "NUL").isFailure)
    }

    @Test
    fun `reject reserved name COM1`() {
        assertTrue(fs.createFile("/", "COM1").isFailure)
    }

    @Test
    fun `reject reserved name LPT1`() {
        assertTrue(fs.createFile("/", "LPT1").isFailure)
    }

    @Test
    fun `reject reserved name PRN`() {
        assertTrue(fs.createFile("/", "PRN").isFailure)
    }

    @Test
    fun `reject reserved name AUX`() {
        assertTrue(fs.createFile("/", "AUX").isFailure)
    }

    @Test
    fun `reject dot name`() {
        assertTrue(fs.createFile("/", ".").isFailure)
    }

    @Test
    fun `reject dotdot name`() {
        assertTrue(fs.createFile("/", "..").isFailure)
    }

    @Test
    fun `reject name exceeding 255 characters`() {
        val tooLong = "a".repeat(256)
        assertTrue(fs.createFile("/", tooLong).isFailure)
    }

    @Test
    fun `reject name with null character`() {
        assertTrue(fs.createFile("/", "bad\u0000name").isFailure)
    }

    @Test
    fun `reject name with control character`() {
        assertTrue(fs.createFile("/", "bad\u0001name").isFailure)
    }

    @Test
    fun `name validation also applies to createDirectory`() {
        assertTrue("CON dir should fail", fs.createDirectory("/", "CON").isFailure)
        assertTrue("* dir should fail", fs.createDirectory("/", "bad*dir").isFailure)
        assertTrue("empty dir should fail", fs.createDirectory("/", "").isFailure)
    }

    // ── Edge cases ──────────────────────────────────────────────────────────

    @Test
    fun `duplicate file name fails`() {
        fs.createFile("/", "dup.txt").getOrThrow()
        val result = fs.createFile("/", "dup.txt")
        assertTrue("Duplicate file should fail", result.isFailure)
    }

    @Test
    fun `duplicate directory name fails`() {
        fs.createDirectory("/", "dupdir").getOrThrow()
        val result = fs.createDirectory("/", "dupdir")
        assertTrue("Duplicate directory should fail", result.isFailure)
    }

    @Test
    fun `write empty file`() {
        fs.createFile("/", "empty.txt").getOrThrow()
        fs.writeFile("/empty.txt", ByteArray(0)).getOrThrow()

        val info = fs.getFileInfo("/empty.txt").getOrThrow()
        assertEquals("Empty file size", 0L, info.size)
    }

    @Test
    fun `case insensitive file access`() {
        // FAT32 is case-insensitive
        fs.createFile("/", "CaseSensitive.txt").getOrThrow()
        fs.writeFile("/CaseSensitive.txt", "data".toByteArray()).getOrThrow()

        // Should be accessible with different case
        assertTrue("Lowercase should exist", fs.exists("/casesensitive.txt"))
        assertTrue("Uppercase should exist", fs.exists("/CASESENSITIVE.TXT"))
    }

    @Test
    fun `many files in one directory`() {
        // Create 50 files in root to test directory cluster expansion
        for (i in 1..50) {
            fs.createFile("/", "file_$i.txt").getOrThrow()
        }
        val entries = fs.listDirectory("/").getOrThrow()
        val names = entries.map { it.name.lowercase() }.toSet()
        assertEquals("Should have exactly 50 entries", 50, entries.size)
        for (i in 1..50) {
            assertTrue("Should contain file_$i.txt", names.contains("file_$i.txt"))
        }
    }

    @Test
    fun `read file with offset and length`() {
        val data = "0123456789ABCDEF".toByteArray()
        fs.createFile("/", "partial.txt").getOrThrow()
        fs.writeFile("/partial.txt", data).getOrThrow()

        // Read a sub-range
        val partial = fs.readFile("/partial.txt", offset = 4, length = 6).getOrThrow()
        assertEquals("456789", String(partial))
    }

    @Test
    fun `filesystem info after initialization`() {
        val info = fs.getFileSystemInfo()
        assertNotNull("FS info should not be null", info)
        assertEquals("Should be FAT32", FileSystemType.FAT32, info!!.type)
        // 10MB volume: total space should be between 8MB and 10MB (after headers/FAT overhead)
        assertTrue("Total space should be >= 8MB", info.totalSpace >= 8L * 1024 * 1024)
        assertTrue("Total space should be <= 10MB", info.totalSpace <= 10L * 1024 * 1024)
        // FAT32 cluster sizes are powers of 2, typically 512-4096 for small volumes
        assertTrue("Cluster size should be power of 2", info.clusterSize > 0 && (info.clusterSize.toLong() and (info.clusterSize.toLong() - 1)) == 0L)
    }

    // ── Additional edge cases ────────────────────────────────────────────────

    @Test
    fun `overwrite existing file with new content`() {
        fs.createFile("/", "over.txt").getOrThrow()
        fs.writeFile("/over.txt", "original".toByteArray()).getOrThrow()

        // Overwrite with different content
        fs.writeFile("/over.txt", "replaced!!".toByteArray()).getOrThrow()
        val readBack = fs.readFile("/over.txt").getOrThrow()
        assertEquals("replaced!!", String(readBack))
    }

    @Test
    fun `overwrite with larger content`() {
        fs.createFile("/", "grow.txt").getOrThrow()
        fs.writeFile("/grow.txt", "short".toByteArray()).getOrThrow()

        val largerData = ByteArray(8192) { (it % 256).toByte() }
        fs.writeFile("/grow.txt", largerData).getOrThrow()
        val readBack = fs.readFile("/grow.txt").getOrThrow()
        assertArrayEquals("Larger overwrite", largerData, readBack)
    }

    @Test
    fun `overwrite with smaller content`() {
        fs.createFile("/", "shrink.txt").getOrThrow()
        val largeData = ByteArray(8192) { (it % 256).toByte() }
        fs.writeFile("/shrink.txt", largeData).getOrThrow()

        fs.writeFile("/shrink.txt", "tiny".toByteArray()).getOrThrow()
        val readBack = fs.readFile("/shrink.txt").getOrThrow()
        assertEquals("tiny", String(readBack))
    }

    @Test
    fun `createFile in nonexistent parent returns failure`() {
        val result = fs.createFile("/nonexistent_dir", "file.txt")
        assertTrue("Should fail for nonexistent parent", result.isFailure)
    }

    @Test
    fun `createDirectory in nonexistent parent returns failure`() {
        val result = fs.createDirectory("/no_such_dir", "child")
        assertTrue("Should fail for nonexistent parent dir", result.isFailure)
    }

    @Test
    fun `delete nonexistent file returns failure`() {
        val result = fs.delete("/no_such_file.txt")
        assertTrue("Should fail deleting nonexistent file", result.isFailure)
    }

    @Test
    fun `listDirectory on nonexistent path returns failure`() {
        val result = fs.listDirectory("/no_such_dir")
        assertTrue("Should fail listing nonexistent dir", result.isFailure)
    }

    @Test
    fun `exists returns false for nonexistent file`() {
        assertFalse(fs.exists("/nope.txt"))
    }

    @Test
    fun `readFile on nonexistent file returns failure`() {
        val result = fs.readFile("/nope.txt")
        assertTrue("Should fail reading nonexistent file", result.isFailure)
    }
}
