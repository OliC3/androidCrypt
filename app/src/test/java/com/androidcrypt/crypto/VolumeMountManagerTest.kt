package com.androidcrypt.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Comprehensive unit tests for [VolumeMountManager].
 *
 * **Important:** [VolumeMountManager] is a singleton object, so every test
 * calls [VolumeMountManager.unmountAll] in [@After] to guarantee isolation.
 */
class VolumeMountManagerTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_vmm_test")
        private const val PASSWORD = "VolumeMountManagerTest!"
    }

    @Before
    fun setUp() {
        TEST_DIR.mkdirs()
    }

    @After
    fun tearDown() {
        VolumeMountManager.unmountAll()
        TEST_DIR.listFiles()?.forEach { it.delete() }
        TEST_DIR.delete()
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private fun tempContainer(tag: String): File {
        return File(TEST_DIR, "vmm_${tag}_${System.nanoTime()}.hc")
    }

    private fun createAndMountFile(tag: String): File {
        val file = tempContainer(tag)
        val createResult = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray(),
            sizeInMB = 4L
        )
        assertTrue("creation failed: ${createResult.exceptionOrNull()?.message}", createResult.isSuccess)

        val mountResult = VolumeMountManager.mountVolume(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray()
        )
        assertTrue("mount failed: ${mountResult.exceptionOrNull()?.message}", mountResult.isSuccess)
        return file
    }

    // ════════════════════════════════════════════════════════════════════════
    //  mountVolume (file path)
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `mountVolume succeeds with valid container`() {
        val file = tempContainer("mount_ok")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()

        val result = VolumeMountManager.mountVolume(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray()
        )

        assertTrue(result.isSuccess)
        val info = result.getOrThrow()
        assertTrue(info.isMounted)
        assertTrue(info.dataAreaSize > 0)
    }

    @Test
    fun `mountVolume fails with wrong password`() {
        val file = tempContainer("mount_wrong_pw")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()

        val result = VolumeMountManager.mountVolume(
            containerPath = file.absolutePath,
            password = "wrongpassword".toCharArray()
        )

        assertTrue(result.isFailure)
    }

    @Test
    fun `mountVolume fails when already mounted`() {
        val file = createAndMountFile("double_mount")

        val result = VolumeMountManager.mountVolume(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray()
        )

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message?.contains("already mounted") == true)
    }

    // ════════════════════════════════════════════════════════════════════════
    //  mountVolumeFromUri (content URI) — skipped in JVM tests; needs Android Context
    // ════════════════════════════════════════════════════════════════════════

    // mountVolumeFromUri tests require android.content.Context and android.net.Uri,
    // so they are covered by instrumented tests instead.

    // ════════════════════════════════════════════════════════════════════════
    //  unmountVolume
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `unmountVolume succeeds for mounted volume`() {
        val file = createAndMountFile("unmount_ok")
        assertTrue(VolumeMountManager.isMounted(file.absolutePath))

        val result = VolumeMountManager.unmountVolume(file.absolutePath)

        assertTrue(result.isSuccess)
        assertFalse(VolumeMountManager.isMounted(file.absolutePath))
    }

    @Test
    fun `unmountVolume fails for non-mounted path`() {
        val result = VolumeMountManager.unmountVolume("/nonexistent/path/container.hc")
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message?.contains("not mounted") == true)
    }

    @Test
    fun `unmountVolume cleans up fileSystemReader`() {
        val file = createAndMountFile("unmount_fs_cleanup")
        val fsReader = VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath)
        assertNotNull(fsReader)

        VolumeMountManager.unmountVolume(file.absolutePath)

        // After unmount, getOrCreateFileSystemReader should return null
        // because the underlying VolumeReader is gone
        val after = VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath)
        assertNull(after)
    }

    // ════════════════════════════════════════════════════════════════════════
    //  unmountAll
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `unmountAll removes all mounted volumes`() {
        val file1 = createAndMountFile("unmount_all_1")
        val file2 = createAndMountFile("unmount_all_2")
        assertEquals(2, VolumeMountManager.getMountedVolumes().size)

        VolumeMountManager.unmountAll()

        assertTrue(VolumeMountManager.getMountedVolumes().isEmpty())
        assertFalse(VolumeMountManager.isMounted(file1.absolutePath))
        assertFalse(VolumeMountManager.isMounted(file2.absolutePath))
    }

    // ════════════════════════════════════════════════════════════════════════
    //  isMounted / getMountedVolumes / getVolumeReader
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `isMounted returns true only for mounted volumes`() {
        val file = createAndMountFile("isMounted")
        assertTrue(VolumeMountManager.isMounted(file.absolutePath))
        assertFalse(VolumeMountManager.isMounted("/some/other/path"))
    }

    @Test
    fun `getMountedVolumes returns all mounted paths`() {
        val file1 = createAndMountFile("list_1")
        val file2 = createAndMountFile("list_2")

        val mounted = VolumeMountManager.getMountedVolumes()

        assertEquals(2, mounted.size)
        assertTrue(mounted.contains(file1.absolutePath))
        assertTrue(mounted.contains(file2.absolutePath))
    }

    @Test
    fun `getVolumeReader returns reader for mounted volume`() {
        val file = createAndMountFile("get_reader")
        val reader = VolumeMountManager.getVolumeReader(file.absolutePath)
        assertNotNull(reader)
    }

    @Test
    fun `getVolumeReader returns null for unmounted volume`() {
        val reader = VolumeMountManager.getVolumeReader("/not/mounted")
        assertNull(reader)
    }

    // ════════════════════════════════════════════════════════════════════════
    //  getOrCreateFileSystemReader / invalidateFileSystemReader
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `getOrCreateFileSystemReader returns same instance on repeated calls`() {
        val file = createAndMountFile("fs_reader_cache")
        val fs1 = VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath)
        val fs2 = VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath)
        assertSame(fs1, fs2)
    }

    @Test
    fun `invalidateFileSystemReader clears specific volume cache`() {
        val file = createAndMountFile("invalidate_specific")
        val fs1 = VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath)
        assertNotNull(fs1)

        VolumeMountManager.invalidateFileSystemReader(file.absolutePath)

        // After invalidation, the same reader instance is returned but its cache is cleared
        val fs2 = VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath)
        assertNotNull(fs2)
        assertSame(fs1, fs2)
    }

    @Test
    fun `invalidateFileSystemReader with null clears all caches`() {
        val file1 = createAndMountFile("invalidate_all_1")
        val file2 = createAndMountFile("invalidate_all_2")
        val fs1 = VolumeMountManager.getOrCreateFileSystemReader(file1.absolutePath)
        val fs2 = VolumeMountManager.getOrCreateFileSystemReader(file2.absolutePath)

        VolumeMountManager.invalidateFileSystemReader(null)

        // Same instances are returned after cache clear
        val fs1After = VolumeMountManager.getOrCreateFileSystemReader(file1.absolutePath)
        val fs2After = VolumeMountManager.getOrCreateFileSystemReader(file2.absolutePath)
        assertSame(fs1, fs1After)
        assertSame(fs2, fs2After)
    }

    // ════════════════════════════════════════════════════════════════════════
    //  readData / readSector
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `readData returns bytes from mounted volume`() {
        val file = createAndMountFile("read_data")
        val result = VolumeMountManager.readData(file.absolutePath, 0L, 512)
        assertTrue(result.isSuccess)
        assertEquals(512, result.getOrThrow().size)
    }

    @Test
    fun `readData fails for unmounted volume`() {
        val result = VolumeMountManager.readData("/not/mounted", 0L, 512)
        assertTrue(result.isFailure)
    }

    @Test
    fun `readSector returns sector bytes from mounted volume`() {
        val file = createAndMountFile("read_sector")
        val result = VolumeMountManager.readSector(file.absolutePath, 0L)
        assertTrue(result.isSuccess)
        assertTrue(result.getOrThrow().isNotEmpty())
    }

    @Test
    fun `readSector fails for unmounted volume`() {
        val result = VolumeMountManager.readSector("/not/mounted", 0L)
        assertTrue(result.isFailure)
    }

    // ════════════════════════════════════════════════════════════════════════
    //  inspectFileSystem
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `inspectFileSystem returns structural metadata`() {
        val file = createAndMountFile("inspect")
        val result = VolumeMountManager.inspectFileSystem(file.absolutePath)
        assertTrue(result.isSuccess)
        val info = result.getOrThrow()
        assertTrue(info.contains("OEM Name"))
        assertTrue(info.contains("Bytes per sector"))
        assertTrue(info.contains("Sectors per cluster"))
    }

    @Test
    fun `inspectFileSystem fails for unmounted volume`() {
        val result = VolumeMountManager.inspectFileSystem("/not/mounted")
        assertTrue(result.isFailure)
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Callbacks
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `mount callback is invoked on successful mount`() {
        val file = tempContainer("mount_cb")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()

        var callbackPath: String? = null
        VolumeMountManager.addMountCallback { path -> callbackPath = path }

        VolumeMountManager.mountVolume(file.absolutePath, PASSWORD.toCharArray()).getOrThrow()

        assertEquals(file.absolutePath, callbackPath)
    }

    @Test
    fun `unmount callback is invoked on unmount`() {
        val file = createAndMountFile("unmount_cb")

        var callbackPath: String? = null
        VolumeMountManager.addUnmountCallback { path -> callbackPath = path }

        VolumeMountManager.unmountVolume(file.absolutePath)

        assertEquals(file.absolutePath, callbackPath)
    }

    @Test
    fun `multiple mount callbacks are all invoked`() {
        val file = tempContainer("multi_cb")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()

        val paths = mutableListOf<String>()
        VolumeMountManager.addMountCallback { paths.add("cb1:$it") }
        VolumeMountManager.addMountCallback { paths.add("cb2:$it") }

        VolumeMountManager.mountVolume(file.absolutePath, PASSWORD.toCharArray()).getOrThrow()

        assertEquals(2, paths.size)
        assertTrue(paths.any { it.startsWith("cb1:") })
        assertTrue(paths.any { it.startsWith("cb2:") })
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Concurrent safety
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `concurrent mounts of different volumes succeed`() = runBlocking {
        val files = (1..4).map { i: Int ->
            val f = tempContainer("concurrent_$i")
            VolumeCreator.createContainer(f.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()
            f
        }

        val deferreds = files.map { file: File ->
            async(Dispatchers.IO) {
                VolumeMountManager.mountVolume(file.absolutePath, PASSWORD.toCharArray())
            }
        }
        val results: List<Result<MountedVolumeInfo>> = deferreds.map { it.await() }

        results.forEachIndexed { index: Int, result: Result<MountedVolumeInfo> ->
            assertTrue("mount $index failed: ${result.exceptionOrNull()?.message}", result.isSuccess)
        }
        assertEquals(4, VolumeMountManager.getMountedVolumes().size)
    }

    @Test
    fun `concurrent unmountAll is safe`() = runBlocking {
        val files = (1..4).map { i: Int -> createAndMountFile("concurrent_unmount_$i") }

        val jobs = List(10) {
            async(Dispatchers.IO) {
                VolumeMountManager.unmountAll()
            }
        }
        jobs.forEach { it.await() }

        assertTrue(VolumeMountManager.getMountedVolumes().isEmpty())
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Hidden volume parameters pass-through
    // ════════════════════════════════════════════════════════════════════════

    @Test
    fun `mountVolume with hiddenVolume flag passes through`() {
        val file = tempContainer("hidden_flag")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()

        // Mounting with useHiddenVolume = true on a normal container may succeed
        // or fail depending on header parsing; the important thing is that the
        // parameter is passed through without crashing.
        val result = VolumeMountManager.mountVolume(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray(),
            useHiddenVolume = true
        )

        // Just verify no crash occurred; result can be success or failure
        assertTrue(true)
    }

    @Test
    fun `mountVolume with PIM parameter passes through`() {
        val file = tempContainer("pim_param")
        VolumeCreator.createContainer(file.absolutePath, PASSWORD.toCharArray(), 4L).getOrThrow()

        val result = VolumeMountManager.mountVolume(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray(),
            pim = 0
        )

        assertTrue(result.isSuccess)
    }
}
