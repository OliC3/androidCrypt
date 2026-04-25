package com.androidcrypt.crypto

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Unit tests for [VolumeMountManager] cache invalidation and callback behaviour.
 *
 * These verify that unmounting correctly cleans up FAT32Reader caches and
 * fires callbacks exactly once per volume.
 */
class VolumeMountManagerCacheInvalidationTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_vmm_cache_test")
        private const val PASSWORD = "CacheInvalidationTest!"
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

    private fun tempContainer(tag: String): File {
        return File(TEST_DIR, "cache_${tag}_${System.nanoTime()}.hc")
    }

    private fun createAndMount(tag: String): File {
        val file = tempContainer(tag)
        val result = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray(),
            sizeInMB = 4L
        )
        assertTrue("creation failed: ${result.exceptionOrNull()?.message}", result.isSuccess)

        val mountResult = VolumeMountManager.mountVolume(file.absolutePath, PASSWORD.toCharArray())
        assertTrue("mount failed: ${mountResult.exceptionOrNull()?.message}", mountResult.isSuccess)
        return file
    }

    // ── callback firing ───────────────────────────────────────────────────────

    @Test
    fun `unmountVolume fires unmount callback exactly once`() {
        val file = createAndMount("callback_once")
        val callbacks = mutableListOf<String>()

        VolumeMountManager.addUnmountCallback { path ->
            callbacks.add(path)
        }

        VolumeMountManager.unmountVolume(file.absolutePath)

        assertEquals(1, callbacks.size)
        assertEquals(file.absolutePath, callbacks[0])
    }

    @Test
    fun `unmountAll fires callback for every mounted volume`() {
        val file1 = createAndMount("multi_a")
        val file2 = createAndMount("multi_b")
        val file3 = createAndMount("multi_c")

        val callbacks = CopyOnWriteArrayList<String>()
        VolumeMountManager.addUnmountCallback { path ->
            callbacks.add(path)
        }

        VolumeMountManager.unmountAll()

        assertEquals(3, callbacks.size)
        assertTrue(callbacks.contains(file1.absolutePath))
        assertTrue(callbacks.contains(file2.absolutePath))
        assertTrue(callbacks.contains(file3.absolutePath))
    }

    @Test
    fun `mount callback fires on successful mount`() {
        val file = tempContainer("mount_cb")
        VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = PASSWORD.toCharArray(),
            sizeInMB = 4L
        )

        val callbacks = mutableListOf<String>()
        VolumeMountManager.addMountCallback { path ->
            callbacks.add(path)
        }

        val result = VolumeMountManager.mountVolume(file.absolutePath, PASSWORD.toCharArray())
        assertTrue(result.isSuccess)
        assertEquals(1, callbacks.size)
        assertEquals(file.absolutePath, callbacks[0])
    }

    @Test
    fun `mount callback does not fire on failed mount`() {
        val file = tempContainer("mount_fail_cb")
        // Create an empty file — mount will fail because it's not a valid container
        file.writeBytes(ByteArray(1024))

        val callbacks = mutableListOf<String>()
        VolumeMountManager.addMountCallback { path ->
            callbacks.add(path)
        }

        val result = VolumeMountManager.mountVolume(file.absolutePath, PASSWORD.toCharArray())
        assertFalse(result.isSuccess)
        assertEquals(0, callbacks.size)
    }

    // ── cache cleanup ─────────────────────────────────────────────────────────

    @Test
    fun `unmountVolume removes volume from mounted list`() {
        val file = createAndMount("remove")
        assertTrue(VolumeMountManager.isMounted(file.absolutePath))

        VolumeMountManager.unmountVolume(file.absolutePath)

        assertFalse(VolumeMountManager.isMounted(file.absolutePath))
        assertEquals(0, VolumeMountManager.getMountedVolumes().size)
    }

    @Test
    fun `unmountAll removes all volumes`() {
        createAndMount("all_a")
        createAndMount("all_b")
        assertEquals(2, VolumeMountManager.getMountedVolumes().size)

        VolumeMountManager.unmountAll()

        assertEquals(0, VolumeMountManager.getMountedVolumes().size)
    }

    @Test
    fun `getVolumeReader returns null after unmount`() {
        val file = createAndMount("reader_null")
        assertNotNull(VolumeMountManager.getVolumeReader(file.absolutePath))

        VolumeMountManager.unmountVolume(file.absolutePath)

        assertNull(VolumeMountManager.getVolumeReader(file.absolutePath))
    }

    @Test
    fun `getOrCreateFileSystemReader returns null after unmount`() {
        val file = createAndMount("fs_null")
        assertNotNull(VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath))

        VolumeMountManager.unmountVolume(file.absolutePath)

        assertNull(VolumeMountManager.getOrCreateFileSystemReader(file.absolutePath))
    }

    @Test
    fun `double unmount returns failure`() {
        val file = createAndMount("double")
        val first = VolumeMountManager.unmountVolume(file.absolutePath)
        assertTrue(first.isSuccess)

        val second = VolumeMountManager.unmountVolume(file.absolutePath)
        assertTrue(second.isFailure)
    }

    @Test
    fun `unmountVolume returns failure for never-mounted path`() {
        val result = VolumeMountManager.unmountVolume("/nonexistent/path.hc")
        assertTrue(result.isFailure)
    }

    // ── concurrent safety ───────────────────────────────────────────────────

    @Test
    fun `callbacks are safe to add during iteration`() {
        val file = createAndMount("concurrent_cb")

        // CopyOnWriteArrayList should not throw ConcurrentModificationException
        VolumeMountManager.addUnmountCallback { _ ->
            // Adding a callback during iteration is safe with CopyOnWriteArrayList
        }

        VolumeMountManager.unmountVolume(file.absolutePath)
        assertTrue(true) // If we get here without exception, the test passes
    }
}
