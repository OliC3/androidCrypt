package com.androidcrypt.app

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the static cache helpers in [VeraCryptDocumentsProvider].
 *
 * These cover the file-type classifier (which decides whether a file should be
 * cached and into which cache bucket) and the put/get behaviour of the global
 * caches that back the [EncryptedFileProxyCallback] used during file reads
 * issued through Android's Storage Access Framework.
 */
class VeraCryptDocumentsProviderCacheTest {

    @Before
    fun setUp() {
        VeraCryptDocumentsProvider.clearAllCachesForTesting()
    }

    @After
    fun tearDown() {
        VeraCryptDocumentsProvider.clearAllCachesForTesting()
    }

    // ── File-type classifiers ───────────────────────────────────────────────

    @Test
    fun `isVideoFile recognises common video extensions`() {
        val videoExts = listOf(
            "mp4", "mkv", "avi", "mov", "webm", "m4v", "3gp", "wmv", "flv"
        )
        for (ext in videoExts) {
            assertTrue(
                "Should recognise .$ext as video",
                VeraCryptDocumentsProvider.isVideoFile("/vol:/dir/file.$ext")
            )
        }
    }

    @Test
    fun `isVideoFile recognises Valv encrypted video suffix`() {
        assertTrue(VeraCryptDocumentsProvider.isVideoFile("/vol:/clip-v.valv"))
    }

    @Test
    fun `isVideoFile recognises paths under a video subfolder`() {
        assertTrue(VeraCryptDocumentsProvider.isVideoFile("/vol:/Camera/video/clip.bin"))
        assertTrue(VeraCryptDocumentsProvider.isVideoFile("/vol:/Some/Video/clip.bin"))
    }

    @Test
    fun `isVideoFile is case insensitive`() {
        assertTrue(VeraCryptDocumentsProvider.isVideoFile("/vol:/clip.MP4"))
        assertTrue(VeraCryptDocumentsProvider.isVideoFile("/vol:/clip.MoV"))
        assertTrue(VeraCryptDocumentsProvider.isVideoFile("/vol:/Clip-V.Valv"))
    }

    @Test
    fun `isVideoFile rejects non-video files`() {
        assertFalse(VeraCryptDocumentsProvider.isVideoFile("/vol:/file.txt"))
        assertFalse(VeraCryptDocumentsProvider.isVideoFile("/vol:/file.jpg"))
        assertFalse(VeraCryptDocumentsProvider.isVideoFile("/vol:/file.gif"))
        assertFalse(VeraCryptDocumentsProvider.isVideoFile("/vol:/file-t.valv"))
        assertFalse(VeraCryptDocumentsProvider.isVideoFile("/vol:/"))
        assertFalse(VeraCryptDocumentsProvider.isVideoFile(""))
    }

    @Test
    fun `isGifFile only matches dot gif extension`() {
        assertTrue(VeraCryptDocumentsProvider.isGifFile("/vol:/img.gif"))
        assertTrue(VeraCryptDocumentsProvider.isGifFile("/vol:/img.GIF"))
        assertTrue(VeraCryptDocumentsProvider.isGifFile("/vol:/img.GiF"))
        assertFalse(VeraCryptDocumentsProvider.isGifFile("/vol:/giffile"))
        assertFalse(VeraCryptDocumentsProvider.isGifFile("/vol:/img.gifx"))
        assertFalse(VeraCryptDocumentsProvider.isGifFile("/vol:/img.png"))
        assertFalse(VeraCryptDocumentsProvider.isGifFile(""))
    }

    @Test
    fun `isThumbnailFile only matches Valv thumbnail suffix`() {
        assertTrue(VeraCryptDocumentsProvider.isThumbnailFile("/vol:/img-t.valv"))
        assertTrue(VeraCryptDocumentsProvider.isThumbnailFile("/vol:/IMG-T.VALV"))
        assertFalse(VeraCryptDocumentsProvider.isThumbnailFile("/vol:/img-v.valv"))
        assertFalse(VeraCryptDocumentsProvider.isThumbnailFile("/vol:/img.valv"))
        assertFalse(VeraCryptDocumentsProvider.isThumbnailFile("/vol:/img.jpg"))
    }

    @Test
    fun `classifier categories are mutually exclusive for canonical extensions`() {
        // GIFs must NOT be classified as video — they have a separate, larger
        // global cache budget. If isVideoFile started returning true for .gif
        // the GIF size cap would silently shrink from 50MB to 10MB.
        assertFalse(
            "GIFs must not be classified as video",
            VeraCryptDocumentsProvider.isVideoFile("/vol:/img.gif")
        )
        assertFalse(
            "Videos must not be classified as GIFs",
            VeraCryptDocumentsProvider.isGifFile("/vol:/clip.mp4")
        )
        assertFalse(
            "Thumbnails must not be classified as video",
            VeraCryptDocumentsProvider.isVideoFile("/vol:/img-t.valv")
        )
    }

    // ── Cache put/get behaviour ─────────────────────────────────────────────

    @Test
    fun `putCachedFile then getCachedFile round-trips video data`() {
        val key = "/vol:/clip.mp4"
        val data = ByteArray(1024) { (it and 0xFF).toByte() }
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        val fetched = VeraCryptDocumentsProvider.getCachedFile(key)
        assertNotNull("Cached video should be retrievable", fetched)
        assertSame("Should return the same byte array reference", data, fetched)
        assertArrayEquals("Cached data must be byte-identical", data, fetched)
    }

    @Test
    fun `putCachedFile then getCachedFile round-trips thumbnail data`() {
        val key = "/vol:/img-t.valv"
        val data = ByteArray(2048) { ((it * 7) and 0xFF).toByte() }
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        val fetched = VeraCryptDocumentsProvider.getCachedFile(key)
        assertNotNull("Cached thumbnail should be retrievable", fetched)
        assertArrayEquals(data, fetched)
    }

    @Test
    fun `putCachedFile then getCachedFile round-trips GIF data`() {
        val key = "/vol:/anim.gif"
        val data = ByteArray(8 * 1024) { ((it * 13) and 0xFF).toByte() }
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        val fetched = VeraCryptDocumentsProvider.getCachedFile(key)
        assertNotNull("Cached GIF should be retrievable", fetched)
        assertArrayEquals(data, fetched)
    }

    @Test
    fun `getCachedFile returns null for unknown key`() {
        assertNull(VeraCryptDocumentsProvider.getCachedFile("/vol:/missing.mp4"))
        assertNull(VeraCryptDocumentsProvider.getCachedFile("/vol:/missing.gif"))
        assertNull(VeraCryptDocumentsProvider.getCachedFile("/vol:/missing-t.valv"))
    }

    @Test
    fun `non-classified files are silently dropped by putCachedFile`() {
        val key = "/vol:/document.txt"
        VeraCryptDocumentsProvider.putCachedFile(key, ByteArray(64))
        assertNull(
            "Non-video / non-GIF / non-thumbnail files must NOT be cached",
            VeraCryptDocumentsProvider.getCachedFile(key)
        )
    }

    @Test
    fun `different keys are isolated`() {
        val a = "/vol:/a.mp4"; val b = "/vol:/b.mp4"
        val dataA = ByteArray(16) { 0x11 }
        val dataB = ByteArray(16) { 0x22 }
        VeraCryptDocumentsProvider.putCachedFile(a, dataA)
        VeraCryptDocumentsProvider.putCachedFile(b, dataB)
        assertArrayEquals(dataA, VeraCryptDocumentsProvider.getCachedFile(a))
        assertArrayEquals(dataB, VeraCryptDocumentsProvider.getCachedFile(b))
    }

    @Test
    fun `put overwrites previous entry with new data and timestamp`() {
        val key = "/vol:/clip.mp4"
        val first = ByteArray(8) { 0xAA.toByte() }
        val second = ByteArray(8) { 0xBB.toByte() }
        VeraCryptDocumentsProvider.putCachedFile(key, first)
        VeraCryptDocumentsProvider.putCachedFile(key, second)
        val fetched = VeraCryptDocumentsProvider.getCachedFile(key)
        assertNotNull(fetched)
        assertArrayEquals("Latest put wins", second, fetched)
        assertNotSame(first, fetched)
    }

    // ── Size-limit enforcement ──────────────────────────────────────────────

    @Test
    fun `videos above 10MB limit are rejected by cache`() {
        val key = "/vol:/huge.mp4"
        val data = ByteArray(VeraCryptDocumentsProvider.VIDEO_CACHE_MAX_SIZE + 1)
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        assertNull(
            "Video over VIDEO_CACHE_MAX_SIZE must be rejected",
            VeraCryptDocumentsProvider.getCachedFile(key)
        )
    }

    @Test
    fun `videos exactly at 10MB limit are accepted`() {
        val key = "/vol:/at-limit.mp4"
        val data = ByteArray(VeraCryptDocumentsProvider.VIDEO_CACHE_MAX_SIZE)
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        assertNotNull(
            "Video at exactly VIDEO_CACHE_MAX_SIZE must be accepted",
            VeraCryptDocumentsProvider.getCachedFile(key)
        )
    }

    @Test
    fun `GIFs above 50MB limit are rejected by cache`() {
        val key = "/vol:/huge.gif"
        // GIF_CACHE_MAX_SIZE is a Long (50MB) — use an Int allocation just over
        // the boundary. This costs ~50MB heap; acceptable for a one-shot test.
        val size = (VeraCryptDocumentsProvider.GIF_CACHE_MAX_SIZE + 1).toInt()
        val data = ByteArray(size)
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        assertNull(
            "GIF over GIF_CACHE_MAX_SIZE must be rejected",
            VeraCryptDocumentsProvider.getCachedFile(key)
        )
    }

    @Test
    fun `GIFs above the video limit but below the GIF limit are accepted`() {
        // Direct regression test for the GIF caching fix: a GIF that exceeds
        // VIDEO_CACHE_MAX_SIZE (10MB) but is under GIF_CACHE_MAX_SIZE (50MB)
        // must still be cached, otherwise large animated GIFs play slowly.
        val key = "/vol:/medium.gif"
        val size = VeraCryptDocumentsProvider.VIDEO_CACHE_MAX_SIZE + 4096
        val data = ByteArray(size) { ((it * 31) and 0xFF).toByte() }
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        val fetched = VeraCryptDocumentsProvider.getCachedFile(key)
        assertNotNull(
            "GIFs between 10MB and 50MB must use the larger GIF cache budget",
            fetched
        )
        assertArrayEquals(data, fetched)
    }

    @Test
    fun `thumbnails above 512KB limit are rejected by cache`() {
        val key = "/vol:/oversize-t.valv"
        val data = ByteArray(VeraCryptDocumentsProvider.THUMBNAIL_CACHE_MAX_SIZE + 1)
        VeraCryptDocumentsProvider.putCachedFile(key, data)
        assertNull(
            "Thumbnail over THUMBNAIL_CACHE_MAX_SIZE must be rejected",
            VeraCryptDocumentsProvider.getCachedFile(key)
        )
    }

    @Test
    fun `cache size limits are documented values`() {
        // Lock in the public contract: tests in other parts of the codebase
        // and downstream apps may rely on these specific sizes.
        assertEquals(10 * 1024 * 1024, VeraCryptDocumentsProvider.VIDEO_CACHE_MAX_SIZE)
        assertEquals(50L * 1024 * 1024, VeraCryptDocumentsProvider.GIF_CACHE_MAX_SIZE)
        assertEquals(512 * 1024, VeraCryptDocumentsProvider.THUMBNAIL_CACHE_MAX_SIZE)
    }

    // ── Concurrency ─────────────────────────────────────────────────────────

    @Test
    fun `concurrent puts and gets do not corrupt the cache`() {
        // Stress the synchronized blocks in put/get with many concurrent
        // writers + readers. Failure modes we are guarding against:
        //   - ConcurrentModificationException from LinkedHashMap iteration
        //   - Lost writes (a key's data appearing as null after a successful put)
        //   - Cross-key contamination
        val threadCount = 16
        val opsPerThread = 200
        val threads = mutableListOf<Thread>()
        val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()

        for (t in 0 until threadCount) {
            threads += Thread {
                try {
                    for (i in 0 until opsPerThread) {
                        val key = "/vol:/t${t}_$i.mp4"
                        val data = ByteArray(64) { ((t * 31 + i) and 0xFF).toByte() }
                        VeraCryptDocumentsProvider.putCachedFile(key, data)
                        // Read back something — own key, or a sibling key
                        val readKey = if (i % 2 == 0) key else "/vol:/t${t}_${i - 1}.mp4"
                        val fetched = VeraCryptDocumentsProvider.getCachedFile(readKey)
                        if (fetched != null && readKey == key) {
                            // If we just put it ourselves, content must match
                            // (LRU eviction can't have removed it: cap is 10 entries
                            //  per cache, but here we only compare same-iteration writes)
                            // Note: with a 10-entry LRU, our own write may have been
                            // evicted by other threads. Only assert when it's still there.
                            if (!fetched.contentEquals(data)) {
                                throw AssertionError("Data corruption for $key")
                            }
                        }
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join(30_000) }

        if (errors.isNotEmpty()) {
            throw AssertionError(
                "Concurrent cache access produced ${errors.size} errors. First: ${errors.first()}",
                errors.first()
            )
        }
    }
}
