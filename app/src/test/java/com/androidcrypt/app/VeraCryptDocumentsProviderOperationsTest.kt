package com.androidcrypt.app

import android.content.ContentProvider
import android.content.pm.ProviderInfo
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import com.androidcrypt.crypto.VolumeCreator
import com.androidcrypt.crypto.VolumeMountManager
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.FileNotFoundException

/**
 * End-to-end tests for [VeraCryptDocumentsProvider]'s SAF operations against a
 * real mounted container: queryRoots/queryChildDocuments/queryDocument,
 * createDocument, deleteDocument, moveDocument, copyDocument, and the
 * openDocument write pipe.
 *
 * This is the exact surface through which external file managers operate —
 * issue #9 (delete not freeing space) and issue #15 (truncated names) both
 * manifested through this provider while the FAT32 layer underneath was
 * correct, so the provider layer gets its own regression coverage here.
 */
@RunWith(RobolectricTestRunner::class)
class VeraCryptDocumentsProviderOperationsTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_provider_ops")
        private const val PASSWORD = "ProviderOps!"
        private const val AUTHORITY = "com.androidcrypt.documents"
    }

    private lateinit var containerFile: File
    private lateinit var provider: VeraCryptDocumentsProvider

    @Before
    fun setUp() {
        TEST_DIR.mkdirs()
        containerFile = File(TEST_DIR, "prov_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(containerFile.absolutePath, PASSWORD.toCharArray(), 10).getOrThrow()
        VolumeMountManager.mountVolume(containerFile.absolutePath, PASSWORD.toCharArray()).getOrThrow()

        provider = VeraCryptDocumentsProvider()
        // ContentProvider.attachInfo is @hide — invoke reflectively (Robolectric).
        val info = ProviderInfo().apply {
            authority = AUTHORITY
            packageName = "com.androidcrypt"
            name = VeraCryptDocumentsProvider::class.java.name
            exported = true
            grantUriPermissions = true
            // DocumentsProvider.attachInfo enforces this guard
            readPermission = "android.permission.MANAGE_DOCUMENTS"
            writePermission = "android.permission.MANAGE_DOCUMENTS"
        }
        val attach = ContentProvider::class.java.getDeclaredMethod(
            "attachInfo", android.content.Context::class.java, ProviderInfo::class.java
        )
        attach.isAccessible = true
        attach.invoke(provider, RuntimeEnvironment.getApplication(), info)
        provider.onCreate()
    }

    @After
    fun tearDown() {
        VolumeMountManager.unmountAll()
        containerFile.delete()
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private fun queryRootId(): String {
        val cursor = provider.queryRoots(arrayOf(Root.COLUMN_ROOT_ID, Root.COLUMN_TITLE,
            Root.COLUMN_AVAILABLE_BYTES, Root.COLUMN_CAPACITY_BYTES))
        assertTrue("queryRoots returned no rows — is the volume mounted?", cursor.moveToFirst())
        val idx = cursor.getColumnIndex(Root.COLUMN_ROOT_ID)
        val rootId = cursor.getString(idx)
        cursor.close()
        return rootId
    }

    private fun childNames(parentDocId: String): List<String> {
        val cursor = provider.queryChildDocuments(parentDocId,
            arrayOf(Document.COLUMN_DISPLAY_NAME), null as String?)
        val names = mutableListOf<String>()
        val nameIdx = cursor.getColumnIndex(Document.COLUMN_DISPLAY_NAME)
        while (cursor.moveToNext()) names.add(cursor.getString(nameIdx))
        cursor.close()
        return names
    }

    private fun fsReader() =
        VolumeMountManager.getOrCreateFileSystemReader(containerFile.absolutePath)!!

    // ── roots / queries ─────────────────────────────────────────────────────

    @Test
    fun `queryRoots exposes the mounted volume with capacity`() {
        val cursor = provider.queryRoots(arrayOf(Root.COLUMN_ROOT_ID, Root.COLUMN_TITLE, Root.COLUMN_AVAILABLE_BYTES, Root.COLUMN_CAPACITY_BYTES))
        assertTrue(cursor.moveToFirst())
        val available = cursor.getLong(cursor.getColumnIndex(Root.COLUMN_AVAILABLE_BYTES))
        val capacity = cursor.getLong(cursor.getColumnIndex(Root.COLUMN_CAPACITY_BYTES))
        val title = cursor.getString(cursor.getColumnIndex(Root.COLUMN_TITLE))
        assertTrue("available bytes should be positive", available > 0)
        assertTrue("capacity should exceed 5 MB", capacity > 5L * 1024 * 1024)
        assertFalse(title.isNullOrEmpty())
        cursor.close()
    }

    @Test
    fun `queryDocument returns metadata for created file`() {
        val rootId = queryRootId()
        val rootDocId = "$rootId:/"
        val docId = provider.createDocument(rootDocId, "application/octet-stream", "meta test.bin")!!

        val cursor = provider.queryDocument(docId, arrayOf(Document.COLUMN_DISPLAY_NAME, Document.COLUMN_SIZE))
        assertTrue(cursor.moveToFirst())
        assertEquals("meta test.bin", cursor.getString(cursor.getColumnIndex(Document.COLUMN_DISPLAY_NAME)))
        assertEquals(0L, cursor.getLong(cursor.getColumnIndex(Document.COLUMN_SIZE)))
        cursor.close()
    }

    // ── issue #15 regression: names must survive the provider verbatim ──────

    @Test
    fun `createDocument preserves long mixed-case filename`() {
        val rootId = queryRootId()
        val rootDocId = "$rootId:/"
        val name = "My Vacation Photo (edited) 2026.jpeg"
        provider.createDocument(rootDocId, "image/jpeg", name)

        val names = childNames(rootDocId)
        assertTrue("expected '$name' in $names", name in names)
    }

    @Test
    fun `createDocument in subdirectory preserves names`() {
        val rootId = queryRootId()
        val rootDocId = "$rootId:/"
        val dirDocId = provider.createDocument(rootDocId, Document.MIME_TYPE_DIR, "My Folder")!!
        provider.createDocument(dirDocId, "text/plain", "notes for meeting.txt")

        val names = childNames(dirDocId)
        assertTrue("expected child in $names", "notes for meeting.txt" in names)
        assertTrue("My Folder" in childNames(rootDocId))
    }

    // ── issue #9 regression: delete must free the space ─────────────────────

    @Test
    fun `deleteDocument frees the file's space`() {
        val rootId = queryRootId()
        val rootDocId = "$rootId:/"

        val before = fsReader().countFreeClusters()
        val docId = provider.createDocument(rootDocId, "application/octet-stream", "big file.bin")!!
        val data = ByteArray(512 * 1024) { (it % 251).toByte() }
        fsReader().writeFile("/big file.bin", data).getOrThrow()
        val afterWrite = fsReader().countFreeClusters()
        assertTrue("write should consume clusters", afterWrite < before)

        provider.deleteDocument(docId)

        assertFalse("file should be gone", fsReader().exists("/big file.bin"))
        assertEquals("delete must return the clusters to the free pool",
            before, fsReader().countFreeClusters())
    }

    // ── move / copy ─────────────────────────────────────────────────────────

    @Test
    fun `moveDocument relocates file preserving name and content`() {
        val rootId = queryRootId()
        val rootDocId = "$rootId:/"
        val dirDocId = provider.createDocument(rootDocId, Document.MIME_TYPE_DIR, "Target Dir")!!

        val docId = provider.createDocument(rootDocId, "text/plain", "moving file.txt")!!
        val payload = "move me".toByteArray()
        fsReader().writeFile("/moving file.txt", payload).getOrThrow()

        val newDocId = provider.moveDocument(docId, rootDocId, dirDocId)
        assertNotNull(newDocId)

        assertFalse(fsReader().exists("/moving file.txt"))
        assertTrue(fsReader().exists("/Target Dir/moving file.txt"))
        assertArrayEquals(payload, fsReader().readFile("/Target Dir/moving file.txt").getOrThrow())
    }

    @Test
    fun `copyDocument duplicates file with identical content`() {
        val rootId = queryRootId()
        val rootDocId = "$rootId:/"
        val dirDocId = provider.createDocument(rootDocId, Document.MIME_TYPE_DIR, "Copies")!!

        val docId = provider.createDocument(rootDocId, "text/plain", "original.txt")!!
        val payload = "copy me please".toByteArray()
        fsReader().writeFile("/original.txt", payload).getOrThrow()

        val newDocId = provider.copyDocument(docId, dirDocId)
        assertNotNull(newDocId)

        assertArrayEquals(payload, fsReader().readFile("/original.txt").getOrThrow())
        assertArrayEquals(payload, fsReader().readFile("/Copies/original.txt").getOrThrow())
    }

    // ── write path (SAF copy-in) ────────────────────────────────────────────

    @Test
    fun `openDocument write mode streams content into the volume`() {
        val rootId = queryRootId()
        val rootDocId = "$rootId:/"
        val docId = provider.createDocument(rootDocId, "application/octet-stream", "piped.bin")!!

        val payload = ByteArray(300 * 1024) { (it * 7 % 256).toByte() }
        val pfd = provider.openDocument(docId, "w", null)
        android.os.ParcelFileDescriptor.AutoCloseOutputStream(pfd).use { out ->
            out.write(payload)
        }

        // The pipe writer drains asynchronously — wait for the FS to settle.
        val deadline = System.currentTimeMillis() + 15_000
        var ok = false
        while (System.currentTimeMillis() < deadline) {
            val info = fsReader().getFileInfo("/piped.bin").getOrNull()
            if (info != null && info.size == payload.size.toLong()) {
                ok = runCatching {
                    fsReader().readFile("/piped.bin").getOrThrow().contentEquals(payload)
                }.getOrDefault(false)
                if (ok) break
            }
            Thread.sleep(100)
        }
        assertTrue("content written through the SAF pipe did not land in the volume", ok)
    }

    // ── security ────────────────────────────────────────────────────────────

    @Test
    fun `queryDocument rejects path traversal`() {
        val rootId = queryRootId()
        try {
            provider.queryDocument("$rootId:/../outside", arrayOf(Document.COLUMN_DISPLAY_NAME))
            fail("traversal docId must be rejected")
        } catch (e: FileNotFoundException) {
            // expected — parseDocumentId throws SecurityException, surfaced as FNFE
        }
    }
}
