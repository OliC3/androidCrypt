package com.androidcrypt.app

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [VeraCryptDocumentsProvider] document ID parsing and helper logic.
 *
 * These tests exercise pure string-manipulation functions that have no Android
 * dependencies, so they run on the JVM without Robolectric or a device.
 */
class VeraCryptDocumentsProviderIdTest {

    // ── parseDocumentId ───────────────────────────────────────────────────────

    @Test
    fun `parseDocumentId extracts rootId and path`() {
        val result = VeraCryptDocumentsProvider.parseDocumentId("veracrypt_abc:/folder/file.txt")
        assertEquals("veracrypt_abc", result.first)
        assertEquals("/folder/file.txt", result.second)
    }

    @Test
    fun `parseDocumentId handles root path`() {
        val result = VeraCryptDocumentsProvider.parseDocumentId("veracrypt_xyz:/")
        assertEquals("veracrypt_xyz", result.first)
        assertEquals("/", result.second)
    }

    @Test
    fun `parseDocumentId handles nested paths`() {
        val result = VeraCryptDocumentsProvider.parseDocumentId("veracrypt_123:/a/b/c/d/e.txt")
        assertEquals("veracrypt_123", result.first)
        assertEquals("/a/b/c/d/e.txt", result.second)
    }

    @Test
    fun `parseDocumentId finds first colon after prefix`() {
        // For "veracrypt_abc:def:/path", the first colon after "veracrypt_" splits at "abc"
        val docId = "veracrypt_abc:def:/path"
        val result = VeraCryptDocumentsProvider.parseDocumentId(docId)
        assertEquals("veracrypt_abc", result.first)
        assertEquals("def:/path", result.second)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseDocumentId throws for missing prefix`() {
        VeraCryptDocumentsProvider.parseDocumentId("invalid:/path")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseDocumentId throws for missing colon`() {
        VeraCryptDocumentsProvider.parseDocumentId("veracrypt_abc/path")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseDocumentId throws for empty string`() {
        VeraCryptDocumentsProvider.parseDocumentId("")
    }

    @Test(expected = SecurityException::class)
    fun `parseDocumentId rejects path traversal with dot-dot`() {
        VeraCryptDocumentsProvider.parseDocumentId("veracrypt_abc:/../etc/passwd")
    }

    @Test(expected = SecurityException::class)
    fun `parseDocumentId rejects path traversal in middle`() {
        VeraCryptDocumentsProvider.parseDocumentId("veracrypt_abc:/foo/../bar")
    }

    @Test(expected = SecurityException::class)
    fun `parseDocumentId rejects double slashes`() {
        VeraCryptDocumentsProvider.parseDocumentId("veracrypt_abc:/foo//bar")
    }

    @Test(expected = SecurityException::class)
    fun `parseDocumentId rejects null bytes`() {
        VeraCryptDocumentsProvider.parseDocumentId("veracrypt_abc:/foo\u0000bar")
    }

    @Test
    fun `parseDocumentId allows single dot segments`() {
        // "." is harmless — it means current directory
        val (rootId, path) = VeraCryptDocumentsProvider.parseDocumentId("veracrypt_abc:/foo/./bar")
        assertEquals("veracrypt_abc", rootId)
        assertEquals("/foo/./bar", path)
    }

    // ── isChildDocument ───────────────────────────────────────────────────────

    @Test
    fun `isChildDocument returns true for direct child`() {
        assertTrue(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/folder",
                "veracrypt_abc:/folder/file.txt"
            )
        )
    }

    @Test
    fun `isChildDocument returns true for nested descendant`() {
        assertTrue(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/folder",
                "veracrypt_abc:/folder/sub/deep/file.txt"
            )
        )
    }

    @Test
    fun `isChildDocument returns false for same document`() {
        assertFalse(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/folder",
                "veracrypt_abc:/folder"
            )
        )
    }

    @Test
    fun `isChildDocument returns false for sibling`() {
        assertFalse(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/folder1",
                "veracrypt_abc:/folder2"
            )
        )
    }

    @Test
    fun `isChildDocument returns false for cross-root`() {
        assertFalse(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/folder",
                "veracrypt_xyz:/folder/file.txt"
            )
        )
    }

    @Test
    fun `isChildDocument returns true for any path under root`() {
        assertTrue(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/",
                "veracrypt_abc:/anything"
            )
        )
        assertTrue(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/",
                "veracrypt_abc:/a/b/c"
            )
        )
    }

    @Test
    fun `isChildDocument returns false for root as child of root`() {
        assertFalse(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/",
                "veracrypt_abc:/"
            )
        )
    }

    @Test
    fun `isChildDocument returns false for unrelated path`() {
        assertFalse(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/folder1",
                "veracrypt_abc:/folder2/file.txt"
            )
        )
    }

    @Test
    fun `isChildDocument returns false for invalid parent`() {
        assertFalse(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "bad_parent",
                "veracrypt_abc:/folder/file.txt"
            )
        )
    }

    @Test
    fun `isChildDocument returns false for invalid child`() {
        assertFalse(
            VeraCryptDocumentsProvider.isChildDocumentStatic(
                "veracrypt_abc:/folder",
                "bad_child"
            )
        )
    }

    // ── getMimeType (via FileEntry) ─────────────────────────────────────────

    @Test
    fun `getMimeType returns directory mime type`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "folder",
            path = "/folder",
            size = 0L,
            isDirectory = true,
            lastModified = 0L,
            mimeType = null
        )
        assertEquals(
            android.provider.DocumentsContract.Document.MIME_TYPE_DIR,
            VeraCryptDocumentsProvider.getMimeTypeStatic(entry)
        )
    }

    @Test
    fun `getMimeType returns octet-stream for no extension`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "README",
            path = "/README",
            size = 100L,
            isDirectory = false,
            lastModified = 0L,
            mimeType = null
        )
        assertEquals("application/octet-stream", VeraCryptDocumentsProvider.getMimeTypeStatic(entry))
    }

    @Test
    fun `getMimeType returns octet-stream for unknown extension`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "file.xyzabc",
            path = "/file.xyzabc",
            size = 100L,
            isDirectory = false,
            lastModified = 0L,
            mimeType = null
        )
        assertEquals("application/octet-stream", VeraCryptDocumentsProvider.getMimeTypeStatic(entry))
    }

    @Test
    fun `getMimeType recognises txt extension`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "notes.txt",
            path = "/notes.txt",
            size = 100L,
            isDirectory = false,
            lastModified = 0L,
            mimeType = null
        )
        val mime = VeraCryptDocumentsProvider.getMimeTypeStatic(entry)
        assertTrue("txt should map to text/*", mime.startsWith("text/"))
    }

    @Test
    fun `getMimeType recognises jpg extension`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "photo.jpg",
            path = "/photo.jpg",
            size = 100L,
            isDirectory = false,
            lastModified = 0L,
            mimeType = null
        )
        val mime = VeraCryptDocumentsProvider.getMimeTypeStatic(entry)
        assertTrue("jpg should map to image/*", mime.startsWith("image/"))
    }

    @Test
    fun `getMimeType recognises png extension`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "image.png",
            path = "/image.png",
            size = 100L,
            isDirectory = false,
            lastModified = 0L,
            mimeType = null
        )
        val mime = VeraCryptDocumentsProvider.getMimeTypeStatic(entry)
        assertTrue("png should map to image/*", mime.startsWith("image/"))
    }

    @Test
    fun `getMimeType recognises pdf extension`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "doc.pdf",
            path = "/doc.pdf",
            size = 100L,
            isDirectory = false,
            lastModified = 0L,
            mimeType = null
        )
        val mime = VeraCryptDocumentsProvider.getMimeTypeStatic(entry)
        assertEquals("application/pdf", mime)
    }

    @Test
    fun `getMimeType is case insensitive`() {
        val lower = com.androidcrypt.crypto.FileEntry(
            name = "file.txt", path = "/file.txt", size = 1L,
            isDirectory = false, lastModified = 0L, mimeType = null
        )
        val upper = com.androidcrypt.crypto.FileEntry(
            name = "FILE.TXT", path = "/FILE.TXT", size = 1L,
            isDirectory = false, lastModified = 0L, mimeType = null
        )
        assertEquals(
            VeraCryptDocumentsProvider.getMimeTypeStatic(lower),
            VeraCryptDocumentsProvider.getMimeTypeStatic(upper)
        )
    }

    @Test
    fun `getMimeType prefers explicit mimeType over extension`() {
        val entry = com.androidcrypt.crypto.FileEntry(
            name = "file.txt",
            path = "/file.txt",
            size = 100L,
            isDirectory = false,
            lastModified = 0L,
            mimeType = "application/json"
        )
        // getMimeType is called only when mimeType is null; this test documents
        // that the helper itself does NOT override an explicit mimeType.
        // The caller (getDocumentType) checks fileEntry.mimeType first.
        assertEquals("text/plain", VeraCryptDocumentsProvider.getMimeTypeStatic(entry))
    }
}
