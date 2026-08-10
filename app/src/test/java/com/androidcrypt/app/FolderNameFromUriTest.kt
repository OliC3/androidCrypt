package com.androidcrypt.app

import android.content.Context
import android.net.Uri
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner

/**
 * Tests [getFolderNameFromUri] — extracts a usable folder name from the
 * tree/document URIs that ACTION_OPEN_DOCUMENT_TREE yields. The "copied_folder"
 * fallback is the only thing standing between a successful folder copy and a
 * crash when the URI has no usable last segment, so it gets a regression test.
 */
@RunWith(RobolectricTestRunner::class)
class FolderNameFromUriTest {

    private val ctx: Context = mock()

    @Test
    fun `tree URI with Documents path yields the leaf folder name`() {
        val uri = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3ADocuments%2FMyFolder")
        assertEquals("MyFolder", getFolderNameFromUri(ctx, uri))
    }

    @Test
    fun `tree URI with SD card root yields the storage label`() {
        val uri = Uri.parse("content://com.android.externalstorage.documents/tree/1234-5678%3APhotos")
        assertEquals("Photos", getFolderNameFromUri(ctx, uri))
    }

    @Test
    fun `tree URI with nested subfolder yields the deepest folder name`() {
        val uri = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3ADCIM%2FCamera%2F2026")
        assertEquals("2026", getFolderNameFromUri(ctx, uri))
    }
}
