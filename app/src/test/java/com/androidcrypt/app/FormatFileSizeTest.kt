package com.androidcrypt.app

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [formatFileSize]. Regression guard for issue #13: integer
 * GB truncation rendered 1824 MB of free space as "1 GB" — which exactly
 * matched the hidden volume's size and looked like the app subtracts the
 * hidden volume from the outer volume's free space (plausible-deniability
 * scare). Fractional units make the distinction visible.
 */
class FormatFileSizeTest {

    @Test
    fun `bytes below 1 KB stay integer`() {
        assertEquals("0 B", formatFileSize(0))
        assertEquals("512 B", formatFileSize(512))
        assertEquals("1023 B", formatFileSize(1023))
    }

    @Test
    fun `KB range shows one decimal`() {
        assertEquals("1.0 KB", formatFileSize(1024))
        assertEquals("1.5 KB", formatFileSize(1536))
    }

    @Test
    fun `MB range shows one decimal`() {
        assertEquals("223.0 MB", formatFileSize(223L * 1024 * 1024))
        assertEquals("1023.5 MB", formatFileSize((1023.5 * 1024 * 1024).toLong()))
    }

    @Test
    fun `issue 13 - 1824 MB must not display as exactly 1 GB`() {
        // The reporter's setup: 2048 MB container, 223 MB used, 1824 MB free.
        // Integer division rendered this as "1 GB", indistinguishable from the
        // hidden volume's 1024 MB being subtracted.
        val freeBytes = 1824L * 1024 * 1024
        val rendered = formatFileSize(freeBytes)
        assertEquals("1.8 GB", rendered)
        assertNotEquals("1 GB", rendered)
    }

    @Test
    fun `exactly 1 GB still displays as such`() {
        assertEquals("1.0 GB", formatFileSize(1024L * 1024 * 1024))
    }

    @Test
    fun `large values use GB`() {
        assertEquals("2.0 GB", formatFileSize(2048L * 1024 * 1024))
        assertEquals("10.0 GB", formatFileSize(10L * 1024 * 1024 * 1024))
    }
}
