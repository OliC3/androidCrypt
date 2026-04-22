package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for charArrayToUtf8Bytes() — the password encoding function.
 * This is security-critical: a bug here silently breaks all password-based operations.
 */
class CryptoUtilsTest {

    @Test
    fun `empty char array returns empty byte array`() {
        val result = charArrayToUtf8Bytes(charArrayOf())
        assertEquals(0, result.size)
    }

    @Test
    fun `ASCII password encodes correctly`() {
        val result = charArrayToUtf8Bytes("hello".toCharArray())
        assertArrayEquals("hello".toByteArray(Charsets.UTF_8), result)
    }

    @Test
    fun `numeric password`() {
        val result = charArrayToUtf8Bytes("123456".toCharArray())
        assertArrayEquals("123456".toByteArray(Charsets.UTF_8), result)
    }

    @Test
    fun `special characters`() {
        val pw = "p@ss!w0rd#$%^&*()".toCharArray()
        val result = charArrayToUtf8Bytes(pw)
        assertArrayEquals("p@ss!w0rd#$%^&*()".toByteArray(Charsets.UTF_8), result)
    }

    @Test
    fun `Unicode 2-byte characters`() {
        // German umlauts: ä=0xC3A4, ö=0xC3B6, ü=0xC3BC
        val pw = "pässwörd".toCharArray()
        val result = charArrayToUtf8Bytes(pw)
        assertArrayEquals("pässwörd".toByteArray(Charsets.UTF_8), result)
        // Verify it's longer than char count (multi-byte encoding)
        assertTrue("UTF-8 should be longer than ASCII", result.size > pw.size)
    }

    @Test
    fun `Unicode 3-byte characters`() {
        // CJK: 密码 (mì mǎ = password in Chinese)
        val pw = "密码test".toCharArray()
        val result = charArrayToUtf8Bytes(pw)
        assertArrayEquals("密码test".toByteArray(Charsets.UTF_8), result)
    }

    @Test
    fun `Unicode 4-byte characters - emoji`() {
        // Emoji: 🔑 (U+1F511) requires surrogate pair in Java chars
        val pw = "key🔑".toCharArray()
        val result = charArrayToUtf8Bytes(pw)
        assertArrayEquals("key🔑".toByteArray(Charsets.UTF_8), result)
    }

    @Test
    fun `single character`() {
        val result = charArrayToUtf8Bytes(charArrayOf('A'))
        assertArrayEquals(byteArrayOf(0x41), result)
    }

    @Test
    fun `max ASCII password 64 chars`() {
        val pw = "A".repeat(64).toCharArray()
        val result = charArrayToUtf8Bytes(pw)
        assertEquals(64, result.size)
        assertTrue(result.all { it == 0x41.toByte() })
    }

    @Test
    fun `very long password 1000 chars`() {
        val pw = "x".repeat(1000).toCharArray()
        val result = charArrayToUtf8Bytes(pw)
        assertEquals(1000, result.size)
    }

    @Test
    fun `null character in password`() {
        // Null chars are valid — some password managers produce them
        val pw = charArrayOf('a', '\u0000', 'b')
        val result = charArrayToUtf8Bytes(pw)
        assertEquals(3, result.size)
        assertEquals(0x61.toByte(), result[0])
        assertEquals(0x00.toByte(), result[1])
        assertEquals(0x62.toByte(), result[2])
    }

    @Test
    fun `deterministic - same input gives same output`() {
        val pw = "deterministic!".toCharArray()
        val r1 = charArrayToUtf8Bytes(pw)
        val r2 = charArrayToUtf8Bytes(pw)
        assertArrayEquals(r1, r2)
    }

    @Test
    fun `result matches String toByteArray for all printable ASCII`() {
        // Verify our non-String path matches String.toByteArray for all printable ASCII
        val pw = (32..126).map { it.toChar() }.toCharArray()
        val expected = String(pw).toByteArray(Charsets.UTF_8)
        val result = charArrayToUtf8Bytes(pw)
        assertArrayEquals("Should match String.toByteArray for printable ASCII", expected, result)
    }

    @Test
    fun `lone surrogate is replaced not propagated`() {
        // A lone high surrogate (\uD800) without a low surrogate is malformed.
        // The encoder uses CodingErrorAction.REPLACE, so it should produce the
        // UTF-8 replacement character rather than crashing or producing invalid UTF-8.
        // This documents that lone surrogates silently change the password.
        val pw = charArrayOf('a', '\uD800', 'b')
        val result = charArrayToUtf8Bytes(pw)
        // Should not throw and should produce a valid byte array
        assertTrue("Result should be non-empty", result.isNotEmpty())
        // First byte must be 'a', last byte must be 'b'
        assertEquals("First byte should be 'a'", 0x61.toByte(), result[0])
        assertEquals("Last byte should be 'b'", 0x62.toByte(), result[result.size - 1])
        // The result should differ from encoding just "ab" (the surrogate adds bytes)
        val withoutSurrogate = charArrayToUtf8Bytes(charArrayOf('a', 'b'))
        assertFalse(
            "Lone surrogate should produce different bytes than skipping it",
            result.contentEquals(withoutSurrogate)
        )
    }
}
