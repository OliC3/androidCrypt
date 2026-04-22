package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for the Crc32 implementation used in volume header validation.
 * Known CRC32 vectors from standard references (ISO 3309 / ITU-T V.42).
 */
class Crc32Test {

    @Test
    fun `known vector - 123456789`() {
        // CRC32 of "123456789" = 0xCBF43926 (standard check value)
        val data = "123456789".toByteArray(Charsets.US_ASCII)
        val crc = Crc32.calculate(data)
        assertEquals("CRC32 of '123456789'", 0xCBF43926.toInt(), crc)
    }

    @Test
    fun `empty input`() {
        val crc = Crc32.calculate(ByteArray(0))
        assertEquals("CRC32 of empty data", 0x00000000, crc)
    }

    @Test
    fun `single byte zero`() {
        val crc = Crc32.calculate(byteArrayOf(0x00))
        assertEquals(0xD202EF8D.toInt(), crc)
    }

    @Test
    fun `single byte 0xFF`() {
        val crc = Crc32.calculate(byteArrayOf(0xFF.toByte()))
        assertEquals(0xFF000000.toInt(), crc)
    }

    @Test
    fun `all zeros 4 bytes`() {
        val crc = Crc32.calculate(ByteArray(4))
        assertEquals(0x2144DF1C, crc)
    }

    @Test
    fun `offset and length sub-range`() {
        // Calculate CRC of "345" embedded in "12345678"
        val data = "12345678".toByteArray(Charsets.US_ASCII)
        val subRange = Crc32.calculate(data, offset = 2, length = 3)

        // Compare to CRC of "345" directly
        val direct = Crc32.calculate("345".toByteArray(Charsets.US_ASCII))
        assertEquals("Sub-range CRC should match direct", direct, subRange)
    }

    @Test
    fun `offset at start is same as no offset`() {
        val data = "Hello, World!".toByteArray()
        assertEquals(
            Crc32.calculate(data),
            Crc32.calculate(data, 0, data.size)
        )
    }

    @Test
    fun `different data produces different CRCs`() {
        val crc1 = Crc32.calculate("abc".toByteArray())
        val crc2 = Crc32.calculate("abd".toByteArray())
        assertNotEquals("Different data should give different CRCs", crc1, crc2)
    }

    @Test
    fun `large data 1MB`() {
        val data = ByteArray(1024 * 1024) { (it % 256).toByte() }
        val crc = Crc32.calculate(data)
        // Verify deterministic
        assertEquals("CRC should be deterministic", crc, Crc32.calculate(data))
    }

    @Test
    fun `known vector - VERA magic`() {
        // "VERA" in bytes — CRC32 verified against Python binascii.crc32(b'VERA')
        val data = byteArrayOf(0x56, 0x45, 0x52, 0x41)
        val crc = Crc32.calculate(data)
        assertEquals("CRC32 of 'VERA'", 0x30258e99.toInt(), crc)
    }
}
