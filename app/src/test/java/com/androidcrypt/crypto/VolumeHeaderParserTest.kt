package com.androidcrypt.crypto

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for VolumeHeaderParser: createHeader/parseHeader round-trip,
 * wrong password, corrupted data, and field validation.
 */
class VolumeHeaderParserTest {

    private val parser = VolumeHeaderParser()

    // ── Round-trip ──────────────────────────────────────────────────────────

    @Test
    fun `createHeader and parseHeader round-trip`() {
        val password = "TestPassword123!".toCharArray()
        val volumeSize = 10L * 1024 * 1024

        val headerBytes = parser.createHeader(
            password = password,
            volumeSize = volumeSize,
            encryptionAlg = EncryptionAlgorithm.AES,
            hashAlg = HashAlgorithm.SHA512
        )

        assertEquals("Header should be 512 bytes", VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE, headerBytes.size)

        val parsed = parser.parseHeader(headerBytes, password)
        assertNotNull("Should parse with correct password", parsed)
        assertEquals(EncryptionAlgorithm.AES, parsed!!.encryptionAlgorithm)
        assertEquals(HashAlgorithm.SHA512, parsed.hashAlgorithm)
        assertEquals(volumeSize, parsed.volumeSize)
        assertEquals(512, parsed.sectorSize)
        assertEquals(VolumeConstants.VOLUME_HEADER_VERSION_NUM, parsed.version)
    }

    @Test
    fun `round-trip with PIM`() {
        val password = "PimTest".toCharArray()
        val headerBytes = parser.createHeader(
            password = password,
            pim = 5,
            volumeSize = 5L * 1024 * 1024
        )

        val parsed = parser.parseHeader(headerBytes, password, pim = 5)
        assertNotNull("Should parse with correct PIM", parsed)
    }

    @Test
    fun `round-trip preserves volume size`() {
        val sizes = listOf(1L * 1024 * 1024, 100L * 1024 * 1024, 1L * 1024 * 1024 * 1024)
        for (size in sizes) {
            val header = parser.createHeader(password = "pw".toCharArray(), volumeSize = size)
            val parsed = parser.parseHeader(header, "pw".toCharArray())
            assertNotNull("Should parse for size $size", parsed)
            assertEquals("Volume size should match for $size", size, parsed!!.volumeSize)
        }
    }

    @Test
    fun `round-trip preserves sector size`() {
        val header = parser.createHeader(
            password = "pw".toCharArray(),
            volumeSize = 10L * 1024 * 1024,
            sectorSize = 4096
        )
        val parsed = parser.parseHeader(header, "pw".toCharArray())
        assertNotNull(parsed)
        assertEquals(4096, parsed!!.sectorSize)
    }

    @Test
    fun `master key is non-zero`() {
        val header = parser.createHeader(password = "pw".toCharArray(), volumeSize = 10L * 1024 * 1024)
        val parsed = parser.parseHeader(header, "pw".toCharArray())
        assertNotNull(parsed)
        assertTrue("Master key should have non-zero bytes", parsed!!.masterKey.any { it != 0.toByte() })
        assertEquals("Master key size should match algorithm", EncryptionAlgorithm.AES.keySize, parsed.masterKey.size)
    }

    @Test
    fun `each createHeader produces unique master key`() {
        val pw = "pw".toCharArray()
        val h1 = parser.createHeader(password = pw, volumeSize = 10L * 1024 * 1024)
        val h2 = parser.createHeader(password = pw, volumeSize = 10L * 1024 * 1024)
        val p1 = parser.parseHeader(h1, pw)!!
        val p2 = parser.parseHeader(h2, pw)!!
        assertFalse("Different headers should have different master keys", p1.masterKey.contentEquals(p2.masterKey))
    }

    // ── Wrong password ──────────────────────────────────────────────────────

    @Test
    fun `parseHeader with wrong password returns null`() {
        val header = parser.createHeader(password = "correct".toCharArray(), volumeSize = 10L * 1024 * 1024)
        val parsed = parser.parseHeader(header, "wrong".toCharArray())
        assertNull("Wrong password should return null", parsed)
    }

    @Test
    fun `parseHeader with wrong PIM returns null`() {
        val header = parser.createHeader(password = "pw".toCharArray(), pim = 3, volumeSize = 10L * 1024 * 1024)
        val parsed = parser.parseHeader(header, "pw".toCharArray(), pim = 999)
        assertNull("Wrong PIM should return null", parsed)
    }

    // ── Corrupted data ──────────────────────────────────────────────────────

    @Test
    fun `parseHeader with corrupted magic returns null`() {
        val header = parser.createHeader(password = "pw".toCharArray(), volumeSize = 10L * 1024 * 1024)
        // Corrupt a byte in the encrypted portion (salt+encrypted data)
        // Flipping a bit in the ciphertext should corrupt the magic after decryption
        header[VolumeConstants.SALT_SIZE + 10] = (header[VolumeConstants.SALT_SIZE + 10].toInt() xor 0xFF).toByte()
        val parsed = parser.parseHeader(header, "pw".toCharArray())
        assertNull("Corrupted header should return null", parsed)
    }

    @Test
    fun `parseHeader with corrupted salt returns null`() {
        val header = parser.createHeader(password = "pw".toCharArray(), volumeSize = 10L * 1024 * 1024)
        // Corrupt the salt — this changes the derived key, so decryption will fail
        header[0] = (header[0].toInt() xor 0xFF).toByte()
        val parsed = parser.parseHeader(header, "pw".toCharArray())
        assertNull("Corrupted salt should return null", parsed)
    }

    @Test
    fun `parseHeader with all zeros returns null`() {
        val header = ByteArray(VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE)
        val parsed = parser.parseHeader(header, "pw".toCharArray())
        assertNull("All-zeros header should return null", parsed)
    }

    @Test
    fun `parseHeader with random data returns null`() {
        val header = ByteArray(VolumeConstants.VOLUME_HEADER_EFFECTIVE_SIZE)
        java.security.SecureRandom().nextBytes(header)
        val parsed = parser.parseHeader(header, "pw".toCharArray())
        assertNull("Random data should return null", parsed)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseHeader with too-small data throws`() {
        parser.parseHeader(ByteArray(10), "pw".toCharArray())
    }

    // ── VolumeHeaderData properties ─────────────────────────────────────────

    @Test
    fun `isSystemEncrypted flag`() {
        val header = parser.createHeader(password = "pw".toCharArray(), volumeSize = 10L * 1024 * 1024)
        val parsed = parser.parseHeader(header, "pw".toCharArray())!!
        assertFalse("Normal volume should not be system-encrypted", parsed.isSystemEncrypted)
        assertEquals(0, parsed.flags)
    }

    @Test
    fun `hidden volume size is zero for normal volume`() {
        val header = parser.createHeader(password = "pw".toCharArray(), volumeSize = 10L * 1024 * 1024)
        val parsed = parser.parseHeader(header, "pw".toCharArray())!!
        assertEquals("Hidden volume size should be 0", 0L, parsed.hiddenVolumeSize)
    }

    @Test
    fun `toString does not leak master key`() {
        val header = parser.createHeader(password = "pw".toCharArray(), volumeSize = 10L * 1024 * 1024)
        val parsed = parser.parseHeader(header, "pw".toCharArray())!!
        val str = parsed.toString()
        assertFalse("toString should not contain masterKey bytes", str.contains("masterKey"))
        assertFalse("toString should not contain byte array notation", str.contains("[B@"))
    }

    // ── Non-AES algorithm round-trips ────────────────────────────────────────

    @Test
    fun `Serpent round-trip via parseHeader`() {
        val password = "SerpentTest".toCharArray()
        val header = parser.createHeader(
            password = password,
            volumeSize = 10L * 1024 * 1024,
            encryptionAlg = EncryptionAlgorithm.SERPENT
        )
        val parsed = parser.parseHeader(header, "SerpentTest".toCharArray())
        assertNotNull("Serpent header should parse", parsed)
        assertEquals(EncryptionAlgorithm.SERPENT, parsed!!.encryptionAlgorithm)
    }

    @Test
    fun `Twofish round-trip via parseHeader`() {
        val header = parser.createHeader(
            password = "TwofishTest".toCharArray(),
            volumeSize = 10L * 1024 * 1024,
            encryptionAlg = EncryptionAlgorithm.TWOFISH
        )
        val parsed = parser.parseHeader(header, "TwofishTest".toCharArray())
        assertNotNull("Twofish header should parse", parsed)
        assertEquals(EncryptionAlgorithm.TWOFISH, parsed!!.encryptionAlgorithm)
    }

    @Test
    fun `AES-Twofish-Serpent cascade round-trip via parseHeader`() {
        val header = parser.createHeader(
            password = "CascadeTest".toCharArray(),
            volumeSize = 10L * 1024 * 1024,
            encryptionAlg = EncryptionAlgorithm.AES_TWOFISH_SERPENT
        )
        val parsed = parser.parseHeader(header, "CascadeTest".toCharArray())
        assertNotNull("AES-Twofish-Serpent header should parse", parsed)
        assertEquals(EncryptionAlgorithm.AES_TWOFISH_SERPENT, parsed!!.encryptionAlgorithm)
    }

    // ── Salt uniqueness ─────────────────────────────────────────────────────

    @Test
    fun `each createHeader produces unique salt`() {
        val pw = "pw".toCharArray()
        val h1 = parser.createHeader(password = pw, volumeSize = 10L * 1024 * 1024)
        val h2 = parser.createHeader(password = pw, volumeSize = 10L * 1024 * 1024)
        val salt1 = h1.copyOfRange(0, VolumeConstants.SALT_SIZE)
        val salt2 = h2.copyOfRange(0, VolumeConstants.SALT_SIZE)
        assertFalse("Two headers should have different salts", salt1.contentEquals(salt2))
    }
}
