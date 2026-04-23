package com.androidcrypt.crypto

import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.File

/**
 * End-to-end create + mount + read-back round-trip for every VeraCrypt
 * PRF.  Validates that:
 *   * [VolumeCreator.createContainer] honours the `hashAlgorithm` parameter
 *   * [VolumeReader.mount] discovers the right hash through brute-force
 *     trial of all five PRFs (so users don't have to specify the hash on
 *     mount, matching the desktop UX)
 *   * [PBKDF2.deriveKey] dispatches correctly to JCE for SHA-* and to
 *     [NativePkcs5] for Whirlpool / Blake2s / Streebog
 *
 * Uses a small PIM so iteration count stays at 16 000 — keeps each round
 * trip well under a second per hash.
 */
class VolumeRoundTripPerHashTest {

    private val filesToCleanup = mutableListOf<File>()
    private val PASSWORD = "TestHashPassword!".toCharArray()
    private val PIM = 1   // 15000 + 1*1000 = 16000 iterations per PRF
    private val SIZE_MB = 5L

    @After
    fun cleanup() {
        for (f in filesToCleanup) f.delete()
        filesToCleanup.clear()
    }

    private fun tempFile(tag: String): File =
        File.createTempFile("vc_${tag}_", ".vc").also { filesToCleanup.add(it) }

    private fun roundTrip(hash: HashAlgorithm) {
        val tag = hash.name.lowercase()
        val file = tempFile(tag)
        file.delete() // createContainer requires file to not exist

        val createResult = VolumeCreator.createContainer(
            containerPath = file.absolutePath,
            password = PASSWORD.copyOf(),
            sizeInMB = SIZE_MB,
            pim = PIM,
            algorithm = EncryptionAlgorithm.AES,
            hashAlgorithm = hash,
        )
        assertTrue(
            "[$hash] creation failed: ${createResult.exceptionOrNull()?.message}",
            createResult.isSuccess
        )

        val reader = VolumeReader(file.absolutePath)
        try {
            val mount = reader.mount(PASSWORD.copyOf(), pim = PIM)
            assertTrue(
                "[$hash] mount failed: ${mount.exceptionOrNull()?.message}",
                mount.isSuccess
            )
            assertTrue("[$hash] mounted flag", mount.getOrThrow().isMounted)

            // Read/write to confirm header decryption produced the right
            // master key (a wrong key still passes the magic check by chance
            // is impossible — the key area CRC + header CRC are independent
            // checks — but a successful FAT round-trip is the gold standard).
            val fs = FAT32Reader(reader)
            fs.initialize().getOrThrow()
            fs.createFile("/", "h.txt").getOrThrow()
            val payload = "hash=${hash.name}".toByteArray()
            fs.writeFile("/h.txt", payload).getOrThrow()
            val read = fs.readFile("/h.txt").getOrThrow()
            assertArrayEquals("[$hash] FAT round-trip payload", payload, read)
        } finally {
            reader.unmount()
        }
    }

    @Test fun `round-trip SHA-512`()  = roundTrip(HashAlgorithm.SHA512)
    @Test fun `round-trip SHA-256`()  = roundTrip(HashAlgorithm.SHA256)
    @Test fun `round-trip Whirlpool`() = roundTrip(HashAlgorithm.WHIRLPOOL)
    @Test fun `round-trip Blake2s`()   = roundTrip(HashAlgorithm.BLAKE2S)
    @Test fun `round-trip Streebog`()  = roundTrip(HashAlgorithm.STREEBOG)
}
