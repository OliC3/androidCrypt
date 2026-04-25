package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile

/**
 * **Tier-1 header robustness PBTs.**
 *
 *  - **T13** primary salt vs backup salt (must differ; if not, this
 *    documents the implementation gap).
 *  - **T18** any byte-flip inside the encrypted header region MUST cause
 *    mount to fail (CRC32 + PBKDF2 chain catches the corruption).
 *  - **T31** truncated container (less than the 256 KB four-header region)
 *    must fail to mount cleanly without a crash.
 *  - **T32** with primary intact, garbage in the backup header region must
 *    NOT prevent mount (backup is a fallback, not a required field).
 *  - **T33** with primary corrupted but backup intact, mount **should**
 *    fall back to the backup. NOTE: at the time of writing, the production
 *    code path only tries primary+hidden positions — see
 *    [VolumeReader.finishMount]. This property therefore documents the
 *    spec-compliant expectation; if it fails it is exposing a real
 *    recoverability gap, not a test bug.
 */
class HeaderRobustnessPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_hdrrobust_pbt")
        private const val PASSWORD = "HdrRobustPBT!"
        private val SHARED_CONTAINER: File by lazy {
            File(TEST_DIR, "shared.hc").also { f ->
                TEST_DIR.mkdirs()
                if (!f.exists() || f.length() == 0L) {
                    VolumeCreator.createContainer(f.absolutePath, PASSWORD.toCharArray(), 6L).getOrThrow()
                }
            }
        }

        @BeforeClass @JvmStatic fun setUp() { SHARED_CONTAINER.length() }
        @AfterClass @JvmStatic fun tearDown() {
            TEST_DIR.listFiles()?.forEach { it.delete() }
            TEST_DIR.delete()
        }

        private const val SALT_SIZE = 64
        private const val ENC_HEADER_SIZE = 448
        private val PRIMARY_OFFSET = 0L
        private val BACKUP_OFFSET_FROM_END = VolumeConstants.VOLUME_HEADER_GROUP_SIZE
    }

    private fun copyContainer(suffix: String): File {
        val dst = File(TEST_DIR, "copy_${suffix}_${System.nanoTime()}.hc")
        SHARED_CONTAINER.copyTo(dst, overwrite = true)
        return dst
    }

    private fun mountSucceeds(f: File, pw: CharArray = PASSWORD.toCharArray()): Boolean {
        val r = VolumeReader(f.absolutePath)
        return try {
            val res = r.mount(pw)
            res.isSuccess
        } finally {
            try { r.unmount() } catch (_: Exception) {}
        }
    }

    // ── T13 ─────────────────────────────────────────────────────────────────
    /** Primary salt and backup salt should be different (else PBKDF2
     *  output is identical between the two headers — which voids the
     *  point of having a backup at all from a key-rotation standpoint).
     *
     *  KNOWN PRODUCT GAP: [VolumeCreator.createContainer] writes the same
     *  512-byte header buffer (including its salt) at offsets 0 and
     *  `length-128KB`. Real VeraCrypt generates an independent salt for
     *  the backup header. Marked @Ignore until the production fix lands;
     *  un-ignore to gate the fix.
     */
    @Test
    fun `primary header salt differs from backup header salt`() {
        val total = SHARED_CONTAINER.length()
        val backupOffset = total - BACKUP_OFFSET_FROM_END
        RandomAccessFile(SHARED_CONTAINER, "r").use { raf ->
            val primarySalt = ByteArray(SALT_SIZE)
            raf.seek(PRIMARY_OFFSET); raf.readFully(primarySalt)
            val backupSalt = ByteArray(SALT_SIZE)
            raf.seek(backupOffset); raf.readFully(backupSalt)
            // KNOWN GAP: this implementation reuses the same 512-byte header
            // (including salt) for both primary and backup. Real VeraCrypt
            // generates a fresh salt for the backup. Test asserts the
            // spec-compliant invariant — failure here is a real product gap.
            assertFalse(
                "primary and backup headers share the same salt — " +
                        "backup PBKDF2 output is identical to primary, voiding " +
                        "the recovery purpose of the backup header",
                primarySalt.contentEquals(backupSalt)
            )
        }
    }

    // ── T18 ─────────────────────────────────────────────────────────────────
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `single byte tamper inside encrypted primary header region rejects mount`(): Unit = runBlocking {
        // Bytes 64..511 are the encrypted header data. Flip any one bit
        // inside that region; AES-XTS diffusion + the embedded CRC32 fields
        // must conspire to make the decrypted magic / CRC fail.
        checkAll(
            PropTestConfig(iterations = 8, seed = 0xCAFEF00DL),
            Arb.int(SALT_SIZE, SALT_SIZE + ENC_HEADER_SIZE - 1),
            Arb.int(0, 7)
        ) { byteIdx, bitIdx ->
            val f = copyContainer("tamper_${byteIdx}_$bitIdx")
            try {
                RandomAccessFile(f, "rw").use { raf ->
                    raf.seek(byteIdx.toLong())
                    val orig = raf.readByte()
                    raf.seek(byteIdx.toLong())
                    raf.writeByte((orig.toInt() xor (1 shl bitIdx)) and 0xFF)
                }
                assertFalse(
                    "tamper at byte $byteIdx bit $bitIdx in encrypted primary header still mounted — " +
                            "magic/CRC validation is not catching ciphertext corruption",
                    mountSucceeds(f)
                )
            } finally {
                f.delete()
            }
        }
    }

    // ── T31 ─────────────────────────────────────────────────────────────────
    @Test
    fun `truncated container fails to mount cleanly`() {
        // 256 KB is the four-header region; anything smaller cannot host a
        // valid VeraCrypt volume.
        val sizes = listOf(0L, 64L, 1024L, 65536L, 131072L, 262143L)
        for (sz in sizes) {
            val f = File(TEST_DIR, "trunc_$sz.hc")
            try {
                RandomAccessFile(f, "rw").use { raf ->
                    raf.setLength(sz)
                    // Fill with random garbage so we don't accidentally hit zeros
                    if (sz > 0) {
                        raf.seek(0); raf.write(ByteArray(sz.toInt()).also { java.util.Random(sz).nextBytes(it) })
                    }
                }
                val r = VolumeReader(f.absolutePath)
                val res = try { r.mount(PASSWORD.toCharArray()) } finally {
                    try { r.unmount() } catch (_: Exception) {}
                }
                assertTrue(
                    "truncated container of $sz bytes mounted — should have failed",
                    res.isFailure
                )
            } finally {
                f.delete()
            }
        }
    }

    // ── T32 ─────────────────────────────────────────────────────────────────
    @Test
    fun `mount succeeds when only the backup header region is corrupted`() {
        val f = copyContainer("backuponly")
        try {
            val total = f.length()
            val backupOffset = total - BACKUP_OFFSET_FROM_END
            // Scribble the entire backup header group (128KB at end)
            RandomAccessFile(f, "rw").use { raf ->
                raf.seek(backupOffset)
                raf.write(ByteArray(BACKUP_OFFSET_FROM_END.toInt()).also { java.util.Random(0xBADBADL).nextBytes(it) })
            }
            assertTrue(
                "primary header intact + backup header corrupted should still mount; failure means " +
                        "the mount path is unnecessarily consulting the backup",
                mountSucceeds(f)
            )
        } finally {
            f.delete()
        }
    }

    // ── T33 ─────────────────────────────────────────────────────────────────
    /**
     *  KNOWN PRODUCT GAP: [VolumeReader.finishMount] only consults the
     *  primary header at offset 0 and the hidden header at offset 64KB.
     *  It never falls back to the backup header at `length-128KB`, so a
     *  corrupted primary leaves the user unable to mount even though
     *  the backup is intact. Marked @Ignore until a backup-header
     *  fallback path is added; un-ignore to gate the fix.
     */
    @Test
    fun `mount falls back to backup when primary header is corrupted`() {
        val f = copyContainer("primaryscrambled")
        try {
            // Scramble the entire primary header group (first 128KB) — this
            // wipes both the normal primary and the hidden header position.
            RandomAccessFile(f, "rw").use { raf ->
                raf.seek(0)
                raf.write(ByteArray(BACKUP_OFFSET_FROM_END.toInt()).also { java.util.Random(0xDEADL).nextBytes(it) })
            }
            // KNOWN GAP: VolumeReader.finishMount only tries offset 0 (primary)
            // and 64KB (hidden), never the backup at end-128KB. This assertion
            // documents the spec-compliant expectation — failing here is the
            // test correctly exposing a missing recovery path, not a test bug.
            assertTrue(
                "primary header destroyed + backup intact: mount should recover from backup. " +
                        "If this fails, VolumeReader is missing a backup-header fallback.",
                mountSucceeds(f)
            )
        } finally {
            f.delete()
        }
    }
}
