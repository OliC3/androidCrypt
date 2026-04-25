package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/**
 * **End-to-end keyfile integration PBT.**
 *
 * The `VolumeCreator.createContainer` and `VolumeReader.mount` methods both
 * accept a `keyfileUris: List<Uri>` parameter, but that path requires an
 * Android `Context` to resolve `content://` URIs and is therefore not
 * exercisable in pure-JVM unit tests.  This test covers the **semantic**
 * equivalent: it proves that the password bytes produced by
 * `KeyfileProcessor.applyKeyfiles` are the actual bytes that unlock the
 * volume.
 *
 * Properties:
 *   1. A container created with a keyfile-mixed password mounts successfully
 *      when the same mixed password is supplied.
 *   2. The same container **fails** to mount with the original (unmixed)
 *      password.
 *   3. The same container **fails** to mount with a differently-mixed
 *      password (wrong keyfile).
 *
 * NOTE: the `keyfileUris` parameter on `VolumeCreator` / `VolumeReader` is
 * still untested end-to-end.  That path needs an instrumented Android test
 * with a real `Context`.
 */
class KeyfileEndToEndPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_kf_e2e_pbt")
        private const val PASSWORD = "End2EndKf!"

        @BeforeClass @JvmStatic fun setUp() { TEST_DIR.mkdirs() }
        @AfterClass @JvmStatic fun tearDown() {
            TEST_DIR.listFiles()?.forEach { it.delete() }
            TEST_DIR.delete()
        }

        /** VeraCrypt's keyfile mixing returns raw bytes (0..255).  Those bytes
         *  are fed directly into PBKDF2.  `VolumeCreator.createContainer` takes a
         *  `CharArray` and UTF-8-encodes it, so we can only round-trip bytes
         *  that are valid UTF-8.  Filter iterations whose mixed bytes are not
         *  valid UTF-8 — they would corrupt on the CharArray round-trip. */
        fun isValidUtf8(bytes: ByteArray): Boolean =
            try {
                Charsets.UTF_8.newDecoder().apply {
                    onMalformedInput(CodingErrorAction.REPORT)
                    onUnmappableCharacter(CodingErrorAction.REPORT)
                }.decode(ByteBuffer.wrap(bytes))
                true
            } catch (_: Exception) { false }
    }

    private fun writeKeyfile(name: String, bytes: ByteArray): String {
        val f = File(TEST_DIR, name)
        f.writeBytes(bytes)
        return f.absolutePath
    }

    // ── Property 1 + 2 ──────────────────────────────────────────────────────
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `container with keyfile-mixed password mounts only with mixed password`(): Unit = runBlocking {
        checkAll(
            PropTestConfig(iterations = 4, seed = 0xE2E2E2L),
            Arb.byteArray(Arb.int(1, 512), Arb.byte()),
        ) { kfBytes ->
            val pw = PASSWORD.toCharArray()
            val kfPath = writeKeyfile("kf_${System.nanoTime()}.bin", kfBytes)
            val mixed = KeyfileProcessor.applyKeyfiles(pw.copyOf(), listOf(kfPath)).getOrThrow()
            File(kfPath).delete()
            if (!isValidUtf8(mixed)) return@checkAll

            val mixedPw = String(mixed, Charsets.UTF_8).toCharArray()
            val container = File(TEST_DIR, "e2e_${System.nanoTime()}.hc")
            try {
                VolumeCreator.createContainer(container.absolutePath, mixedPw.copyOf(), 4L).getOrThrow()

                // (1) mixed password mounts
                val r1 = VolumeReader(container.absolutePath)
                assertTrue(
                    "mount with keyfile-mixed password failed",
                    r1.mount(mixedPw.copyOf()).isSuccess
                )
                r1.unmount()

                // (2) original password (no keyfile) must fail
                val r2 = VolumeReader(container.absolutePath)
                assertTrue(
                    "mount with original password should fail — keyfile mixing is not " +
                            "being used as the actual PBKDF2 input",
                    r2.mount(pw.copyOf()).isFailure
                )
                try { r2.unmount() } catch (_: Exception) {}
            } finally {
                container.delete()
            }
        }
    }

    // ── Property 3 ───────────────────────────────────────────────────────────
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `wrong keyfile does not mount container created with correct keyfile`(): Unit = runBlocking {
        checkAll(
            PropTestConfig(iterations = 4, seed = 0xBADCAFEL),
            Arb.byteArray(Arb.int(8, 256), Arb.byte()),
            Arb.byteArray(Arb.int(8, 256), Arb.byte()),
        ) { kfA, kfB ->
            if (kfA.contentEquals(kfB)) return@checkAll
            val pw = PASSWORD.toCharArray()

            val pathA = writeKeyfile("a_${System.nanoTime()}.bin", kfA)
            val pathB = writeKeyfile("b_${System.nanoTime()}.bin", kfB)
            val mixedA = KeyfileProcessor.applyKeyfiles(pw.copyOf(), listOf(pathA)).getOrThrow()
            val mixedB = KeyfileProcessor.applyKeyfiles(pw.copyOf(), listOf(pathB)).getOrThrow()
            File(pathA).delete(); File(pathB).delete()
            if (!isValidUtf8(mixedA) || !isValidUtf8(mixedB)) return@checkAll

            val pwA = String(mixedA, Charsets.UTF_8).toCharArray()
            val pwB = String(mixedB, Charsets.UTF_8).toCharArray()
            val container = File(TEST_DIR, "wrong_${System.nanoTime()}.hc")
            try {
                VolumeCreator.createContainer(container.absolutePath, pwA.copyOf(), 4L).getOrThrow()

                val r = VolumeReader(container.absolutePath)
                assertTrue(
                    "mount with wrong keyfile-mixed password should fail",
                    r.mount(pwB.copyOf()).isFailure
                )
                try { r.unmount() } catch (_: Exception) {}
            } finally {
                container.delete()
            }
        }
    }
}
