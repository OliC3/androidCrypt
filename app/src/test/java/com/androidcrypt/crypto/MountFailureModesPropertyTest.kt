package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.filter
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * **Tier-1 mount-failure / key-lifecycle PBTs.**
 *
 *  - **T15** mount with wrong password returns failure, leaves no mounted state,
 *    and does NOT modify any byte of the container.
 *  - **T30** after `unmount()`, the volume reader's master-key field has been
 *    cleared (no key bytes left on the JVM heap inside VolumeReader).
 */
class MountFailureModesPropertyTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_mountfail_pbt")
        private const val RIGHT_PW = "Correct-Pw-2026!"
        private lateinit var container: File
        private lateinit var pristineBytes: ByteArray

        @BeforeClass @JvmStatic
        fun setUp() {
            TEST_DIR.mkdirs()
            container = File(TEST_DIR, "mf_${System.nanoTime()}.hc")
            VolumeCreator.createContainer(container.absolutePath, RIGHT_PW.toCharArray(), 4L).getOrThrow()
            pristineBytes = container.readBytes()
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            TEST_DIR.listFiles()?.forEach { it.delete() }
            TEST_DIR.delete()
        }
    }

    // ── T15 ─────────────────────────────────────────────────────────────────
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `wrong password mount fails, leaves container bytes untouched`(): Unit = runBlocking {
        checkAll(
            PropTestConfig(iterations = 6, seed = 0xBADCAFEL),
            Arb.string(1, 32).filter { it != RIGHT_PW && !it.contains('\u0000') }
        ) { wrongPw ->
            val r = VolumeReader(container.absolutePath)
            val res = try {
                r.mount(wrongPw.toCharArray())
            } finally {
                try { r.unmount() } catch (_: Exception) {}
            }
            assertTrue(
                "mount with wrong password '$wrongPw' unexpectedly succeeded",
                res.isFailure
            )
            // Container bytes must be byte-identical to pre-mount state.
            val nowBytes = container.readBytes()
            assertEquals(
                "container size changed after a failed mount with '$wrongPw'",
                pristineBytes.size, nowBytes.size
            )
            assertTrue(
                "container BYTES changed after a failed mount with '$wrongPw' — " +
                        "wrong-password path is performing a write somewhere",
                pristineBytes.contentEquals(nowBytes)
            )
        }
    }

    // ── T30 ─────────────────────────────────────────────────────────────────
    /** After `unmount()` the VolumeReader's `masterKey` field must be
     *  null (or zeroed). Inspect via reflection — there's no public getter,
     *  so reflection is the only way to assert this security invariant. */
    @Test
    fun `unmount clears master key field on VolumeReader`() {
        val r = VolumeReader(container.absolutePath)
        try {
            r.mount(RIGHT_PW.toCharArray()).getOrThrow()
            // The mount path zeros + nulls masterKey almost immediately after
            // copying it into XTSMode — see VolumeReader.finishMount line ~344.
            // So even WHILE mounted, the field is expected to be null.
            // After unmount the field must remain null.
            r.unmount()
        } catch (e: Exception) {
            try { r.unmount() } catch (_: Exception) {}
            throw e
        }
        val f = VolumeReader::class.java.getDeclaredField("masterKey")
        f.isAccessible = true
        val key = f.get(r) as ByteArray?
        if (key != null) {
            assertTrue(
                "VolumeReader.masterKey is non-null AND non-zero after unmount " +
                        "(${key.size} bytes, first byte=${key[0].toInt() and 0xFF}) — key material is leaking",
                key.all { it == 0.toByte() }
            )
        }
        // Also check XTSMode reference is cleared
        val xf = VolumeReader::class.java.getDeclaredField("xtsMode")
        xf.isAccessible = true
        assertNull("VolumeReader.xtsMode still bound after unmount", xf.get(r))
    }
}
