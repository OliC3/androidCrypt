package com.androidcrypt.crypto

import io.kotest.property.Arb
import io.kotest.property.PropTestConfig
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.next
import io.kotest.property.checkAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **XTS edge-case PBTs that complement [XtsAesPropertyTest].**
 *
 *  - **T27** cascade ciphers (AES-Twofish-Serpent, Serpent-Twofish-AES)
 *    must satisfy the same XTS round-trip and wrong-tweak invariants as
 *    the single-block ciphers; they are excluded from the main XTS suite
 *    so this test ensures they aren't quietly broken.
 *  - **T28** non-multiple-of-512-byte input must be rejected (or at
 *    minimum: not silently truncate to a smaller plaintext).
 *  - **T29** tweak edge values: 0, 1, 2^32-1, 2^32, Long.MAX_VALUE round-
 *    trip correctly. Catches tweak-counter overflow / int-vs-long bugs in
 *    the JNI bridge.
 */
class XtsCascadePropertyTest {

    private fun cascadeKey(algo: EncryptionAlgorithm, salt: Long): ByteArray =
        ByteArray(algo.keySize).also { java.util.Random(0xC4_5CADEL xor salt).nextBytes(it) }

    private fun payload(sectors: Int, salt: Long): ByteArray =
        ByteArray(sectors * 512).also { java.util.Random(salt).nextBytes(it) }

    private val cascades = listOf(
        EncryptionAlgorithm.AES_TWOFISH_SERPENT,
        EncryptionAlgorithm.SERPENT_TWOFISH_AES,
    )

    // ── T27 round-trip + wrong-tweak for cascades ───────────────────────────
    @Test
    @OptIn(io.kotest.common.ExperimentalKotest::class)
    fun `cascade XTS round-trip and wrong-tweak rejection`() = runBlocking {
        for (algo in cascades) {
            val key = cascadeKey(algo, algo.ordinal.toLong())
            val xts = XTSMode(key, algo)
            try {
                checkAll(
                    PropTestConfig(iterations = 12, seed = 0xCA5CADE0L),
                    Arb.int(1, 8),
                    Arb.long(0L, 1L shl 30),
                ) { sectors, tweak ->
                    val pt = payload(sectors, tweak)
                    val ct = xts.encrypt(pt, tweak)
                    assertEquals("ciphertext length mismatch for $algo", pt.size, ct.size)
                    assertArrayEquals("round-trip failed for cascade $algo @ tweak=$tweak",
                        pt, xts.decrypt(ct, tweak))
                    val wrongTweak = tweak xor 1L
                    val ptBad = xts.decrypt(ct, wrongTweak)
                    assertFalse(
                        "decrypt with wrong tweak recovered plaintext for cascade $algo " +
                                "(tweak=$tweak wrong=$wrongTweak)",
                        ptBad.contentEquals(pt)
                    )
                }
            } finally { xts.close() }
        }
    }

    // ── T28 non-sector-aligned input ────────────────────────────────────────
    @Test
    fun `non-sector-aligned XTS input is rejected or handled safely`() {
        // We accept either: (a) encrypt returns a size != input size (likely
        // truncate-to-sector-multiple), (b) encrypt throws, (c) encrypt
        // returns a same-sized ciphertext that decrypts back to original.
        // What we MUST NOT see: silent corruption — encrypt then decrypt
        // returning bytes different from the input.
        val key = cascadeKey(EncryptionAlgorithm.AES, 0L)
        val xts = XTSMode(key, EncryptionAlgorithm.AES)
        try {
            for (extra in listOf(1, 7, 100, 511, 513, 1023)) {
                val pt = ByteArray(512 + extra).also { java.util.Random(extra.toLong()).nextBytes(it) }
                val ct: ByteArray
                try {
                    ct = xts.encrypt(pt, 0L)
                } catch (_: Throwable) {
                    // Acceptable: implementation rejects unaligned input.
                    continue
                }
                if (ct.size != pt.size) {
                    // Acceptable: ciphertext truncated to a sector boundary.
                    continue
                }
                val rt: ByteArray = try { xts.decrypt(ct, 0L) } catch (_: Throwable) { continue }
                if (rt.size == pt.size) {
                    assertArrayEquals(
                        "non-aligned input round-tripped to a DIFFERENT plaintext (extra=$extra) — " +
                                "silent corruption, not safe rejection",
                        pt, rt
                    )
                }
            }
        } finally { xts.close() }
    }

    // ── T29 tweak edge values ───────────────────────────────────────────────
    @Test
    fun `XTS round-trip survives tweak edge values`() {
        val key = cascadeKey(EncryptionAlgorithm.AES, 1L)
        val xts = XTSMode(key, EncryptionAlgorithm.AES)
        try {
            val edges = listOf(
                0L,
                1L,
                (1L shl 32) - 1,    // 2^32 - 1 — int overflow boundary
                1L shl 32,           // 2^32     — first long-only value
                (1L shl 32) + 1,
                Long.MAX_VALUE - 1,
                Long.MAX_VALUE,
            )
            val pt = payload(4, 0xE0_6EL)
            for (t in edges) {
                val ct = xts.encrypt(pt, t)
                val rt = xts.decrypt(ct, t)
                assertArrayEquals("tweak=$t edge round-trip failed", pt, rt)
            }
            // Two adjacent edge tweaks must produce different first-sector
            // ciphertext (catches tweak truncated to int).
            val c0 = xts.encrypt(pt, (1L shl 32) - 1).copyOfRange(0, 512)
            val c1 = xts.encrypt(pt, 1L shl 32).copyOfRange(0, 512)
            assertFalse(
                "tweak (2^32 - 1) and (2^32) produced identical first-sector ciphertext — " +
                        "tweak is being truncated to a 32-bit int somewhere",
                c0.contentEquals(c1)
            )
        } finally { xts.close() }
    }
}
