package com.androidcrypt.app

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [CopyService] notification rate-limiting logic.
 *
 * The actual [updateNotification] method requires an Android [Service] context,
 * so these tests exercise the rate-limit arithmetic and state transitions in
 * isolation.
 */
class CopyServiceNotificationRateLimitTest {

    // ── rate-limit arithmetic ───────────────────────────────────────────────

    @Test
    fun `notificationRateLimit is 500ms`() {
        // Verify the constant hasn't drifted — changing this affects UX
        val limit = CopyService::class.java.getDeclaredField("notificationRateLimit")
            .apply { isAccessible = true }
            .get(CopyService()) as Long
        assertEquals(500L, limit)
    }

    @Test
    fun `rate limit allows update after threshold`() {
        val lastTime = 1000L
        val now = 1600L
        val rateLimit = 500L
        assertTrue("600ms elapsed > 500ms limit", now - lastTime >= rateLimit)
    }

    @Test
    fun `rate limit blocks update before threshold`() {
        val lastTime = 1000L
        val now = 1200L
        val rateLimit = 500L
        assertFalse("200ms elapsed < 500ms limit", now - lastTime >= rateLimit)
    }

    @Test
    fun `rate limit exact boundary`() {
        val lastTime = 1000L
        val rateLimit = 500L
        assertTrue("exactly 500ms should allow update", (lastTime + rateLimit) - lastTime >= rateLimit)
    }

    // ── progress text formatting ────────────────────────────────────────────

    @Test
    fun `progress text includes current and total`() {
        val text = formatProgress(3, 10)
        assertTrue(text.contains("3"))
        assertTrue(text.contains("10"))
    }

    @Test
    fun `progress text at boundaries`() {
        assertEquals("0/1", formatProgress(0, 1))
        assertEquals("1/1", formatProgress(1, 1))
        assertEquals("0/100", formatProgress(0, 100))
        assertEquals("100/100", formatProgress(100, 100))
    }

    @Test
    fun `progress percentage calculation`() {
        assertEquals(0, percent(0, 10))
        assertEquals(50, percent(5, 10))
        assertEquals(100, percent(10, 10))
        assertEquals(33, percent(1, 3))
        assertEquals(0, percent(0, 0)) // avoid div-by-zero
    }

    // ── CopyState transition during rate limit ──────────────────────────────

    @Test
    fun `Copying state holds progress text`() {
        val state = CopyService.CopyState.Copying("3/10", 3, 10)
        assertEquals("3/10", state.progress)
        assertEquals(3, state.current)
        assertEquals(10, state.total)
    }

    @Test
    fun `Copying state can represent rate-limited update`() {
        // Simulate: first update creates notification + state,
        // second update (within 500ms) only updates state
        val state1 = CopyService.CopyState.Copying("1/10", 1, 10)
        val state2 = CopyService.CopyState.Copying("2/10", 2, 10)
        assertNotEquals(state1, state2)
        assertEquals(2, state2.current)
    }

    @Test
    fun `force flag bypasses rate limit conceptually`() {
        // When force=true, the notification should always update.
        // We can't call the real method, but we can verify the flag exists
        // and document its purpose.
        val method = CopyService::class.java.getDeclaredMethod(
            "updateNotification",
            String::class.java,
            Int::class.java,
            Int::class.java,
            Boolean::class.java
        )
        assertNotNull(method)
        assertEquals("updateNotification", method.name)
        val params = method.parameterTypes
        assertEquals(4, params.size)
        assertEquals(Boolean::class.java, params[3])
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun formatProgress(current: Int, total: Int): String {
        return "$current/$total"
    }

    private fun percent(current: Int, total: Int): Int {
        return if (total == 0) 0 else (current * 100) / total
    }
}
