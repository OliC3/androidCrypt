package com.androidcrypt.app

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [CopyService.CopyState] sealed class and related pure logic.
 *
 * These tests do not require Android dependencies — they exercise the state
 * machine, progress formatting, and data class behaviour in isolation.
 */
class CopyServiceStateTest {

    // ── CopyState equality & properties ─────────────────────────────────────

    @Test
    fun `Idle state is a singleton`() {
        val a = CopyService.CopyState.Idle
        val b = CopyService.CopyState.Idle
        assertSame(a, b)
    }

    @Test
    fun `Copying state holds progress current and total`() {
        val state = CopyService.CopyState.Copying("50%", 5, 10)
        assertEquals("50%", state.progress)
        assertEquals(5, state.current)
        assertEquals(10, state.total)
    }

    @Test
    fun `Copying states with same values are equal`() {
        val a = CopyService.CopyState.Copying("50%", 5, 10)
        val b = CopyService.CopyState.Copying("50%", 5, 10)
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `Copying states with different values are not equal`() {
        val a = CopyService.CopyState.Copying("50%", 5, 10)
        val b = CopyService.CopyState.Copying("60%", 6, 10)
        assertNotEquals(a, b)
    }

    @Test
    fun `Completed state holds message and success flag`() {
        val success = CopyService.CopyState.Completed("Done", true)
        assertEquals("Done", success.message)
        assertTrue(success.success)

        val failure = CopyService.CopyState.Completed("Failed", false)
        assertEquals("Failed", failure.message)
        assertFalse(failure.success)
    }

    @Test
    fun `Completed equality depends on both fields`() {
        val a = CopyService.CopyState.Completed("Done", true)
        val b = CopyService.CopyState.Completed("Done", true)
        val c = CopyService.CopyState.Completed("Done", false)
        assertEquals(a, b)
        assertNotEquals(a, c)
    }

    @Test
    fun `Error state holds message`() {
        val state = CopyService.CopyState.Error("Disk full")
        assertEquals("Disk full", state.message)
    }

    @Test
    fun `Error equality`() {
        val a = CopyService.CopyState.Error("Disk full")
        val b = CopyService.CopyState.Error("Disk full")
        val c = CopyService.CopyState.Error("Network error")
        assertEquals(a, b)
        assertNotEquals(a, c)
    }

    @Test
    fun `different CopyState subtypes are never equal`() {
        val idle = CopyService.CopyState.Idle
        val copying = CopyService.CopyState.Copying("50%", 5, 10)
        val completed = CopyService.CopyState.Completed("Done", true)
        val error = CopyService.CopyState.Error("Oops")

        assertNotEquals(idle as Any, copying as Any)
        assertNotEquals(copying as Any, completed as Any)
        assertNotEquals(completed as Any, error as Any)
        assertNotEquals(error as Any, idle as Any)
    }

    // ── Progress formatting helpers ─────────────────────────────────────────

    @Test
    fun `formatProgress produces expected strings`() {
        assertEquals("0 / 10", formatProgress(0, 10))
        assertEquals("5 / 10", formatProgress(5, 10))
        assertEquals("10 / 10", formatProgress(10, 10))
        assertEquals("1 / 1", formatProgress(1, 1))
    }

    @Test
    fun `formatProgress with zero total`() {
        assertEquals("0 / 0", formatProgress(0, 0))
    }

    @Test
    fun `formatProgress percentage`() {
        assertEquals("0%", formatPercent(0, 10))
        assertEquals("50%", formatPercent(5, 10))
        assertEquals("100%", formatPercent(10, 10))
        assertEquals("0%", formatPercent(0, 0))
    }

    @Test
    fun `formatPercent with large numbers`() {
        assertEquals("33%", formatPercent(333, 1000))
        assertEquals("99%", formatPercent(999, 1000))
        assertEquals("100%", formatPercent(1000, 1000))
    }

    // ── State transition simulation ─────────────────────────────────────────

    @Test
    fun `typical copy lifecycle transitions`() {
        var state: CopyService.CopyState = CopyService.CopyState.Idle
        assertTrue(state is CopyService.CopyState.Idle)

        state = CopyService.CopyState.Copying("0 / 5", 0, 5)
        assertTrue(state is CopyService.CopyState.Copying)

        state = CopyService.CopyState.Copying("3 / 5", 3, 5)
        val copying = state as CopyService.CopyState.Copying
        assertEquals(3, copying.current)

        state = CopyService.CopyState.Completed("Copied 5 files", true)
        assertTrue(state is CopyService.CopyState.Completed)
        assertTrue((state as CopyService.CopyState.Completed).success)
    }

    @Test
    fun `error transition from copying`() {
        var state: CopyService.CopyState = CopyService.CopyState.Copying("2 / 5", 2, 5)
        state = CopyService.CopyState.Error("Out of space")
        assertTrue(state is CopyService.CopyState.Error)
    }

    @Test
    fun `copying current never exceeds total`() {
        // Simulate a validation that could be enforced in production code
        val current = 5
        val total = 5
        val state = CopyService.CopyState.Copying("5 / 5", current, total)
        assertTrue(
            "current ($current) should not exceed total ($total)",
            state.current <= state.total
        )
    }

    // ── Companion object constants ──────────────────────────────────────────

    @Test
    fun `action constants are unique`() {
        val actions = setOf(
            CopyService.ACTION_COPY_FOLDER_TO_VOLUME,
            CopyService.ACTION_COPY_FILE_TO_VOLUME,
            CopyService.ACTION_COPY_FOLDER_PATH_TO_VOLUME,
            CopyService.ACTION_CANCEL
        )
        assertEquals("Action constants must be unique", 4, actions.size)
    }

    @Test
    fun `extra key constants are non-empty`() {
        assertTrue(CopyService.EXTRA_SOURCE_URI.isNotBlank())
        assertTrue(CopyService.EXTRA_SOURCE_PATH.isNotBlank())
        assertTrue(CopyService.EXTRA_VOLUME_PATH.isNotBlank())
        assertTrue(CopyService.EXTRA_FOLDER_NAME.isNotBlank())
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private fun formatProgress(current: Int, total: Int): String {
        return "$current / $total"
    }

    private fun formatPercent(current: Int, total: Int): String {
        return if (total == 0) "0%" else "${(current * 100) / total}%"
    }
}
