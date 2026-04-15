package com.androidcrypt.crypto

import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class FullVector1Debug {
    
    @Test
    fun debugFullVector1() {
        println("=== Debugging full Vector 1 (AES-256 XTS, 64-byte key) ===")
        
        // VeraCrypt AES XTS uses 256-bit keys: 32 bytes encryption + 32 bytes tweak = 64 bytes total
        val key1 = ByteArray(32) { 0x00 }
        val key2 = ByteArray(32) { 0x00 }
        val fullKey = ByteArray(64)
        System.arraycopy(key1, 0, fullKey, 0, 32)
        System.arraycopy(key2, 0, fullKey, 32, 32)
        
        val xts = XTSMode(fullKey, EncryptionAlgorithm.AES)
        val plaintext = ByteArray(32) { 0x00 }
        val ciphertext = xts.encrypt(plaintext, 0L)
        
        println("Ciphertext: ${ciphertext.joinToString("") { "%02x".format(it) }}")
        
        println("\nBlock 0 (bytes 0-15):")
        println("  Got: ${ciphertext.copyOfRange(0, 16).joinToString("") { "%02x".format(it) }}")
        
        println("\nBlock 1 (bytes 16-31):")
        println("  Got: ${ciphertext.copyOfRange(16, 32).joinToString("") { "%02x".format(it) }}")
        
        // Verify round-trip
        val decrypted = xts.decrypt(ciphertext, 0L)
        assert(plaintext.contentEquals(decrypted)) { "Round-trip failed" }
        println("\nRound-trip: PASS")
    }
}
