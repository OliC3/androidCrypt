import com.androidcrypt.crypto.Serpent

fun main() {
    // Test vector
    val key = ByteArray(32) {
        when(it) {
            0 -> 0x00.toByte(); 1 -> 0x01.toByte(); 2 -> 0x02.toByte(); 3 -> 0x03.toByte()
            4 -> 0x04.toByte(); 5 -> 0x05.toByte(); 6 -> 0x06.toByte(); 7 -> 0x07.toByte()
            8 -> 0x08.toByte(); 9 -> 0x09.toByte(); 10 -> 0x0A.toByte(); 11 -> 0x0B.toByte()
            12 -> 0x0C.toByte(); 13 -> 0x0D.toByte(); 14 -> 0x0E.toByte(); 15 -> 0x0F.toByte()
            16 -> 0x10.toByte(); 17 -> 0x11.toByte(); 18 -> 0x12.toByte(); 19 -> 0x13.toByte()
            20 -> 0x14.toByte(); 21 -> 0x15.toByte(); 22 -> 0x16.toByte(); 23 -> 0x17.toByte()
            24 -> 0x18.toByte(); 25 -> 0x19.toByte(); 26 -> 0x1A.toByte(); 27 -> 0x1B.toByte()
            28 -> 0x1C.toByte(); 29 -> 0x1D.toByte(); 30 -> 0x1E.toByte(); 31 -> 0x1F.toByte()
            else -> 0x00.toByte()
        }
    }
    
    val plaintext = ByteArray(16) { 0 }
    
    val serpent = Serpent()
    serpent.init(key, true)
    val ks = serpent.keySchedule
    
    val encrypted = serpent.encrypt(plaintext, ks)
    
    println("Encrypted:")
    for (b in encrypted) {
        print("%02X ".format(b))
    }
    println()
    
    println("Expected: DE 26 9F F8 33 E4 32 B8 5B 2E 88 D2 70 1C E7 5C")
}
