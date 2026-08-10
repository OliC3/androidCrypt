package com.androidcrypt.crypto

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import com.androidcrypt.crypto.EncryptionAlgorithm.AES
import com.androidcrypt.crypto.HashAlgorithm.SHA512
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * Tests [VolumeReader.mount] via the content-URI path — the path real users
 * hit when mounting from the in-app picker (VolumeMountManager.mountVolumeFromUri
 * → VolumeReader(context, uri).mount). The file-path path is covered by the
 * rest of the crypto test suite; this covers the SAF file-descriptor read
 * path: contentResolver.openFileDescriptor → FileChannel header read →
 * trial decrypt.
 */
@RunWith(RobolectricTestRunner::class)
class VolumeReaderUriMountTest {

    companion object {
        private val TEST_DIR = File(System.getProperty("java.io.tmpdir")!!, "androidcrypt_uri_mount")
        private const val PASSWORD = "UriMount!"
    }

    private lateinit var containerFile: File

    @Before
    fun setUp() {
        TEST_DIR.mkdirs()
        containerFile = File(TEST_DIR, "uri_${System.nanoTime()}.hc")
        VolumeCreator.createContainer(
            containerFile.absolutePath, PASSWORD.toCharArray(), 5,
            algorithm = AES, hashAlgorithm = SHA512
        ).getOrThrow()
    }

    @After
    fun tearDown() {
        containerFile.delete()
    }

    private fun mockContext(): Context {
        val pfd = ParcelFileDescriptor.open(
            containerFile, ParcelFileDescriptor.MODE_READ_WRITE
        )
        val resolver = mock<android.content.ContentResolver> {
            on { openFileDescriptor(any<Uri>(), eq("rw")) } doReturn pfd
        }
        return mock<Context> { on { contentResolver } doReturn resolver }
    }

    private fun nullFdContext(): Context {
        val resolver = mock<android.content.ContentResolver> {
            on { openFileDescriptor(any<Uri>(), eq("rw")) } doReturn null
        }
        return mock<Context> { on { contentResolver } doReturn resolver }
    }

    private fun newReader(ctx: Context, uri: Uri) =
        VolumeReader(containerPath = containerFile.absolutePath, context = ctx, containerUri = uri)

    @Test
    fun `mount via content URI decrypts the header`() {
        val reader = newReader(mockContext(), Uri.parse("content://test/container.hc"))
        val result = reader.mount(PASSWORD.toCharArray())
        assertTrue("mount via URI failed: ${result.exceptionOrNull()?.message}", result.isSuccess)
        val info = result.getOrThrow()
        assertTrue(info.isMounted)
        assertTrue(info.dataAreaSize > 0)
        reader.unmount()
    }

    @Test
    fun `mount via content URI with wrong password fails`() {
        val reader = newReader(mockContext(), Uri.parse("content://test/container.hc"))
        val result = reader.mount("WrongPassword!".toCharArray())
        assertTrue(result.isFailure)
        assertEquals(
            "Invalid password or corrupted header",
            result.exceptionOrNull()?.message
        )
    }

    @Test
    fun `mount via URI fails when contentResolver returns null fd`() {
        val reader = newReader(nullFdContext(), Uri.parse("content://test/container.hc"))
        val result = reader.mount(PASSWORD.toCharArray())
        assertTrue(result.isFailure)
    }
}
