package com.androidcrypt.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.provider.DocumentsContract
import android.util.Log
import androidx.core.app.NotificationCompat
import com.androidcrypt.crypto.FAT32Reader
import com.androidcrypt.crypto.VolumeMountManager
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Semaphore
import java.io.ByteArrayInputStream

/**
 * Foreground Service for copying files to/from encrypted volumes.
 * Allows file operations to continue when the app is in the background.
 */
class CopyService : Service() {
    
    companion object {
        private const val TAG = "CopyService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "copy_service_channel"
        
        // Action constants
        const val ACTION_COPY_FOLDER_TO_VOLUME = "copy_folder_to_volume"
        const val ACTION_COPY_FILE_TO_VOLUME = "copy_file_to_volume"
        const val ACTION_COPY_FOLDER_PATH_TO_VOLUME = "copy_folder_path_to_volume" // java.io.File-based, bypasses SAF
        const val ACTION_CANCEL = "cancel_copy"
        
        // Extra keys
        const val EXTRA_SOURCE_URI = "source_uri"
        const val EXTRA_SOURCE_PATH = "source_path" // absolute file-system path for File-based copy
        const val EXTRA_VOLUME_PATH = "volume_path"
        const val EXTRA_FOLDER_NAME = "folder_name"
        
        // Singleton for accessing current state from Activity
        private val _copyState = MutableStateFlow<CopyState>(CopyState.Idle)
        val copyState: StateFlow<CopyState> = _copyState
        
        private val _progress = MutableStateFlow("")
        val progress: StateFlow<String> = _progress
        
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
    }
    
    sealed class CopyState {
        object Idle : CopyState()
        data class Copying(val progress: String, val current: Int, val total: Int) : CopyState()
        data class Completed(val message: String, val success: Boolean) : CopyState()
        data class Error(val message: String) : CopyState()
    }
    
    private val binder = LocalBinder()
    private var copyJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var wakeLock: PowerManager.WakeLock? = null
    
    inner class LocalBinder : Binder() {
        fun getService(): CopyService = this@CopyService
    }
    
    override fun onBind(intent: Intent?): IBinder = binder
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")
        when (intent?.action) {
            ACTION_CANCEL -> {
                Log.d(TAG, "Cancel action received")
                cancelCopy()
                return START_NOT_STICKY
            }
            ACTION_COPY_FOLDER_TO_VOLUME -> {
                val sourceUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(EXTRA_SOURCE_URI, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Uri>(EXTRA_SOURCE_URI)
                }
                val volumePath = intent.getStringExtra(EXTRA_VOLUME_PATH)
                val folderName = intent.getStringExtra(EXTRA_FOLDER_NAME)
                
                if (sourceUri != null && volumePath != null && folderName != null) {
                    startForeground(NOTIFICATION_ID, createNotification("Preparing to copy..."))
                    acquireWakeLock()
                    startFolderCopy(sourceUri, volumePath, folderName)
                }
            }
            ACTION_COPY_FILE_TO_VOLUME -> {
                val sourceUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(EXTRA_SOURCE_URI, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Uri>(EXTRA_SOURCE_URI)
                }
                val volumePath = intent.getStringExtra(EXTRA_VOLUME_PATH)
                
                if (sourceUri != null && volumePath != null) {
                    startForeground(NOTIFICATION_ID, createNotification("Preparing to copy..."))
                    acquireWakeLock()
                    startFileCopy(sourceUri, volumePath)
                }
            }
            ACTION_COPY_FOLDER_PATH_TO_VOLUME -> {
                // File-based folder copy — bypasses SAF restrictions entirely.
                // Used when the app has MANAGE_EXTERNAL_STORAGE and shows its own folder browser.
                val sourcePath = intent.getStringExtra(EXTRA_SOURCE_PATH)
                val volumePath = intent.getStringExtra(EXTRA_VOLUME_PATH)
                if (sourcePath != null && volumePath != null) {
                    val sourceDir = java.io.File(sourcePath)
                    if (sourceDir.isDirectory) {
                        startForeground(NOTIFICATION_ID, createNotification("Preparing to copy..."))
                        acquireWakeLock()
                        startFolderCopyFromPath(sourceDir, volumePath)
                    }
                }
            }
        }
        
        return START_NOT_STICKY
    }
    
    override fun onDestroy() {
        super.onDestroy()
        cancelCopy()
        releaseWakeLock()
        _isRunning.value = false  // Always reset so a future service instance isn't blocked
        serviceScope.cancel()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "File Copy Operations",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress of file copy operations"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(progressText: String, current: Int = 0, total: Int = 0): Notification {
        val cancelIntent = Intent(this, CopyService::class.java).apply {
            action = ACTION_CANCEL
        }
        val cancelPendingIntent = PendingIntent.getService(
            this, 0, cancelIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openAppPendingIntent = PendingIntent.getActivity(
            this, 0, openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Copying files to encrypted volume")
            .setContentText(progressText)
            .setSmallIcon(android.R.drawable.ic_menu_upload)
            .setOngoing(true)
            .setContentIntent(openAppPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel", cancelPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
        
        if (total > 0) {
            builder.setProgress(total, current, false)
        } else {
            builder.setProgress(0, 0, true)
        }
        
        return builder.build()
    }
    
    private var lastNotificationTime = 0L
    private val notificationRateLimit = 500L // Update at most every 500ms
    
    private fun updateNotification(progressText: String, current: Int = 0, total: Int = 0, force: Boolean = false) {
        val now = System.currentTimeMillis()
        // Rate limit notification updates to avoid system throttling
        if (!force && now - lastNotificationTime < notificationRateLimit) {
            // Still update the StateFlow for UI, just skip the system notification
            _progress.value = progressText
            _copyState.value = CopyState.Copying(progressText, current, total)
            return
        }
        lastNotificationTime = now
        
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, createNotification(progressText, current, total))
        
        _progress.value = progressText
        _copyState.value = CopyState.Copying(progressText, current, total)
    }
    
    private fun acquireWakeLock() {
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "CopyService::WakeLock"
        ).apply {
            acquire(60 * 60 * 1000L) // 1 hour max
        }
    }
    
    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) {
                it.release()
            }
        }
        wakeLock = null
    }
    
    fun cancelCopy() {
        Log.d(TAG, "cancelCopy() called, copyJob=$copyJob")
        val job = copyJob
        copyJob = null
        
        // Only show cancelled message if job was actually running (not already completed)
        if (job != null && job.isActive) {
            job.cancel()
            _isRunning.value = false
            _copyState.value = CopyState.Error("Copy cancelled")
        }
        
        releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.d(TAG, "cancelCopy() complete")
    }
    
    private fun completeCopy(success: Boolean, message: String) {
        _isRunning.value = false
        _copyState.value = if (success) {
            CopyState.Completed(message, true)
        } else {
            CopyState.Error(message)
        }
        
        // Show completion notification
        val notificationManager = getSystemService(NotificationManager::class.java)
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(if (success) "Copy complete" else "Copy failed")
            .setContentText(message)
            .setSmallIcon(if (success) android.R.drawable.ic_menu_upload else android.R.drawable.ic_dialog_alert)
            .setAutoCancel(true)
            .build()
        
        notificationManager.notify(NOTIFICATION_ID + 1, notification)
        
        releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }
    
    private fun startFileCopy(sourceUri: Uri, volumePath: String) {
        if (_isRunning.value) {
            Log.w(TAG, "Copy already in progress")
            return
        }
        
        _isRunning.value = true
        _copyState.value = CopyState.Copying("Starting...", 0, 1)
        
        copyJob = serviceScope.launch {
            try {
                val reader = VolumeMountManager.getOrCreateFileSystemReader(volumePath)
                    ?: run { completeCopy(false, "Volume not mounted"); return@launch }
                
                // Get file name and size
                val fileName = getFileNameFromUri(sourceUri)
                val fileSize = getFileSizeFromUri(sourceUri)
                
                Log.d(TAG, "startFileCopy: fileSize=${fileSize / (1024 * 1024)} MB")
                
                updateNotification("Copying: $fileName", 0, 1)
                
                // Open input stream for the file
                val inputStream = contentResolver.openInputStream(sourceUri)
                if (inputStream == null) {
                    completeCopy(false, "Could not open file")
                    return@launch
                }
                
                // Create file in volume
                val filePath = "/$fileName"
                if (!reader.exists(filePath)) {
                    reader.createFile("/", fileName).getOrThrow()
                }
                
                // Stream file directly to volume (no memory buffering)
                // Wrap in BufferedInputStream to reduce content-provider syscalls
                // when filling the 8MB write-batch buffer
                val bufferedStream = java.io.BufferedInputStream(inputStream, 1024 * 1024) // 1MB
                bufferedStream.use { stream ->
                    reader.writeFileStreaming(filePath, stream, fileSize) { bytesWritten ->
                        val percent = if (fileSize > 0) (bytesWritten * 100 / fileSize).toInt() else 0
                        if (bytesWritten % (50 * 1024 * 1024) < (256 * 1024)) { // Log every ~50MB
                            Log.d(TAG, "startFileCopy: Progress ${bytesWritten / (1024 * 1024)} MB / ${fileSize / (1024 * 1024)} MB ($percent%)")
                        }
                    }.getOrThrow()
                }
                
                Log.d(TAG, "startFileCopy: Streaming write completed")
                updateNotification("Complete: $fileName", 1, 1)
                
                // Notify DocumentsProvider
                notifyVolumeChanged(volumePath)
                
                completeCopy(true, "File copied successfully!")
                
            } catch (e: CancellationException) {
                completeCopy(false, "Copy cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Copy failed", e)
                completeCopy(false, "Copy failed: ${e.message}")
            }
        }
    }
    
    private fun startFolderCopy(sourceUri: Uri, volumePath: String, folderName: String) {
        if (_isRunning.value) {
            Log.w(TAG, "Copy already in progress")
            return
        }
        
        _isRunning.value = true
        _copyState.value = CopyState.Copying("Counting files...", 0, 0)
        
        copyJob = serviceScope.launch {
            try {
                val reader = VolumeMountManager.getOrCreateFileSystemReader(volumePath)
                    ?: run { completeCopy(false, "Volume not mounted"); return@launch }
                
                updateNotification("Counting files...", 0, 0)
                
                // Count total files
                val totalFiles = countFilesInFolder(sourceUri)
                val counter = CopyCounter(totalFiles)
                
                updateNotification("Copying 0/$totalFiles files...", 0, totalFiles)
                
                // Copy folder
                copyFolderToVolume(sourceUri, "/", folderName, reader, counter) { progress ->
                    updateNotification(progress, counter.current, counter.total)
                }
                
                // Notify DocumentsProvider
                notifyVolumeChanged(volumePath)
                
                val failedCount = counter.failedFiles.size
                if (failedCount > 0) {
                    val successCount = totalFiles - failedCount
                    completeCopy(false, "Copied $successCount/$totalFiles files. $failedCount failed: ${counter.failedFiles.take(5).joinToString(", ")}")
                } else {
                    completeCopy(true, "Folder copied successfully! ($totalFiles files)")
                }
                
            } catch (e: CancellationException) {
                completeCopy(false, "Copy cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Copy failed", e)
                completeCopy(false, "Copy failed: ${e.message}")
            }
        }
    }
    
    // ── File-based folder copy (bypasses SAF ACTION_OPEN_DOCUMENT_TREE restrictions) ───────────

    private fun startFolderCopyFromPath(sourceDir: java.io.File, volumePath: String) {
        if (_isRunning.value) {
            Log.w(TAG, "Copy already in progress")
            return
        }

        _isRunning.value = true
        _copyState.value = CopyState.Copying("Counting files...", 0, 0)

        copyJob = serviceScope.launch {
            try {
                val reader = VolumeMountManager.getOrCreateFileSystemReader(volumePath)
                    ?: run { completeCopy(false, "Volume not mounted"); return@launch }

                updateNotification("Counting files...", 0, 0)

                val totalFiles = countFilesInDirectory(sourceDir)
                val counter = CopyCounter(totalFiles)

                updateNotification("Copying 0/$totalFiles files...", 0, totalFiles)

                copyFolderToVolumeFromPath(sourceDir, "/", reader, counter) { progress ->
                    updateNotification(progress, counter.current, counter.total)
                }

                notifyVolumeChanged(volumePath)

                val failedCount = counter.failedFiles.size
                if (failedCount > 0) {
                    val successCount = totalFiles - failedCount
                    completeCopy(false, "Copied $successCount/$totalFiles files. $failedCount failed: ${counter.failedFiles.take(5).joinToString(", ")}")
                } else {
                    completeCopy(true, "Folder copied successfully! ($totalFiles files)")
                }
            } catch (e: CancellationException) {
                completeCopy(false, "Copy cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Folder copy from path failed", e)
                completeCopy(false, "Copy failed: ${e.message}")
            }
        }
    }

    private fun countFilesInDirectory(dir: java.io.File): Int {
        var count = 0
        dir.listFiles()?.forEach { entry ->
            if (entry.isDirectory) count += countFilesInDirectory(entry) else count++
        }
        return count
    }

    private suspend fun copyFolderToVolumeFromPath(
        sourceDir: java.io.File,
        targetPath: String,
        reader: FAT32Reader,
        counter: CopyCounter,
        onProgress: (String) -> Unit
    ): Unit = coroutineScope {
        val folderName = sourceDir.name
        val newFolderPath = if (targetPath == "/") "/$folderName" else "$targetPath/$folderName"

        if (!reader.exists(newFolderPath)) {
            reader.createDirectory(targetPath, folderName).getOrThrow()
        }

        val entries = sourceDir.listFiles() ?: return@coroutineScope
        val files = entries.filter { it.isFile }
        val subdirs = entries.filter { it.isDirectory }

        val semaphore = kotlinx.coroutines.sync.Semaphore(SMALL_FILE_PARALLELISM)

        val fileJobs = files.map { file ->
            launch(Dispatchers.IO) {
                semaphore.acquire()
                try {
                    ensureActive()
                    counter.increment()
                    onProgress("Copying ${counter.progressString()}: ${file.name}")

                    val filePath = "$newFolderPath/${file.name}"
                    var shouldCopy = true
                    if (reader.exists(filePath)) {
                        val existingInfo = reader.getFileInfo(filePath).getOrNull()
                        val sourceSize = file.length()
                        if (existingInfo == null ||
                            (existingInfo.size == 0L && sourceSize > 0) ||
                            (existingInfo.size != sourceSize && sourceSize > 0)) {
                            // 0-byte entry, unknown info, or size mismatch (partial/corrupted) — re-copy
                            try { reader.delete(filePath) } catch (_: Exception) {}
                        } else {
                            shouldCopy = false
                        }
                    }

                    if (shouldCopy) {
                        try {
                            reader.createFile(newFolderPath, file.name).getOrThrow()
                            java.io.BufferedInputStream(file.inputStream(), 1024 * 1024).use { stream ->
                                if (file.length() > 0) {
                                    reader.writeFileStreaming(filePath, stream, file.length()) { bytesWritten ->
                                        if (bytesWritten % (10 * 1024 * 1024) == 0L) {
                                            onProgress("Copying ${counter.progressString()}: ${bytesWritten / (1024 * 1024)}MB")
                                        }
                                    }.getOrThrow()
                                }
                            }
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            // Clean up any partial/0-byte entry left behind by the failed write
                            try {
                                if (reader.exists(filePath)) reader.delete(filePath)
                            } catch (cleanupEx: Exception) {
                                Log.w(TAG, "Failed to clean up partial entry: ${file.name}", cleanupEx)
                            }
                            throw e  // Re-throw so the outer catch reports the failure
                        }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to copy file: ${file.name}", e)
                    counter.addFailure(file.name)
                    onProgress("Failed ${file.name}: ${e.message}")
                } finally {
                    semaphore.release()
                }
            }
        }

        val subdirJobs = subdirs.map { dir ->
            launch(Dispatchers.IO) {
                copyFolderToVolumeFromPath(dir, newFolderPath, reader, counter, onProgress)
            }
        }

        fileJobs.forEach { it.join() }
        subdirJobs.forEach { it.join() }
    }

    // ─────────────────────────────────────────────────────────────────────────

    private fun notifyVolumeChanged(volumePath: String) {
        try {
            val authority = "com.androidcrypt.documents"
            val rootId = "veracrypt_${volumePath.hashCode()}"
            val rootDocId = "$rootId:/"
            val childrenUri = DocumentsContract.buildChildDocumentsUri(authority, rootDocId)
            contentResolver.notifyChange(childrenUri, null)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to notify volume change", e)
        }
    }
    
    private fun getFileNameFromUri(uri: Uri): String {
        var fileName: String? = null
        try {
            contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0 && !cursor.isNull(idx)) {
                        fileName = cursor.getString(idx)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to query file name from URI", e)
        }
        return fileName ?: uri.lastPathSegment ?: "unknown"
    }
    
    private fun getFileSizeFromUri(uri: Uri): Long {
        var size = 0L
        try {
            contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(android.provider.OpenableColumns.SIZE)
                    if (idx >= 0 && !cursor.isNull(idx)) {
                        size = cursor.getLong(idx)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to query file size from URI", e)
        }
        return size
    }
    
    private fun countFilesInFolder(folderUri: Uri): Int {
        var count = 0
        // Handle both tree URIs and document URIs
        val docId = try {
            DocumentsContract.getDocumentId(folderUri)
        } catch (e: Exception) {
            DocumentsContract.getTreeDocumentId(folderUri)
        }
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val mimeType = cursor.getString(1)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    // Recursively count subfolder
                    val subFolderUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
                    count += countFilesInSubFolder(folderUri, docId)
                } else {
                    count++
                }
            }
        }
        
        return count
    }
    
    private fun countFilesInSubFolder(treeUri: Uri, folderId: String): Int {
        var count = 0
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, folderId)
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val mimeType = cursor.getString(1)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    count += countFilesInSubFolder(treeUri, docId)
                } else {
                    count++
                }
            }
        }
        
        return count
    }
    
    // Data class for pre-read files (small files only)
    private data class PreReadFile(
        val name: String,
        val targetPath: String,
        val data: ByteArray,
        val size: Long
    )
    
    // Data class for large files that need streaming
    private data class LargeFileInfo(
        val docId: String,
        val name: String,
        val targetPath: String,
        val size: Long
    )
    
    // Optimized thresholds and parallelism settings
    // Small files: stream directly instead of buffering (reduces memory pressure)
    // Large files: already streamed, just increase parallelism
    private val LARGE_FILE_THRESHOLD = 5 * 1024 * 1024L  // 5MB threshold for streaming
    
    // Unified parallelism — all files share one semaphore.
    // FAT metadata writes serialize on writeLock, so >4 concurrent writers
    // just increases contention without improving throughput.
    private val SMALL_FILE_PARALLELISM = 4
    
    // Counter class for progress tracking
    class CopyCounter(val total: Int) {
        var current: Int = 0
            private set
        
        // Track files that failed so we can report them at the end
        private val _failedFiles = mutableListOf<String>()
        val failedFiles: List<String> get() = _failedFiles
        
        fun increment() {
            current++
        }
        
        @Synchronized
        fun addFailure(name: String) {
            _failedFiles.add(name)
        }
        
        fun progressString(): String = "$current/$total"
    }
    
    private suspend fun copyFolderToVolume(
        folderUri: Uri,
        targetPath: String,
        folderName: String,
        reader: FAT32Reader,
        counter: CopyCounter,
        onProgress: (String) -> Unit
    ): Unit = coroutineScope {
        // Create the folder in the volume
        val newFolderPath = if (targetPath == "/") "/$folderName" else "$targetPath/$folderName"
        
        if (!reader.exists(newFolderPath)) {
            reader.createDirectory(targetPath, folderName).getOrThrow()
        }
        
        // Handle both tree URIs and document URIs
        val docId = try {
            DocumentsContract.getDocumentId(folderUri)
        } catch (e: Exception) {
            DocumentsContract.getTreeDocumentId(folderUri)
        }
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(folderUri, docId)
        
        val smallFiles: MutableList<Triple<String, String, Long>> = mutableListOf()
        val largeFiles: MutableList<LargeFileInfo> = mutableListOf()
        val subdirs: MutableList<Pair<String, String>> = mutableListOf()
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val name = cursor.getString(1)
                val mimeType = cursor.getString(2)
                val size = cursor.getLong(3)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    subdirs.add(docId to name)
                } else {
                    val filePath = if (newFolderPath == "/") "/$name" else "$newFolderPath/$name"
                    var shouldCopy = true
                    if (reader.exists(filePath)) {
                        // Check if existing file is 0 bytes or size-mismatched — if so, delete and re-copy
                        val existingInfo = reader.getFileInfo(filePath).getOrNull()
                        if (existingInfo == null ||
                            (existingInfo.size == 0L && size > 0) ||
                            (size > 0 && existingInfo.size != size)) {
                            try { reader.delete(filePath) } catch (_: Exception) {}
                        } else {
                            counter.increment()
                            onProgress("Skipping ${counter.progressString()}: $name (exists)")
                            shouldCopy = false
                        }
                    }
                    if (shouldCopy) {
                        if (size > LARGE_FILE_THRESHOLD) {
                            largeFiles.add(LargeFileInfo(docId, name, newFolderPath, size))
                        } else {
                            smallFiles.add(Triple(docId, name, size))
                        }
                    }
                }
            }
        }
        
        // UNIFIED QUEUE: merge small + large files into a single list and
        // process them all with one semaphore. This prevents large files from
        // sitting idle while small files drain, and vice-versa.
        val allFiles = smallFiles.map { (docId, name, size) ->
            LargeFileInfo(docId, name, newFolderPath, size)
        } + largeFiles

        val semaphore = Semaphore(SMALL_FILE_PARALLELISM)

        val fileJobs = allFiles.map { file ->
            launch(Dispatchers.IO) {
                semaphore.acquire()
                try {
                    ensureActive()
                    copySingleFileStreaming(file.docId, file.name, file.targetPath, folderUri, reader, file.size, counter, onProgress)
                } catch (e: CancellationException) {
                    throw e // Propagate cancellation (user pressed Cancel)
                } catch (e: Exception) {
                    // Log failure but don't cancel siblings — other files should continue
                    Log.e(TAG, "Failed to copy file: ${file.name}", e)
                    counter.addFailure(file.name)
                    onProgress("Failed ${file.name}: ${e.message}")
                } finally {
                    semaphore.release()
                }
            }
        }

        // PARALLEL SUBDIRS: launch all subdirectory copies concurrently instead
        // of processing them depth-first one-by-one after all files finish.
        // The FAT32 writeLock naturally serializes metadata operations, so the
        // semaphore inside each sub-call is sufficient to prevent overload.
        val subdirJobs = subdirs.map { (docId, name) ->
            launch(Dispatchers.IO) {
                copySubFolder(folderUri, docId, newFolderPath, name, reader, counter, onProgress)
            }
        }

        // Wait for everything — files and subdirectories run concurrently
        fileJobs.forEach { it.join() }
        subdirJobs.forEach { it.join() }
    }
    
    /**
     * Copy a single file using streaming (no memory buffering)
     * This is the optimized version that works for both small and large files
     */
    private suspend fun copySingleFileStreaming(
        docId: String,
        name: String,
        targetPath: String,
        folderUri: Uri,
        reader: FAT32Reader,
        fileSize: Long,
        counter: CopyCounter,
        onProgress: (String) -> Unit
    ): Unit {
        counter.increment()
        onProgress("Copying ${counter.progressString()}: $name")
        
        val newFilePath = if (targetPath == "/") "/$name" else "$targetPath/$name"
        
        try {
            // Create file in volume
            reader.createFile(targetPath, name).getOrThrow()
            
            // Stream directly from source to volume - no intermediate buffering
            val fileUri = DocumentsContract.buildDocumentUriUsingTree(folderUri, docId)
            val inputStream = contentResolver.openInputStream(fileUri)
                ?: throw Exception("Could not open input stream for $name")
            inputStream.use { inputStream ->
                // Use a large buffered stream for better I/O performance (1MB buffer)
                val bufferedStream = java.io.BufferedInputStream(inputStream, 1024 * 1024)
                
                // Use actual file size for proper cluster allocation.
                // If size is unknown (0 or -1), query it or fall back to dynamic streaming.
                val actualSize = if (fileSize > 0) fileSize else {
                    val queriedSize = getFileSizeFromUri(fileUri)
                    if (queriedSize > 0) queriedSize else -1L
                }
                
                if (actualSize > 0) {
                    reader.writeFileStreaming(newFilePath, bufferedStream, actualSize) { bytesWritten ->
                        if (bytesWritten % (10 * 1024 * 1024) == 0L) {
                            onProgress("Copying ${counter.progressString()}: ${bytesWritten / (1024 * 1024)}MB")
                        }
                    }.getOrThrow()
                } else {
                    // Unknown size: use dynamic streaming (allocates clusters on-demand)
                    reader.writeFileStreamingDynamic(newFilePath, bufferedStream) { bytesWritten ->
                        if (bytesWritten % (10 * 1024 * 1024) == 0L) {
                            onProgress("Copying ${counter.progressString()}: ${bytesWritten / (1024 * 1024)}MB")
                        }
                    }.getOrThrow()
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write file $name", e)
            // Clean up 0-byte file that was created before the write failed
            try {
                if (reader.exists(newFilePath)) {
                    reader.delete(newFilePath)
                }
            } catch (cleanupEx: Exception) {
                Log.w(TAG, "Failed to clean up 0-byte file", cleanupEx)
            }
            throw e
        }
    }
    
    private suspend fun copySubFolder(
        treeUri: Uri,
        folderId: String,
        targetPath: String,
        folderName: String,
        reader: FAT32Reader,
        counter: CopyCounter,
        onProgress: (String) -> Unit
    ): Unit = coroutineScope {
        val newFolderPath = if (targetPath == "/") "/$folderName" else "$targetPath/$folderName"
        
        if (!reader.exists(newFolderPath)) {
            reader.createDirectory(targetPath, folderName).getOrThrow()
        }
        
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, folderId)
        
        val smallFiles: MutableList<Triple<String, String, Long>> = mutableListOf()
        val largeFiles: MutableList<LargeFileInfo> = mutableListOf()
        val subdirs: MutableList<Pair<String, String>> = mutableListOf()
        
        contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE
            ),
            null, null, null
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val docId = cursor.getString(0)
                val name = cursor.getString(1)
                val mimeType = cursor.getString(2)
                val size = cursor.getLong(3)
                
                if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                    subdirs.add(docId to name)
                } else {
                    val filePath = if (newFolderPath == "/") "/$name" else "$newFolderPath/$name"
                    var shouldCopy = true
                    if (reader.exists(filePath)) {
                        // Check if existing file is 0 bytes or size-mismatched — if so, delete and re-copy
                        val existingInfo = reader.getFileInfo(filePath).getOrNull()
                        if (existingInfo == null ||
                            (existingInfo.size == 0L && size > 0) ||
                            (size > 0 && existingInfo.size != size)) {
                            try { reader.delete(filePath) } catch (_: Exception) {}
                        } else {
                            counter.increment()
                            onProgress("Skipping ${counter.progressString()}: $name (exists)")
                            shouldCopy = false
                        }
                    }
                    if (shouldCopy) {
                        if (size > LARGE_FILE_THRESHOLD) {
                            largeFiles.add(LargeFileInfo(docId, name, newFolderPath, size))
                        } else {
                            smallFiles.add(Triple(docId, name, size))
                        }
                    }
                }
            }
        }
        
        // UNIFIED QUEUE: merge small + large files into a single list and
        // process them all with one semaphore.
        val allFiles = smallFiles.map { (docId, name, size) ->
            LargeFileInfo(docId, name, newFolderPath, size)
        } + largeFiles

        val semaphore = Semaphore(SMALL_FILE_PARALLELISM)

        val fileJobs = allFiles.map { file ->
            launch(Dispatchers.IO) {
                semaphore.acquire()
                try {
                    ensureActive()
                    copySingleFileStreaming(file.docId, file.name, file.targetPath, treeUri, reader, file.size, counter, onProgress)
                } catch (e: CancellationException) {
                    throw e // Propagate cancellation (user pressed Cancel)
                } catch (e: Exception) {
                    // Log failure but don't cancel siblings — other files should continue
                    Log.e(TAG, "Failed to copy file: ${file.name}", e)
                    counter.addFailure(file.name)
                    onProgress("Failed ${file.name}: ${e.message}")
                } finally {
                    semaphore.release()
                }
            }
        }

        // PARALLEL SUBDIRS: launch all subdirectory copies concurrently.
        val subdirJobs = subdirs.map { (docId, name) ->
            launch(Dispatchers.IO) {
                copySubFolder(treeUri, docId, newFolderPath, name, reader, counter, onProgress)
            }
        }

        // Wait for everything — files and subdirectories run concurrently
        fileJobs.forEach { it.join() }
        subdirJobs.forEach { it.join() }
    }
}
