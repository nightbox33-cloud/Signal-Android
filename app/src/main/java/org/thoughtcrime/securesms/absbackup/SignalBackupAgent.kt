package org.thoughtcrime.securesms.absbackup

import android.app.backup.BackupAgent
import android.app.backup.BackupDataInput
import android.app.backup.BackupDataOutput
import android.app.backup.FullBackupDataOutput
import android.os.ParcelFileDescriptor
import org.signal.core.util.logging.Log
import org.thoughtcrime.securesms.absbackup.backupables.SvrAuthTokens
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Uses the [Android Backup Service](https://developer.android.com/guide/topics/data/keyvaluebackup) and backs up everything in [items]
 */
class SignalBackupAgent : BackupAgent() {
  private val items: List<AndroidBackupItem> = listOf(
    SvrAuthTokens
  )

  override fun onBackup(oldState: ParcelFileDescriptor?, data: BackupDataOutput, newState: ParcelFileDescriptor) {
    Log.i(TAG, "Performing backup to Android Backup Service.")
    val contentsHash = cumulativeHashCode()
    if (oldState == null) {
      performBackup(data)
    } else {
      val hash = try {
        DataInputStream(FileInputStream(oldState.fileDescriptor)).use { it.readInt() }
      } catch (e: IOException) {
        Log.w(TAG, "No old state, may be first backup request or bug with not writing to newState at end.", e)
      }
      if (hash != contentsHash) {
        performBackup(data)
      }
    }

    DataOutputStream(FileOutputStream(newState.fileDescriptor)).use { it.writeInt(contentsHash) }
    Log.i(TAG, "Backup finished.")
  }

  private fun performBackup(data: BackupDataOutput) {
    Log.i(TAG, "Creating new backup data.")
    items.forEach {
      val backupData = it.getDataForBackup()
      data.writeEntityHeader(it.getKey(), backupData.size)
      data.writeEntityData(backupData, backupData.size)
    }
  }

  override fun onRestore(dataInput: BackupDataInput, appVersionCode: Int, newState: ParcelFileDescriptor) {
    Log.i(TAG, "Restoring from Android Backup Service.")
    while (dataInput.readNextHeader()) {
      val buffer = ByteArray(dataInput.dataSize)
      dataInput.readEntityData(buffer, 0, dataInput.dataSize)
      items.find { dataInput.key == it.getKey() }?.restoreData(buffer)
    }
    DataOutputStream(FileOutputStream(newState.fileDescriptor)).use { it.writeInt(cumulativeHashCode()) }
    Log.i(TAG, "Android Backup Service restore complete.")
  }

  /**
   * Signal only participates in key-value backup (see [items]). The default
   * [BackupAgent.onFullBackup] implementation backs up the app's entire data
   * directory, so we explicitly refuse to emit any file-based backup data.
   */
  override fun onFullBackup(data: FullBackupDataOutput) {
    Log.w(TAG, "Refusing full (file-based) backup: only key-value backup is supported.")
  }

  /**
   * Counterpart to [onFullBackup]: never restore files from a full backup set.
   */
  override fun onRestoreFile(data: ParcelFileDescriptor, size: Long, destination: File, type: Int, mode: Long, mtime: Long) {
    Log.w(TAG, "Refusing full (file-based) restore: only key-value restore is supported.")
  }

  private fun cumulativeHashCode(): Int {
    return items.fold("") { acc: String, androidBackupItem: AndroidBackupItem -> acc + androidBackupItem.getDataForBackup().decodeToString() }.hashCode()
  }

  companion object {
    private val TAG = Log.tag(SignalBackupAgent::class)
  }
}
