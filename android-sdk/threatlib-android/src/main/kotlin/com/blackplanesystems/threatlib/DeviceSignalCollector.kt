package com.blackplanesystems.threatlib

import android.content.Context
import android.os.BatteryManager
import android.os.Build
import android.os.SystemClock
import java.security.MessageDigest
import java.util.Locale
import java.util.TimeZone

data class DeviceSignals(
    val deviceHash: String,
    val platform: String,
    val androidVersion: String,
    val manufacturer: String,
    val model: String,
    val sensorCount: Int,
    val sensorTypes: List<String>,
    val accessibilityServices: List<String>,
    val installSource: String,
    val timeSinceRebootS: Long,
    val batteryLevel: Float,
    val batteryCharging: Boolean,
    val screenOn: Boolean,
    val timezone: String,
    val screenWidth: Int,
    val screenHeight: Int,
    val language: String
)

object DeviceSignalCollector {
    fun collect(context: Context): DeviceSignals {
        val display = context.resources.displayMetrics
        val battery = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val level = battery.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) / 100.0f
        val fingerprint = "${Build.MANUFACTURER}:${Build.MODEL}:${Build.VERSION.SDK_INT}"
        return DeviceSignals(
            deviceHash = sha256(fingerprint),
            platform = "android",
            androidVersion = Build.VERSION.RELEASE ?: "unknown",
            manufacturer = Build.MANUFACTURER ?: "unknown",
            model = Build.MODEL ?: "unknown",
            sensorCount = 0,
            sensorTypes = emptyList(),
            accessibilityServices = emptyList(),
            installSource = "unknown",
            timeSinceRebootS = SystemClock.elapsedRealtime() / 1000,
            batteryLevel = level,
            batteryCharging = false,
            screenOn = true,
            timezone = TimeZone.getDefault().id,
            screenWidth = display.widthPixels,
            screenHeight = display.heightPixels,
            language = Locale.getDefault().toLanguageTag()
        )
    }

    private fun sha256(value: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
