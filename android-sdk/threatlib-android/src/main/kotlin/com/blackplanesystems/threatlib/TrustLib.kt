package com.blackplanesystems.threatlib

import android.content.Context

object ThreatLib {
    private var backendUrl: String = ""
    private var adapter: String = "generic"
    private var accountId: String = ""

    fun initialize(context: Context, backendUrl: String, platformAdapter: String = "generic") {
        this.backendUrl = backendUrl
        this.adapter = platformAdapter
    }

    fun setAccountId(hashedId: String) {
        accountId = hashedId
    }

    fun collectAndSubmit(context: Context): Map<String, Any> {
        val device = DeviceSignalCollector.collect(context)
        return mapOf(
            "account_id" to accountId,
            "platform_adapter" to adapter,
            "device_hash" to device.deviceHash,
            "device_platform" to device.platform,
            "device_android_version" to device.androidVersion,
            "device_manufacturer" to device.manufacturer,
            "device_model" to device.model,
            "device_sensor_count" to device.sensorCount,
            "device_sensor_types" to device.sensorTypes,
            "device_accessibility_services" to device.accessibilityServices,
            "device_install_source" to device.installSource,
            "device_time_since_reboot_s" to device.timeSinceRebootS,
            "device_battery_level" to device.batteryLevel,
            "device_battery_charging" to device.batteryCharging,
            "device_screen_on" to device.screenOn,
            "device_timezone" to device.timezone,
            "device_screen_width" to device.screenWidth,
            "device_screen_height" to device.screenHeight,
            "device_language" to device.language
        )
    }

    fun recordEvent(eventType: String, eventData: Map<String, Any>): Map<String, Any> {
        return mapOf("account_id" to accountId, "event_type" to eventType, "event_data" to eventData)
    }
}
