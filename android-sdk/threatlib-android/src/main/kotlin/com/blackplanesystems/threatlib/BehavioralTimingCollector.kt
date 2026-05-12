package com.blackplanesystems.threatlib

data class TimingFeatures(
    val fieldIntervals: Map<String, List<Float>>,
    val pasteEvents: Map<String, Boolean>,
    val tosScrolled: Boolean,
    val backNavCount: Int,
    val registrationDurationS: Int
)

class BehavioralTimingCollector {
    private val fieldIntervals = mutableMapOf<String, MutableList<Float>>()
    private val lastEvent = mutableMapOf<String, Long>()
    private val pasteEvents = mutableMapOf<String, Boolean>()
    private val startedAt = System.currentTimeMillis()
    private var tosScrolled = false
    private var backNavCount = 0

    fun recordKey(field: String) {
        val now = System.currentTimeMillis()
        lastEvent[field]?.let { fieldIntervals.getOrPut(field) { mutableListOf() }.add((now - it).toFloat()) }
        lastEvent[field] = now
    }

    fun recordPaste(field: String) {
        pasteEvents[field] = true
    }

    fun recordBackNavigation() {
        backNavCount += 1
    }

    fun recordTosScrolled() {
        tosScrolled = true
    }

    fun snapshot(): TimingFeatures {
        return TimingFeatures(fieldIntervals, pasteEvents, tosScrolled, backNavCount, ((System.currentTimeMillis() - startedAt) / 1000).toInt())
    }
}
