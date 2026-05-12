package com.blackplanesystems.threatlib

class ThreatLibClient(private val backendUrl: String) {
    fun buildScoreRequest(signals: Map<String, Any>): Pair<String, Map<String, Any>> {
        return Pair("$backendUrl/score", signals)
    }

    fun buildEventRequest(event: Map<String, Any>): Pair<String, Map<String, Any>> {
        return Pair("$backendUrl/event", event)
    }
}
