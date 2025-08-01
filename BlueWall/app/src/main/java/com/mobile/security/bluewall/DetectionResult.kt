package com.mobile.security.bluewall

data class DetectionResult(
    val mac: String,
    val threatType: ThreatType,
    val description: String
)
