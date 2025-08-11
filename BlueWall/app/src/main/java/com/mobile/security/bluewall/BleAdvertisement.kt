package com.mobile.security.bluewall

import java.util.UUID

data class BleAdvertisement(
    val name: String,
    val mac: String,
    val rssi: Int,
    val manufacturerData: ByteArray?,
    val serviceUUIDs: List<String>?,
    val timestamp: Long
)

