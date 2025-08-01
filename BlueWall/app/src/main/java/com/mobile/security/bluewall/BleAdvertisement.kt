package com.mobile.security.bluewall

import java.util.UUID

data class BleAdvertisement(
    val mac: String,
    val rssi: Int,
    val timestamp: Long,
    val manufacturerData: ByteArray?,
    val serviceUUIDs: List<UUID>?,
    val deviceName: String?
)
