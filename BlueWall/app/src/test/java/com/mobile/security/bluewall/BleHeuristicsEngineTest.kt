package com.mobile.security.bluewall

import org.junit.Assert.*
import org.junit.Test
import java.util.*

class BleHeuristicsEngineTest {

    private val engine = BleHeuristicsEngine()

    @Test
    fun testDetectMacRandomization() {
        val signature = byteArrayOf(0x01, 0x02, 0x03)
        val ads = listOf(
            BleAdvertisement("AA:BB:CC:01", -40, 1000L, signature, null, "Device1"),
            BleAdvertisement("AA:BB:CC:02", -42, 1001L, signature, null, "Device2"),
            BleAdvertisement("AA:BB:CC:03", -43, 1002L, signature, null, "Device3")
        )
        val results = engine.analyze(ads, emptySet())
        assertTrue(results.any { it.threatType == ThreatType.MAC_RANDOMIZATION })
    }

    @Test
    fun testDetectUuidSpoofing() {
        val uuid = UUID.randomUUID()
        val ads = listOf(
            BleAdvertisement("11:22:33:01", -60, 2000L, null, listOf(uuid), "Beacon1"),
            BleAdvertisement("11:22:33:02", -62, 2001L, null, listOf(uuid), "Beacon2"),
            BleAdvertisement("11:22:33:03", -63, 2002L, null, listOf(uuid), "Beacon3"),
            BleAdvertisement("11:22:33:04", -64, 2003L, null, listOf(uuid), "Beacon4")
        )
        val results = engine.analyze(ads, emptySet())
        assertTrue(results.any { it.threatType == ThreatType.UUID_SPOOFING })
    }

    @Test
    fun testDetectBeaconFlooding() {
        val mac = "22:33:44:55:66:77"
        val ads = (1..6000).map {
            BleAdvertisement(mac, -50, it.toLong(), null, null, "Flooder")
        }
        val results = engine.analyze(ads, emptySet())
        assertTrue(results.any { it.threatType == ThreatType.BEACON_FLOODING })
    }

    @Test
    fun testTrustedMacFiltering() {
        val signature = byteArrayOf(0x01, 0x02, 0x03)
        val ad = BleAdvertisement("AA:BB:CC:DD:EE:FF", -45, 1234L, signature, null, "Trusted")
        val results = engine.analyze(listOf(ad, ad, ad), setOf("AA:BB:CC:DD:EE:FF"))
        assertTrue(results.isEmpty())
    }
}
