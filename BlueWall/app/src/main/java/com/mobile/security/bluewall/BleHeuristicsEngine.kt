package com.mobile.security.bluewall

import android.util.Log

class BleHeuristicsEngine {

    // Rolling state: signature (6-byte hex) -> map of mac -> first seen timestamp (ms)
    private val signatureToMacsTimestamps = mutableMapOf<String, MutableMap<String, Long>>()

    // Rolling window length: 5 minutes in ms
    private val macRandomizationWindowMs = 5 * 60 * 1000L

    // Threshold to flag MAC randomization
    private val macRandomizationThreshold = 5

    fun analyze(
        advertisements: List<BleAdvertisement>,
        trustedMacs: Set<String>
    ): List<DetectionResult> {
        Log.d("BleHeuristicsEngine", "Starting analyze with ${advertisements.size} advertisements")
        val results = mutableListOf<DetectionResult>()

        results += detectMacRandomization(advertisements)
        results += detectUuidSpoofing(advertisements)
        results += detectBeaconFlooding(advertisements)

        return results.filter { it.mac !in trustedMacs }
    }

    private fun detectMacRandomization(ads: List<BleAdvertisement>): List<DetectionResult> {
        val now = System.currentTimeMillis()
        val results = mutableListOf<DetectionResult>()

        // Prune stale MAC entries older than rolling window
        val signaturesToRemove = mutableListOf<String>()
        signatureToMacsTimestamps.forEach { (signature, macs) ->
            val macsToRemove = macs.filterValues { now - it > macRandomizationWindowMs }.keys
            macsToRemove.forEach { macs.remove(it) }
            if (macs.isEmpty()) signaturesToRemove.add(signature)
        }
        signaturesToRemove.forEach { signatureToMacsTimestamps.remove(it) }

        // Update rolling state with current batch
        for (ad in ads) {
            val data = ad.manufacturerData
            if (data == null || data.isEmpty()) {
                //Log.d("BleHeuristicsEngine", "Ad ${ad.mac} has null/empty manufacturerData")
                continue
            }

            val hexData = data.joinToString("") { "%02x".format(it) }
            Log.d("BleHeuristicsEngine", "Ad ${ad.mac} manufacturerData (hex): $hexData")

            if (data.size < 5) {
                Log.d("BleHeuristicsEngine", "Ad ${ad.mac} manufacturerData too short for signature extraction")
                continue
            }

            val signatureBytes = data.sliceArray(0 until 5)
            val signature = signatureBytes.joinToString("") { "%02x".format(it) }
            //Log.d("BleHeuristicsEngine", "Ad ${ad.mac} signature: $signature")

            val macs = signatureToMacsTimestamps.getOrPut(signature) { mutableMapOf() }
            macs[ad.mac] = now
        }

        // Generate detection results for signatures exceeding threshold
        signatureToMacsTimestamps.forEach { (signature, macs) ->
            Log.d("BleHeuristicsEngine", "Signature $signature has ${macs.size} advertisements (rolling window)")
            if (macs.size >= macRandomizationThreshold) {
                macs.keys.forEach { mac ->
                    results.add(
                        DetectionResult(
                            mac = mac,
                            threatType = ThreatType.MAC_RANDOMIZATION,
                            description = "MAC randomization suspected: signature $signature with ${macs.size} unique MACs in 5-minute window"
                        )
                    )
                }
            }
        }

        return results
    }

    private fun detectUuidSpoofing(ads: List<BleAdvertisement>): List<DetectionResult> {
        val uuidToMacsDebug = mutableMapOf<String, MutableSet<String>>()

        for (ad in ads) {
            ad.serviceUUIDs?.forEach { uuid ->
                uuidToMacsDebug.getOrPut(uuid.toString()) { mutableSetOf() }.add(ad.mac)
            }
        }

        // Log.d("BleHeuristicsEngine", "coming before debug")
        // Debug logging: how many MACs per UUID
        for ((uuid, macs) in uuidToMacsDebug) {
            Log.d("UUID_ANALYSIS", "UUID=$uuid seen across ${macs.size} MAC(s)")
        }
        // Log.d("BleHeuristicsEngine", "coming after debug")

        val uuidToMacs = mutableMapOf<String, MutableSet<String>>()
        for (ad in ads) {
            ad.serviceUUIDs?.forEach { uuid ->
                uuidToMacs.getOrPut(uuid.toString()) { mutableSetOf() }.add(ad.mac)
            }
        }
        return uuidToMacs.filter { it.value.size > 5 }.flatMap { (_, macs) ->
            macs.map { mac ->
                DetectionResult(mac, ThreatType.UUID_SPOOFING, "Same UUID seen across many MACs")
            }
        }
    }

    private fun detectBeaconFlooding(ads: List<BleAdvertisement>): List<DetectionResult> {
        val macToCount = mutableMapOf<String, Int>()
        for (ad in ads) {
            macToCount[ad.mac] = (macToCount[ad.mac] ?: 0) + 1
        }

        return macToCount.filter { it.value > 5000 }.map { (mac, count) ->
            DetectionResult(mac, ThreatType.BEACON_FLOODING, "$count ads received from same MAC")
        }
    }

}
