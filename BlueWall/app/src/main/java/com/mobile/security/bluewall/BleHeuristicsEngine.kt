package com.mobile.security.bluewall

class BleHeuristicsEngine {

    fun analyze(
        advertisements: List<BleAdvertisement>,
        trustedMacs: Set<String>
    ): List<DetectionResult> {
        val results = mutableListOf<DetectionResult>()

        results += detectMacRandomization(advertisements)
        results += detectUuidSpoofing(advertisements)
        results += detectBeaconFlooding(advertisements, 5000)

        return results.filter { it.mac !in trustedMacs }
    }

    private fun detectMacRandomization(ads: List<BleAdvertisement>): List<DetectionResult> {
        val signatureToMacs = mutableMapOf<String, MutableSet<String>>()
        for (ad in ads) {
            val signature = ad.manufacturerData?.contentToString() ?: continue
            signatureToMacs.getOrPut(signature) { mutableSetOf() }.add(ad.mac)
        }
        return signatureToMacs.filter { it.value.size > 1 }.flatMap { (_, macs) ->
            macs.map { mac ->
                DetectionResult(mac, ThreatType.MAC_RANDOMIZATION, "Multiple MACs with same signature")
            }
        }
    }

    private fun detectUuidSpoofing(ads: List<BleAdvertisement>): List<DetectionResult> {
        val uuidToMacs = mutableMapOf<String, MutableSet<String>>()
        for (ad in ads) {
            ad.serviceUUIDs?.forEach { uuid ->
                uuidToMacs.getOrPut(uuid.toString()) { mutableSetOf() }.add(ad.mac)
            }
        }
        return uuidToMacs.filter { it.value.size > 3 }.flatMap { (_, macs) ->
            macs.map { mac ->
                DetectionResult(mac, ThreatType.UUID_SPOOFING, "Same UUID seen across many MACs")
            }
        }
    }

    private fun detectBeaconFlooding(ads: List<BleAdvertisement>, threshold: Int): List<DetectionResult> {
        val macToTimestamps = mutableMapOf<String, MutableList<Long>>()
        for (ad in ads) {
            macToTimestamps.getOrPut(ad.mac) { mutableListOf() }.add(ad.timestamp)
        }
        return macToTimestamps.filter { it.value.size > threshold }.map { (mac, _) ->
            DetectionResult(mac, ThreatType.BEACON_FLOODING, "Excessive beacons from MAC")
        }
    }
}
