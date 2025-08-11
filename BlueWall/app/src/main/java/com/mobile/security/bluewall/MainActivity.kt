package com.mobile.security.bluewall

import android.graphics.Color
import android.os.*
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var outputBox: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var toggleButton: Button
    private lateinit var threatMac: TextView
    private lateinit var threatUuid: TextView
    private lateinit var threatFlood: TextView

    private var showDetails = false
    private var lastJsonLine: String? = null
    private var currentAdList: List<BleAdvertisement> = emptyList()
    private val seenMacs = mutableSetOf<String>()
    private val trustedMacs = setOf<String>()
    private val heuristics = BleHeuristicsEngine()

    private val blinkHandler = Handler(Looper.getMainLooper())
    private var blinkState = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20, 20, 20, 20)
        }

        // Threat indicators bar (vertical stacked)
        val threatBar = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 30) }
            gravity = Gravity.CENTER_HORIZONTAL
        }

        threatMac = makeThreatBox("⚠️ MAC RANDOMIZATION")
        threatUuid = makeThreatBox("📡 UUID SPOOFING")
        threatFlood = makeThreatBox("💀 BEACON FLOODING")

        threatBar.addView(threatMac)
        threatBar.addView(threatUuid)
        threatBar.addView(threatFlood)
        layout.addView(threatBar)

        // Main output scroll view
        scrollView = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }

        outputBox = TextView(this).apply {
            textSize = 14f
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            movementMethod = ScrollingMovementMethod.getInstance()
        }

        scrollView.addView(outputBox)
        layout.addView(scrollView)

        // Toggle button
        toggleButton = Button(this).apply {
            text = "Show Details"
            setOnClickListener {
                showDetails = !showDetails
                text = if (showDetails) "Show Summary" else "Show Details"
                if (!showDetails) seenMacs.clear()
                updateOutput(force = true)
            }
        }

        val exitButton = Button(this).apply {
            text = "Exit"
            setOnClickListener {
                finishAffinity()
                System.exit(0)
            }
        }

        layout.addView(toggleButton)
        layout.addView(exitButton)
        setContentView(layout)

        outputBox.text = "Connecting to BLE relay...\n"
        startTcpRelayListener()
        startBlinkTimer()
    }

    private fun makeThreatBox(label: String): TextView {
        return TextView(this).apply {
            text = label
            textSize = 16f
            setPadding(25, 20, 25, 20)
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.DKGRAY)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 8, 0, 8) }
        }
    }

    private fun startTcpRelayListener() {
        Thread {
            try {
                val socket = Socket("127.0.0.1", 9001)
                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))

                while (true) {
                    val line = reader.readLine() ?: break
                    if (line == lastJsonLine) continue
                    lastJsonLine = line

                    val devicesJson = JSONArray(line)
                    if (devicesJson.length() > 0) {
                        currentAdList = (0 until devicesJson.length()).mapNotNull { idx ->
                            try {
                                val obj = devicesJson.getJSONObject(idx)
                                BleAdvertisement(
                                    name = obj.optString("name", "Unknown"),
                                    mac = obj.optString("address", "??:??"),
                                    rssi = obj.optInt("rssi", -999),
                                    manufacturerData = obj.optString("manufacturerHex")?.hexToByteArrayOrNull(),
                                    serviceUUIDs = obj.optJSONArray("serviceUUIDs")?.let { arr ->
                                        List(arr.length()) { arr.optString(it) }
                                    } ?: emptyList(),
                                    timestamp = obj.optLong("timestamp", 0)
                                )
                            } catch (e: Exception) {
                                null
                            }
                        }
                        runOnUiThread { updateOutput(force = false) }
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    outputBox.append("Relay connection failed: ${e.message}\n")
                }
            }
        }.start()
    }

    @Volatile
    private var isUpdating = false

    private fun updateOutput(force: Boolean) {
        if (isUpdating) return
        isUpdating = true
        try {
            if (!::outputBox.isInitialized) return
            val adList = currentAdList
            val sb = StringBuilder()
            val dateFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            val nowStr = dateFormat.format(Date())

            if (showDetails) {
                adList.forEach { ad ->
                    sb.append("Name: ${ad.name}\n")
                    sb.append("Address: ${ad.mac}\n")
                    sb.append("RSSI: ${ad.rssi} dBm\n")
                    sb.append("-----\n")
                }
                if (adList.isEmpty()) sb.append("No BLE devices found.\n")
            } else {
                val findings = heuristics.analyze(adList, trustedMacs)
                if (findings.isEmpty()) {
                    sb.append("No BLE threats or devices found.\n")
                } else {
                    findings.forEach { res ->
                        sb.append("${res.mac} → ${res.threatType}: ${res.description}\n")
                    }
                }
                sb.append("\nTracking active. Last update: $nowStr\n")
                if (force) seenMacs.clear()
                findings.forEach { res -> seenMacs.add(res.mac) }

                // Update threat boxes
                val macThreat = findings.any { it.threatType.name == "MAC_RANDOMIZATION" }
                val uuidThreat = findings.any { it.threatType.name == "UUID_SPOOFING" }
                val floodThreat = findings.any { it.threatType.name == "BEACON_FLOODING" }

                updateThreatBox(threatMac, macThreat)
                updateThreatBox(threatUuid, uuidThreat)
                updateThreatBox(threatFlood, floodThreat)
            }

            runOnUiThread {
                outputBox.text = sb.toString()
                scrollView.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
                outputBox.requestLayout()
            }
        } finally {
            isUpdating = false
        }
    }

    private fun updateThreatBox(view: TextView, active: Boolean) {
        if (active) {
            view.setBackgroundColor(if (blinkState) Color.RED else Color.DKGRAY)
        } else {
            view.setBackgroundColor(Color.DKGRAY)
        }
    }

    private fun startBlinkTimer() {
        blinkHandler.postDelayed(object : Runnable {
            override fun run() {
                blinkState = !blinkState
                updateOutput(force = false)
                blinkHandler.postDelayed(this, 700)
            }
        }, 700)
    }

    private fun String.hexToByteArrayOrNull(): ByteArray? {
        return try {
            chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (e: Exception) {
            null
        }
    }
}
