package com.mobile.security.bluewall

import android.app.Application
import androidx.emoji2.bundled.BundledEmojiCompatConfig
import androidx.emoji2.text.EmojiCompat

class BlueWall : Application() {
    override fun onCreate() {
        super.onCreate()

        // Configure and initialize EmojiCompat
        val config = BundledEmojiCompatConfig(this)
        EmojiCompat.init(config)
    }
}
