#! /bin/bash
adb uninstall com.mobile.security.bluewall
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk

