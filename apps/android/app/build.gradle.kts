plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing comes from the environment, so the key never enters the
// repository: MAYI_KEYSTORE (path), MAYI_KEYSTORE_PASSWORD, MAYI_KEY_ALIAS.
// scripts/release.sh sets them. Every release must use the same key, or
// installed copies (and Obtainium) cannot update.
val releaseKeystore = providers.environmentVariable("MAYI_KEYSTORE").orNull

android {
    namespace = "dev.mayi.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.mayi.android"
        // Android 12: key agreement with keys held in the Android Keystore.
        minSdk = 31
        targetSdk = 36
        versionCode = 10
        versionName = "0.1.0-alpha.10"
        // The ABIs build-core.sh builds the Rust core for. Without this the APK
        // would claim every ABI JNA ships, and crash on the others.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = providers.environmentVariable("MAYI_KEYSTORE_PASSWORD").orNull
                keyAlias = providers.environmentVariable("MAYI_KEY_ALIAS").orNull ?: "mayi"
                keyPassword = storePassword
            }
        }
    }
    buildTypes {
        release {
            // Shrinking would need keep rules for JNA and the generated bindings.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all {
            // The JVM tests run the real Rust core, built for this machine by build-core.sh.
            val target = rootDir.resolve("../../target/release").canonicalPath
            it.systemProperty("jna.library.path", target)
            it.environment("MAYI_CLI", "$target/mayi")
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended:1.7.8")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.biometric:biometric:1.1.0")
    // The Rust core's bindings call it through JNA.
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    // The QR scanner: the camera through CameraX, read by ZXing. No Google
    // Play services, so it works on phones without them.
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    // Draws the QR codes this phone shows (invitations, join codes) and reads
    // the ones it scans.
    implementation("com.google.zxing:core:3.5.3")

    testImplementation("junit:junit:4.13.2")
    testImplementation("net.java.dev.jna:jna:5.17.0")
}
