import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Firma de release: los datos viven en keystore.properties (fuera de git).
// Sin ese archivo la compilación de depuración sigue funcionando igual.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "org.armax.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.armax.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 6
        versionName = "0.1.5"
        // libarmax_ffi.so solo se compila para ARM de 64 bits (ver README)
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    signingConfigs {
        if (keystoreProps.getProperty("storeFile") != null) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    // JNA: carga libarmax_ffi.so sin escribir JNI
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // ZXing (generador de códigos QR)
    implementation("com.google.zxing:core:3.5.3")
    // Escáner de QR con cámara (activity propia; pide el permiso de cámara por sí sola)
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
