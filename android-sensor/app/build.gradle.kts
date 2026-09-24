plugins {
    id("com.android.application")
}

android {
    namespace = "com.bobsome1.watchdawg.sensor"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.bobsome1.watchdawg.sensor"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.2.0-phone-guard"

        testInstrumentationRunner = "android.app.InstrumentationTestRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
