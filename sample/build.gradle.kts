plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.github.rootect.sample"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.rootect.sample"
        minSdk = 24
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

dependencies {
    implementation(project(":rootect-core"))
}
