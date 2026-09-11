plugins {
    alias(libs.plugins.android.application)
}

val sampleSigningSha256 = providers.gradleProperty("rootect.sampleSigningSha256")
    .orElse("")
    .get()
    .lowercase()
require(sampleSigningSha256.isEmpty() || sampleSigningSha256.matches(Regex("[0-9a-f]{64}"))) {
    "rootect.sampleSigningSha256 must be 64 hexadecimal characters"
}

android {
    namespace = "io.github.rootect.sample"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.rootect.demo"
        minSdk = 24
        versionCode = 1
        versionName = providers.gradleProperty("VERSION_NAME").get()
        buildConfigField("String", "ROOTECT_SIGNING_SHA256", "\"$sampleSigningSha256\"")
    }

    buildFeatures { buildConfig = true }

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
