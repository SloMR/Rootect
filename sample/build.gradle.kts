plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.github.rootect.sample"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.rootect.demo"
        minSdk = 24
        versionCode = 1
        versionName = providers.gradleProperty("VERSION_NAME").get()
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
