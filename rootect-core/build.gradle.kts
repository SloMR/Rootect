plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
    signing
}

group = providers.gradleProperty("GROUP").get()
version = providers.gradleProperty("VERSION_NAME").get()

android {
    namespace = "io.github.rootect"
    compileSdk = 37
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 24

        consumerProguardFiles("consumer-rules.pro")

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
}

val javadocJar = tasks.register<Jar>("javadocJar") {
    archiveClassifier.set("javadoc")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "rootect-core"
            artifact(javadocJar)
            afterEvaluate { from(components["release"]) }

            pom {
                name.set("Rootect")
                description.set(
                    "Environment-integrity evidence for Android apps: root, runtime " +
                        "instrumentation, repackaging, debuggers and emulators.",
                )
                url.set("https://github.com/SloMR/Rootect")
                inceptionYear.set("2026")

                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("rootect")
                        name.set("Sulaiman AlRomaih")
                        url.set("https://github.com/SloMR/Rootect")
                    }
                }
                scm {
                    url.set("https://github.com/SloMR/Rootect")
                    connection.set("scm:git:https://github.com/SloMR/Rootect.git")
                    developerConnection.set("scm:git:ssh://git@github.com/SloMR/Rootect.git")
                }
            }
        }
    }

    repositories {
        maven {
            name = "release"
            url = uri(layout.buildDirectory.dir("release-bundle"))
        }
    }
}

signing {
    val key = providers.environmentVariable("SIGNING_KEY").orNull
    val password = providers.environmentVariable("SIGNING_PASSWORD").orNull

    isRequired = key != null && password != null
    if (isRequired) {
        useInMemoryPgpKeys(key, password)
        sign(publishing.publications)
    }
}
