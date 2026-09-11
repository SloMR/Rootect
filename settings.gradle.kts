pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Rootect"

include(":rootect-core")
include(":sample")

val keyAttestationPath = providers.gradleProperty("keyAttestationPath").orNull
    ?: providers.environmentVariable("KEY_ATTESTATION_PATH").orNull
if (keyAttestationPath != null) {
    includeBuild(file(keyAttestationPath)) {
        dependencySubstitution {
            substitute(module("com.android:keyattestation")).using(project(":"))
        }
    }
    include(":attestation-server")
}
