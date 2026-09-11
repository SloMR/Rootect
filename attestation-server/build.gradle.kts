plugins {
    kotlin("jvm")
    application
}

dependencies {
    implementation("com.android:keyattestation:local")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("com.google.protobuf:protobuf-javalite:4.28.3")
    implementation("io.ktor:ktor-server-body-limit-jvm:3.5.2")
    implementation("io.ktor:ktor-server-core-jvm:3.5.2")
    implementation("io.ktor:ktor-server-netty-jvm:3.5.2")

    testImplementation(kotlin("test-junit5"))
    testImplementation("io.ktor:ktor-server-test-host-jvm:3.5.2")
}

kotlin { jvmToolchain(21) }

application {
    mainClass.set("io.github.rootect.attestation.AttestationServerKt")
}

tasks.test { useJUnitPlatform() }
