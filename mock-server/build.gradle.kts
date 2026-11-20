plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.serialization")
    application
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":rasp-core"))
    implementation("io.ktor:ktor-server-core:2.3.12")
    implementation("io.ktor:ktor-server-netty:2.3.12")
    implementation("io.ktor:ktor-server-content-negotiation:2.3.12")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.12")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.1")
    implementation("org.slf4j:slf4j-simple:2.0.13")
    testImplementation(kotlin("test"))
    testImplementation("io.ktor:ktor-server-test-host:2.3.12")
}

application {
    mainClass.set("com.bank.rasp.server.ApplicationKt")
}

tasks.test { useJUnitPlatform() }
