import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile


/*
 * This file was generated by the Gradle 'init' task.
 */

plugins {
    `maven-publish`
    kotlin("jvm") version "1.6.21"
    kotlin("plugin.serialization") version "1.6.21"
    application
    id("com.github.johnrengelman.shadow") version "7.0.0"
}
tasks.withType<ShadowJar> {
    isZip64 = true
    mergeServiceFiles() // # <<< Most important line
}

repositories {
    mavenLocal()
    maven {
        url = uri("https://repo.maven.apache.org/maven2/")
    }
    mavenCentral()
    maven { url = uri("https://maven.pkg.jetbrains.space/public/p/kotlinx-html/maven") }
    maven { url = uri("https://repo1.maven.org/maven2") }
}

dependencies {
    implementation("org.apache.httpcomponents:httpmime:4.5.13")

//    implementation("de.fraunhofer.sit.sse.flowdroid:soot-infoflow:2.10.0")
//    implementation("de.fraunhofer.sit.sse.flowdroid:soot-infoflow-android:2.10.0")

    implementation("de.fraunhofer.sit.sse.flowdroid:soot-infoflow-android:2.14.1")

    implementation("org.eclipse.jdt:org.eclipse.jdt.core:3.24.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.3.3")
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.6.21")
    // coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.2")
    val kotlinxHtmlVersion = "0.7.2"
    // include for Common module
    implementation("org.jetbrains.kotlinx:kotlinx-html:$kotlinxHtmlVersion")

    // test
    testImplementation(platform("org.junit:junit-bom:5.7.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
configurations.all {
    resolutionStrategy.dependencySubstitution {
        substitute(module("org.osgi.service:org.osgi.service.prefs")).with(module("org.osgi:org.osgi.service.prefs:1.1.2"))
    }
}

group = "net.bytedance.security.app"
version = "0.1.2"
description = "appshark"
java.sourceCompatibility = JavaVersion.VERSION_1_8

publishing {
    publications.create<MavenPublication>("maven") {
        from(components["java"])
    }
}
val compileKotlin: KotlinCompile by tasks
compileKotlin.kotlinOptions {
    jvmTarget = "1.8"
}
val compileTestKotlin: KotlinCompile by tasks
compileTestKotlin.kotlinOptions {
    jvmTarget = "1.8"
}
application {
    mainClass.set("net.bytedance.security.app.JavaEntry")
}
