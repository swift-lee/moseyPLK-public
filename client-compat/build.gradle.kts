import groovy.json.JsonSlurper

buildscript {
    dependencies { classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.20") }
}
plugins {
    id("com.android.application") version "9.2.1"
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20"
}

val release = JsonSlurper().parse(file("../release.json")) as Map<*, *>
val assets = file("../moseyPLK-assets")
val stage = providers.gradleProperty("moseyStage").get()
layout.buildDirectory.set(file("$stage/gradle"))

android {
    namespace = release["client_id"] as String
    compileSdk = 37
    buildToolsVersion = "37.0.0"
    testBuildType = "release"
    defaultConfig {
        applicationId = release["client_id"] as String
        minSdk = 36
        targetSdk = 36
        versionCode = (release["version_code"] as Number).toInt()
        versionName = release["version"] as String
        ndk { abiFilters += "arm64-v8a" }
    }
    buildTypes {
        debug { signingConfig = null }
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = null
        }
    }
    buildFeatures { compose = true; buildConfig = false }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].java.srcDir("$stage/generated")
    sourceSets["main"].assets.srcDir("$stage/assets")
    sourceSets["main"].jniLibs.srcDir("$stage/jniLibs")
    packaging {
        jniLibs { useLegacyPackaging = false; keepDebugSymbols += "**/*.so" }
        resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1")
    }
    testOptions { unitTests.isReturnDefaultValues = false }
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencyLocking { lockAllConfigurations() }
configurations.configureEach {
    // No benchmark/profile receiver or initializer is needed in the manager.
    exclude(group = "androidx.profileinstaller")
}

dependencies {
    compileOnly(files("$assets/tools/client-compat/api-82.jar"))
    implementation(files("$assets/tools/dexkit-research/lib/dexkit-2.2.0.jar"))
    implementation("com.google.flatbuffers:flatbuffers-java:23.5.26")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.4.20")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.compose.material:material-icons-extended:1.7.8")
    implementation("org.jetbrains.compose.foundation:foundation:1.11.1")
    implementation("top.yukonga.miuix.kmp:miuix-ui:0.9.3")
    implementation("com.github.topjohnwu.libsu:core:6.0.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}
