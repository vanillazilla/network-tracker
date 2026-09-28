plugins {
    kotlin("jvm") version "2.4.20"
    application
}

group = "com.networktracker"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.formdev:flatlaf:3.7.2")
    implementation("net.java.dev.jna:jna:5.19.1")
    implementation("net.java.dev.jna:jna-platform:5.19.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.11.0")
}

kotlin {
    jvmToolchain(25)
}

application {
    mainClass.set("com.networktracker.MainKt")
    applicationDefaultJvmArgs = listOf(
        "--enable-native-access=ALL-UNNAMED",
        "-Dsun.java2d.uiScale.enabled=true",
    )
}

// Single self-contained jar: java -jar build/libs/network-tracker-1.0.0-all.jar
tasks.register<Jar>("fatJar") {
    group = "build"
    description = "Builds a runnable jar with all dependencies."
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes(
            "Main-Class" to "com.networktracker.MainKt",
            "Enable-Native-Access" to "ALL-UNNAMED",
        )
    }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({ configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) } }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/versions/*/module-info.class")
    }
}
