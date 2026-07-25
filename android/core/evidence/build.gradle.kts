plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    api(project(":core:model"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
