plugins {
    application
    java
}

group = "org.iadb.tech.bid"
version = "1.0-SNAPSHOT"
val vertxVersion by extra("3.9.0")
val mainVerticleName by extra ("org.iadb.tech.MainVerticle")

repositories {
    jcenter()
}

configure<JavaPluginConvention> {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    implementation ("io.vertx:vertx-web-client:$vertxVersion")
    implementation ("io.vertx:vertx-web:$vertxVersion")
    implementation("org.slf4j:slf4j-api:1.7.25")
    implementation("org.apache.santuario:xmlsec:2.1.5")

    runtimeOnly("ch.qos.logback:logback-classic:1.2.3")

    testImplementation("io.vertx:vertx-junit5:$vertxVersion")
    testImplementation("org.junit.jupiter:junit-jupiter:5.6.2")
    testImplementation("org.hamcrest:hamcrest:2.2")
}

tasks.register<JavaExec>("vertxRun") {
    classpath = sourceSets["main"].runtimeClasspath
    main = "io.vertx.core.Launcher"
    args = listOf("run", mainVerticleName)
}

tasks.test {
    useJUnitPlatform()
}

application {
    applicationName = "citi-proxy"
    mainClassName = "io.vertx.core.Launcher"
    applicationDefaultJvmArgs = listOf("-Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory")
    applicationDistribution.exclude("**/*.jks", "**/*.pem", "**/*.crt", "**/*.key", "**/*.p12", "**/*.pfx")
}

tasks.distZip {
    archiveFileName.set("${archiveBaseName.get()}.${archiveExtension.get()}")
}