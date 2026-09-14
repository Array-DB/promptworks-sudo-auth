plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.promptworks.authenticator"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.promptworks.sudoauth.secure.v37"
        minSdk = 28
        targetSdk = 36
        versionCode = 25
        versionName = "3.9.1"

        val bootstrapUrl = providers.gradleProperty("PW_BOOTSTRAP_URL").orNull ?: ""
        val bootstrapToken = providers.gradleProperty("PW_BOOTSTRAP_TOKEN").orNull ?: ""
        buildConfigField("String", "PW_BOOTSTRAP_URL", "\"${bootstrapUrl.replace("\\", "\\\\").replace("\"", "\\\"")}\"")
        buildConfigField("String", "PW_BOOTSTRAP_TOKEN", "\"${bootstrapToken.replace("\\", "\\\\").replace("\"", "\\\"")}\"")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.08.00"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
