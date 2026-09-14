package com.promptworks.authenticator

import android.Manifest

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.math.BigInteger
import java.io.IOException
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.Image
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Computer
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Flight
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Menu
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.WifiOff
import androidx.compose.material.icons.outlined.WorkspacePremium
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.time.Instant
import kotlin.math.sin

private const val APPROVAL_ALIAS = "promptworks-approval-key-v2"
private const val TRANSPORT_ALIAS = "promptworks-transport-key-v1"
private const val OFFLINE_WRAP_ALIAS = "promptworks-offline-wrap-v1"
private const val OFFLINE_SUITE = "PW-TIME-MATCH-HMAC-SHA256-8:v1"
private const val TIME_WINDOW_SECONDS = 60L
private const val PREFS = "pw"
private val BG = Color(0xFF07111D)
private val CYAN = Color(0xFF19CFFF)
private val CARD = Color(0xFF111D2B)
private val MUTED = Color(0xFFA9C7EA)
private val RED = Color(0xFFFF596A)
private val GREEN = Color(0xFF63D471)

data class AuthRequest(
    val id: String,
    val userId: String,
    val service: String,
    val device: String,
    val location: String,
    val action: String,
    val challenge: String,
    val code: String,
    val expiresAt: String,
)

enum class AppPage { AUTH, HISTORY, SETTINGS, ABOUT }

class MainActivity : FragmentActivity() {
    private lateinit var prefs: android.content.SharedPreferences
    // Use only the installer-generated CA bundled into this APK. We deliberately do
    // not inherit arbitrary user-installed CAs for the PromptWorks backend.
    private val http: OkHttpClient by lazy {
        val cf = CertificateFactory.getInstance("X.509")
        val ca = resources.openRawResource(R.raw.promptworks_server_ca).use { cf.generateCertificate(it) }
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("promptworks-local-root", ca)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        val trust = tmf.trustManagers.filterIsInstance<X509TrustManager>().single()
        val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        OkHttpClient.Builder()
            .sslSocketFactory(ssl.socketFactory, trust)
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(12, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()
    }

    private fun importBootstrap(sourceIntent: Intent?): Boolean {
        val bootstrapUrl = sourceIntent?.getStringExtra("pw_url").orEmpty()
        val bootstrapToken = sourceIntent?.getStringExtra("pw_token").orEmpty()
        val activationState = sourceIntent?.getStringExtra("pw_activation_state").orEmpty().lowercase()
        val received = bootstrapUrl.isNotBlank() && bootstrapToken.isNotBlank()
        if (bootstrapUrl.isNotBlank() || bootstrapToken.isNotBlank()) {
            // commit() is intentional here: the provisioning UI is created immediately after
            // this function returns, so the bootstrap material must already be durable/visible.
            prefs.edit()
                .putString("bootstrapUrl", bootstrapUrl)
                .putString("bootstrapToken", bootstrapToken)
                .putString("activationState", if (activationState.isBlank()) "candidate" else activationState)
                .commit()
        } else if (activationState == "candidate" || activationState == "active") {
            prefs.edit().putString("activationState", activationState).commit()
        }
        // Never log the URL/token themselves. The installer only needs an acknowledgement that
        // both values reached the APK over the already-authorized ADB channel.
        Log.i("PromptWorksBootstrap", "received_url=${bootstrapUrl.isNotBlank()} received_token=${bootstrapToken.isNotBlank()}")
        return received
    }


    private fun importRequestFocus(sourceIntent: Intent?) {
        val requestId = sourceIntent?.getStringExtra("pw_request_id").orEmpty()
        if (requestId.startsWith("req_") && requestId.length <= 100) {
            prefs.edit().putString("focusRequestId", requestId).apply()
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        // Bootstrap values are delivered over the already-authorized ADB session at install time,
        // not compiled into the APK where a one-time enrollment token could be extracted later.
        importBootstrap(intent)
        importRequestFocus(intent)
        setContent { PromptWorksApp() }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val bootstrapChanged = importBootstrap(intent)
        importRequestFocus(intent)
        if (bootstrapChanged || intent.getStringExtra("pw_activation_state").orEmpty().isNotBlank()) {
            // Refresh Compose state even if Android reused the existing launcher Activity.
            recreate()
        }
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun ensureKeys() {
        val ks = keyStore()
        if (!ks.containsAlias(APPROVAL_ALIAS)) {
            fun generateApprovalKey(strongBox: Boolean) {
                val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                val builder = KeyGenParameterSpec.Builder(APPROVAL_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setInvalidatedByBiometricEnrollment(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    @Suppress("DEPRECATION")
                    builder.setUserAuthenticationValidityDurationSeconds(-1)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) builder.setIsStrongBoxBacked(true)
                generator.initialize(builder.build())
                generator.generateKeyPair()
            }
            try {
                generateApprovalKey(true)
            } catch (_: StrongBoxUnavailableException) {
                generateApprovalKey(false)
            } catch (_: Exception) {
                if (!ks.containsAlias(APPROVAL_ALIAS)) generateApprovalKey(false)
            }
        }
        if (!ks.containsAlias(TRANSPORT_ALIAS)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            generator.initialize(
                KeyGenParameterSpec.Builder(TRANSPORT_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            generator.generateKeyPair()
        }
    }

    private fun publicKeyPem(alias: String): String {
        ensureKeys()
        val body = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(keyStore().getCertificate(alias).publicKey.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
    }

    private fun publicKeyFingerprint(alias: String): String {
        ensureKeys()
        val bytes = keyStore().getCertificate(alias).publicKey.encoded
        return MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun approvalSignature(): Signature {
        ensureKeys()
        return Signature.getInstance("SHA256withECDSA").apply {
            initSign(keyStore().getKey(APPROVAL_ALIAS, null) as PrivateKey)
        }
    }

    private fun transportSign(payload: String): String {
        ensureKeys()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(keyStore().getKey(TRANSPORT_ALIAS, null) as PrivateKey)
        signature.update(payload.toByteArray())
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    private fun ensureOfflineWrapKey() {
        val ks = keyStore()
        if (ks.containsAlias(OFFLINE_WRAP_ALIAS)) return
        fun build(strongBox: Boolean) {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(
                OFFLINE_WRAP_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) builder.setIsStrongBoxBacked(true)
            generator.init(builder.build())
            generator.generateKey()
        }
        try {
            build(true)
        } catch (_: StrongBoxUnavailableException) {
            build(false)
        } catch (_: Exception) {
            if (!ks.containsAlias(OFFLINE_WRAP_ALIAS)) build(false)
        }
    }

    private fun wrapCipher(): Cipher {
        ensureOfflineWrapKey()
        val key = keyStore().getKey(OFFLINE_WRAP_ALIAS, null)
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    private fun unwrapCipher(): Cipher {
        val iv = Base64.getDecoder().decode(prefs.getString("offlineIv", "").orEmpty())
        require(iv.isNotEmpty()) { "Offline authenticator is not provisioned" }
        ensureOfflineWrapKey()
        val key = keyStore().getKey(OFFLINE_WRAP_ALIAS, null)
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
    }

    private fun protectOfflineSecretWithBiometric(secretHex: String, hostId: String, pairingId: String, hostKeyFingerprint: String, approvalKeyFingerprint: String, done: (String?) -> Unit) {
        require(secretHex.matches(Regex("^[0-9a-fA-F]{64}$"))) { "Provisioning server returned an invalid offline key" }
        val cipher = wrapCipher()
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val c = result.cryptoObject?.cipher ?: error("Biometric crypto object missing")
                        val ciphertext = c.doFinal(secretHex.uppercase().toByteArray(Charsets.US_ASCII))
                        prefs.edit()
                            .putString("offlineCiphertext", Base64.getEncoder().encodeToString(ciphertext))
                            .putString("offlineIv", Base64.getEncoder().encodeToString(c.iv))
                            .putString("offlineHostId", hostId)
                            .putString("pairingId", pairingId)
                            .putString("hostKeyFingerprint", hostKeyFingerprint)
                            .putString("approvalKeyFingerprint", approvalKeyFingerprint)
                            .putString("offlineSuite", OFFLINE_SUITE)
                            .apply()
                        done(null)
                    } catch (e: Exception) {
                        done(e.message ?: "Could not protect offline key")
                    }
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { done(errString.toString()) }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Protect PromptWorks offline key")
            .setSubtitle("Strong biometric is required to finish first-time provisioning")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    private fun timeMatchResponse(secretHex: String, number: String, epoch: Long, decision: String): String {
        require(number.matches(Regex("^[0-9]{3}$"))) { "Enter the 3-digit number exactly as shown by sudo" }
        require(decision == "approve" || decision == "deny")
        require(secretHex.matches(Regex("^[0-9A-Fa-f]{64}$"))) { "Bound runtime key is invalid" }
        val key = ByteArray(32) { i -> secretHex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        val host = prefs.getString("offlineHostId", "").orEmpty()
        require(host.isNotBlank()) { "Host binding is unavailable" }
        val payload = listOf("PromptWorks-TimeMatch-v1", host, epoch.toString(), number, decision)
            .joinToString("\n").toByteArray(Charsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val digest = mac.doFinal(payload)
        val offset = digest.last().toInt() and 0x0f
        val binary = ((digest[offset].toInt() and 0x7f) shl 24) or
            ((digest[offset + 1].toInt() and 0xff) shl 16) or
            ((digest[offset + 2].toInt() and 0xff) shl 8) or
            (digest[offset + 3].toInt() and 0xff)
        key.fill(0); payload.fill(0); digest.fill(0)
        return "%08d".format(binary % 100_000_000)
    }

    private fun offlineReadyProof(secretHex: String, pairingId: String, hostId: String, deviceId: String, userId: String, approvalKeyFingerprint: String, hostKeyFingerprint: String): String {
        val key = ByteArray(32) { i -> secretHex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val payload = listOf("promptworks-offline-ready-v2", pairingId, hostId, deviceId, userId, approvalKeyFingerprint, hostKeyFingerprint)
            .joinToString("\n").toByteArray(Charsets.UTF_8)
        val out = mac.doFinal(payload)
        key.fill(0)
        return out.joinToString("") { "%02x".format(it.toInt() and 0xff) }.also { out.fill(0) }
    }

    private fun biometricOfflineResponse(number: String, decision: String, done: (String, String, Long) -> Unit) {
        try {
            val cipher = unwrapCipher()
            val prompt = BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try {
                            val c = result.cryptoObject?.cipher ?: error("Biometric crypto object missing")
                            val wrapped = Base64.getDecoder().decode(prefs.getString("offlineCiphertext", "").orEmpty())
                            val secretBytes = c.doFinal(wrapped)
                            val secret = String(secretBytes, Charsets.US_ASCII)
                            val epoch = (System.currentTimeMillis() / 1000L) / TIME_WINDOW_SECONDS
                            val response = timeMatchResponse(secret, number, epoch, decision)
                            secretBytes.fill(0)
                            done(response, "", epoch)
                        } catch (e: Exception) {
                            done("", e.message ?: "Time-match response failed", -1L)
                        }
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { done("", errString.toString(), -1L) }
                },
            )
            val host = prefs.getString("offlineHostId", "Linux host").orEmpty()
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(if (decision == "approve") "Approve sudo request" else "Deny sudo request")
                .setSubtitle("Time-bound number match for $host")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Cancel")
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            done("", e.message ?: "Offline authenticator unavailable", -1L)
        }
    }

    private fun validServerUrl(value: String): Boolean {
        val base = value.trim().trimEnd('/')
        return base.startsWith("https://") || base.startsWith("http://127.0.0.1") || base.startsWith("http://localhost")
    }

    private suspend fun call(
        method: String,
        path: String,
        body: JSONObject? = null,
        headers: Map<String, String> = emptyMap(),
        baseOverride: String? = null,
    ): String = withContext(Dispatchers.IO) {
        val base = (baseOverride ?: prefs.getString("url", "").orEmpty()).trim().trimEnd('/')
        require(validServerUrl(base)) { "Remote server must use HTTPS" }
        val requestBody = if (method == "GET") null else (body ?: JSONObject()).toString()
            .toRequestBody("application/json".toMediaType())
        val builder = Request.Builder().url(base + path).method(method, requestBody)
        headers.forEach { (key, value) -> builder.header(key, value) }
        http.newCall(builder.build()).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) error("Server ${response.code}: $text")
            text
        }
    }

    private suspend fun fetchRequests(): List<AuthRequest> {
        val id = prefs.getString("deviceId", "").orEmpty()
        require(id.isNotBlank()) { "Phone is not enrolled" }
        val nonce = JSONObject(call("POST", "/v1/devices/$id/nonce")).getString("nonce")
        val payload = listOf("promptworks-device-auth-v1", id, nonce).joinToString("\n")
        val signature = transportSign(payload)
        val array = JSONArray(
            call(
                "GET",
                "/v1/devices/$id/requests",
                headers = mapOf("X-PW-Nonce" to nonce, "X-PW-Signature" to signature),
            )
        )
        return (0 until array.length()).map { index ->
            array.getJSONObject(index).let {
                AuthRequest(
                    id = it.getString("id"),
                    userId = it.getString("user_id"),
                    service = it.getString("service"),
                    device = it.getString("device"),
                    location = it.getString("location"),
                    action = it.optString("action", ""),
                    challenge = it.getString("challenge"),
                    code = it.getString("verification_code"),
                    expiresAt = it.getString("expires_at"),
                )
            }
        }
    }

    private fun decisionPayload(request: AuthRequest, decision: String, deviceId: String) = listOf(
        "promptworks-auth-v2",
        request.id,
        request.challenge,
        request.code,
        request.userId,
        request.service,
        request.device,
        request.location,
        request.action,
        request.expiresAt,
        decision,
        deviceId,
    ).joinToString("\n")

    private fun biometricDecision(request: AuthRequest, decision: String, done: (Boolean, String) -> Unit) {
        val cryptoSignature = approvalSignature()
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val signature = result.cryptoObject?.signature ?: error("Biometric crypto object missing")
                        val id = prefs.getString("deviceId", "").orEmpty()
                        signature.update(decisionPayload(request, decision, id).toByteArray())
                        val encoded = Base64.getEncoder().encodeToString(signature.sign())
                        kotlinx.coroutines.CoroutineScope(Dispatchers.Main).launch {
                            val body = JSONObject()
                                .put("deviceId", id)
                                .put("decision", decision)
                                .put("signature", encoded)
                            var lastError = "Decision delivery failed"
                            repeat(3) { attempt ->
                                try {
                                    val responseText = call("POST", "/v1/auth/requests/${request.id}/decision", body)
                                    val response = JSONObject(responseText)
                                    val expectedStatus = if (decision == "approve") "approved" else "denied"
                                    require(response.optString("id") == request.id) { "Decision acknowledgement request mismatch" }
                                    require(response.optString("status") == expectedStatus) { "Decision acknowledgement status mismatch" }
                                    val receipt = response.optString("receiptCode")
                                    require(receipt.matches(Regex("^[0-9]{8}$"))) { "Decision acknowledgement receipt invalid" }
                                    done(true, if (decision == "approve") "Approved · receipt ****${receipt.takeLast(4)}" else "Denied · receipt ****${receipt.takeLast(4)}")
                                    return@launch
                                } catch (e: Exception) {
                                    lastError = e.message ?: e.javaClass.simpleName
                                    // A lost HTTP response after a successful commit is safe to retry: the
                                    // backend decision endpoint is idempotent for the same signed decision.
                                    if (attempt < 2 && (e is IOException || lastError.contains("timeout", true) || lastError.contains("connection", true))) {
                                        delay(450L * (attempt + 1))
                                    } else if (attempt < 2) {
                                        delay(250L)
                                    }
                                }
                            }
                            done(false, "Secure response not confirmed: $lastError")
                        }
                    } catch (e: Exception) {
                        done(false, e.message ?: "Decision failed")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    done(false, errString.toString())
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(if (decision == "approve") "Approve sudo request" else "Confirm denial")
            .setSubtitle("Code ${request.code} · ${request.service}")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cryptoSignature))
    }

    @Composable
    private fun PromptWorksApp() {
        var page by remember { mutableStateOf(AppPage.AUTH) }
        var drawerOpen by remember { mutableStateOf(false) }
        var enrollmentVersion by remember { mutableIntStateOf(0) }

        MaterialTheme(
            colorScheme = darkColorScheme(
                primary = CYAN,
                background = BG,
                surface = CARD,
                onBackground = Color.White,
                onSurface = Color.White,
            ),
            typography = Typography(),
        ) {
            Surface(Modifier.fillMaxSize(), color = BG) {
                BoxWithConstraints(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
                    // Reference composition: the drawer overlays from the left while the
                    // current page shifts right and remains clipped by the phone viewport.
                    // Do not resize/squash the page — that was one of the visual mismatches
                    // in the previous pass.
                    val targetDrawerWidth = maxWidth * 0.60f
                    val contentOffset by animateDpAsState(
                        targetValue = if (drawerOpen) targetDrawerWidth * 0.94f else 0.dp,
                        label = "contentOffset",
                    )
                    val drawerOffset by animateDpAsState(
                        targetValue = if (drawerOpen) 0.dp else -targetDrawerWidth,
                        label = "drawerOffset",
                    )

                    Box(
                        Modifier
                            .fillMaxSize()
                            .offset(x = contentOffset)
                    ) {
                        when (page) {
                            AppPage.AUTH -> AuthPage(
                                enrollmentVersion = enrollmentVersion,
                                onOpenDrawer = { drawerOpen = !drawerOpen },
                                onNavigate = { page = it },
                            )
                            AppPage.HISTORY -> HistoryPage(
                                onOpenDrawer = { drawerOpen = !drawerOpen },
                                onNavigate = { page = it },
                            )
                            AppPage.SETTINGS -> SettingsPage(
                                onOpenDrawer = { drawerOpen = !drawerOpen },
                                onEnrollmentChanged = { enrollmentVersion++ },
                            )
                            AppPage.ABOUT -> AboutPage(onOpenDrawer = { drawerOpen = !drawerOpen })
                        }

                        if (drawerOpen) {
                            // A very light scrim keeps the visible right-hand pane muted,
                            // matching the supplied drawer reference without hiding it.
                            Box(
                                Modifier
                                    .fillMaxSize()
                                    .background(Color.Black.copy(alpha = 0.18f))
                                    .clickable { drawerOpen = false }
                            )
                        }
                    }

                    Box(
                        Modifier
                            .width(targetDrawerWidth)
                            .fillMaxHeight()
                            .offset(x = drawerOffset)
                            .background(Color(0xFF091521))
                    ) {
                        SettingsDrawer(
                            page = page,
                            onNavigate = { page = it; drawerOpen = false },
                            onClose = { drawerOpen = false },
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun SettingsDrawer(page: AppPage, onNavigate: (AppPage) -> Unit, onClose: () -> Unit) {
        BoxWithConstraints(
            Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        listOf(Color(0xFF091723), Color(0xFF0B1A27), Color(0xFF08131D))
                    )
                )
        ) {
            val short = maxHeight < 700.dp
            val markSize = if (short) 82.dp else 96.dp
            val rowHeight = if (short) 48.dp else 54.dp

            Column(
                Modifier
                    .fillMaxSize()
                    .padding(start = 16.dp, end = 14.dp, top = if (short) 18.dp else 30.dp, bottom = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                PromptWorksMark(markSize)
                Spacer(Modifier.height(if (short) 6.dp else 9.dp))
                PromptWorksWordmark(fontSize = if (short) 21.sp else 24.sp, secureBelow = true)
                Spacer(Modifier.height(if (short) 18.dp else 27.dp))

                DrawerItem(Icons.Outlined.Devices, "Devices", page == AppPage.AUTH, rowHeight) { onNavigate(AppPage.AUTH) }
                DrawerItem(Icons.Outlined.Shield, "Security", page == AppPage.SETTINGS, rowHeight) { onNavigate(AppPage.SETTINGS) }
                DrawerItem(Icons.Outlined.Flight, "Offline Mode", false, rowHeight) { onNavigate(AppPage.SETTINGS) }
                DrawerItem(Icons.Outlined.WorkspacePremium, "Upgrade Gate", false, rowHeight) { onNavigate(AppPage.ABOUT) }
                DrawerItem(Icons.Outlined.History, "History", page == AppPage.HISTORY, rowHeight) { onNavigate(AppPage.HISTORY) }
                DrawerItem(Icons.Outlined.Info, "About", page == AppPage.ABOUT, rowHeight) { onNavigate(AppPage.ABOUT) }

                Spacer(Modifier.weight(1f))
                HorizontalDivider(color = Color(0xFF26394B))
                Spacer(Modifier.height(16.dp))
                Row(
                    Modifier
                        .fillMaxWidth()
                        .height(if (short) 72.dp else 82.dp)
                        .clip(RoundedCornerShape(17.dp))
                        .background(Color(0xFF10202E))
                        .border(1.dp, Color(0xFF21374A), RoundedCornerShape(17.dp))
                        .clickable { onClose() }
                        .padding(horizontal = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Secure by design.", color = Color(0xFF8FA6BF), fontSize = 13.sp)
                        Spacer(Modifier.height(3.dp))
                        Text("In control by you.", color = Color(0xFF8FA6BF), fontSize = 13.sp)
                    }
                    Icon(
                        Icons.Outlined.KeyboardArrowRight,
                        null,
                        tint = Color(0xFF8EA5BD),
                        modifier = Modifier.size(24.dp),
                    )
                }
            }
        }
    }

    @Composable
    private fun DrawerItem(
        icon: ImageVector,
        label: String,
        selected: Boolean,
        height: androidx.compose.ui.unit.Dp,
        onClick: () -> Unit,
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .height(height)
                .clip(RoundedCornerShape(13.dp))
                .background(if (selected) Color(0xFF173048) else Color.Transparent)
                .clickable { onClick() },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .width(5.dp)
                    .fillMaxHeight()
                    .background(if (selected) CYAN else Color.Transparent)
            )
            Spacer(Modifier.width(15.dp))
            Icon(
                icon,
                null,
                tint = if (selected) Color(0xFF19D8FF) else Color(0xFFE5EFF9),
                modifier = Modifier.size(25.dp),
            )
            Spacer(Modifier.width(18.dp))
            Text(
                label,
                color = if (selected) Color.White else Color(0xFFD7E2EE),
                fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold,
                fontSize = 16.sp,
                maxLines = 1,
            )
            Spacer(Modifier.weight(1f))
            Icon(
                Icons.Outlined.KeyboardArrowRight,
                null,
                tint = Color(0xFF8195AC),
                modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(8.dp))
        }
        Spacer(Modifier.height(5.dp))
    }

    @Composable
    private fun TopBar(title: String, onOpenDrawer: () -> Unit) {
        Row(
            Modifier.fillMaxWidth().height(58.dp).padding(horizontal = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onOpenDrawer) { Icon(Icons.Outlined.Menu, "Menu", tint = Color.White) }
            Spacer(Modifier.width(4.dp))
            Text(title, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = Color.White)
        }
    }

    @Composable
    private fun AuthPage(enrollmentVersion: Int, onOpenDrawer: () -> Unit, onNavigate: (AppPage) -> Unit) {
        var provisioned by remember(enrollmentVersion) { mutableStateOf(prefs.getBoolean("offlineReady", false)) }
        if (!provisioned) {
            Column(Modifier.fillMaxSize().background(BG)) {
                TopBar("PromptWorks Secure", onOpenDrawer)
                SetupPanel(onEnrolled = { provisioned = true })
            }
            return
        }

        var challenge by remember { mutableStateOf("") }
        var response by remember { mutableStateOf("") }
        var responseDecision by remember { mutableStateOf("") }
        var responseEpoch by remember { mutableLongStateOf(-1L) }
        var status by remember { mutableStateOf("") }
        var busy by remember { mutableStateOf(false) }
        var nowSeconds by remember { mutableLongStateOf(System.currentTimeMillis() / 1000L) }

        LaunchedEffect(Unit) {
            while (true) {
                nowSeconds = System.currentTimeMillis() / 1000L
                delay(1000)
            }
        }
        val secondsRemaining = (TIME_WINDOW_SECONDS - (nowSeconds % TIME_WINDOW_SECONDS)).toInt()

        BoxWithConstraints(
            Modifier.fillMaxSize().background(
                Brush.verticalGradient(listOf(Color(0xFF07131E), Color(0xFF06111B), Color(0xFF07131D)))
            )
        ) {
            val short = maxHeight < 735.dp
            Column(
                Modifier.fillMaxSize().padding(horizontal = 15.dp, vertical = if (short) 4.dp else 8.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Row(
                    Modifier.fillMaxWidth().height(if (short) 30.dp else 34.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClick = onOpenDrawer, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Outlined.Settings, "Settings", tint = Color(0xFFBFD1E6), modifier = Modifier.size(25.dp))
                    }
                }

                PromptWorksMark(if (short) 68.dp else 82.dp)
                Spacer(Modifier.height(2.dp))
                PromptWorksWordmark(fontSize = if (short) 23.sp else 26.sp, secureBelow = true)
                Spacer(Modifier.height(if (short) 6.dp else 9.dp))
                PairedPill()
                Spacer(Modifier.height(if (short) 8.dp else 12.dp))

                Card(
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    shape = RoundedCornerShape(20.dp),
                    border = BorderStroke(1.dp, Color(0xFF2C475D)),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0A1722)),
                ) {
                    Column(
                        Modifier.fillMaxSize().padding(horizontal = if (short) 16.dp else 20.dp, vertical = if (short) 12.dp else 16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Outlined.WifiOff, null, tint = Color(0xFF00E6B8), modifier = Modifier.size(22.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("OFFLINE SUDO APPROVAL", color = Color(0xFF00E6B8), fontSize = 12.sp, fontWeight = FontWeight.Black)
                        }
                        Spacer(Modifier.height(if (short) 5.dp else 8.dp))
                        Text(
                            "Enter the 3 digits shown by sudo",
                            color = Color(0xFFF5F8FC),
                            fontSize = if (short) 23.sp else 28.sp,
                            fontWeight = FontWeight.ExtraBold,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(if (short) 8.dp else 12.dp))

                        OutlinedTextField(
                            value = challenge,
                            onValueChange = {
                                challenge = it.filter(Char::isDigit).take(3)
                                response = ""; responseDecision = ""; responseEpoch = -1L; status = ""
                            },
                            label = { Text("3-digit NUMBER MATCH") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )

                        Spacer(Modifier.height(if (short) 8.dp else 12.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("◷", color = CYAN, fontSize = 21.sp)
                            Spacer(Modifier.width(7.dp))
                            Text("Current offline window: ", color = Color(0xFFA6B8CE), fontSize = 13.sp)
                            Text("${secondsRemaining}s", color = if (secondsRemaining <= 10) RED else CYAN, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        }

                        Spacer(Modifier.height(if (short) 8.dp else 12.dp))
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            DecisionButton(
                                text = "DENY",
                                enabled = challenge.length == 3 && !busy && secondsRemaining >= 8,
                                icon = Icons.Outlined.Close,
                                accent = RED,
                                fill = Color(0x331A0710),
                                height = if (short) 51.dp else 58.dp,
                                modifier = Modifier.weight(1f),
                            ) {
                                busy = true; status = "Unlock to generate an offline DENY code…"
                                biometricOfflineResponse(challenge, "deny") { value, error, epoch ->
                                    busy = false; response = value; responseDecision = if (value.isNotBlank()) "DENIED" else ""; responseEpoch = epoch; status = error
                                }
                            }
                            DecisionButton(
                                text = "APPROVE",
                                enabled = challenge.length == 3 && !busy && secondsRemaining >= 8,
                                icon = Icons.Outlined.Check,
                                accent = CYAN,
                                fill = Color(0x2200BFEF),
                                height = if (short) 51.dp else 58.dp,
                                modifier = Modifier.weight(1f),
                            ) {
                                busy = true; status = "Unlock to generate an offline APPROVE code…"
                                biometricOfflineResponse(challenge, "approve") { value, error, epoch ->
                                    busy = false; response = value; responseDecision = if (value.isNotBlank()) "APPROVED" else ""; responseEpoch = epoch; status = error
                                }
                            }
                        }

                        Spacer(Modifier.height(if (short) 8.dp else 12.dp))
                        if (response.isNotBlank()) {
                            Text(responseDecision, color = if (responseDecision == "APPROVED") Color(0xFF00E6B8) else RED, fontSize = 12.sp, fontWeight = FontWeight.Black)
                            Text(response, color = CYAN, fontSize = if (short) 40.sp else 48.sp, fontWeight = FontWeight.Black, letterSpacing = 2.sp)
                            Text(
                                "Type this 8-digit code into the waiting sudo prompt. Nothing is sent over the network.",
                                color = Color(0xFFA2B6D0),
                                fontSize = 12.sp,
                                textAlign = TextAlign.Center,
                                maxLines = 2,
                            )
                            Text("Epoch $responseEpoch · ${shortHost()}", color = Color(0xFF6F879F), fontSize = 10.sp)
                        } else {
                            Spacer(Modifier.weight(1f))
                            ShieldEmblem(if (short) 70.dp else 88.dp)
                            Spacer(Modifier.height(5.dp))
                            Text(
                                "Biometric unlock happens on-device. The bound secret never leaves the APK or Linux host.",
                                color = Color(0xFF91AAC6),
                                fontSize = 12.sp,
                                textAlign = TextAlign.Center,
                                maxLines = 2,
                            )
                        }

                        if (status.isNotBlank()) {
                            Spacer(Modifier.height(5.dp))
                            Text(status, color = if (status.contains("fail", true) || status.contains("error", true)) RED else MUTED, fontSize = 11.sp, textAlign = TextAlign.Center, maxLines = 2)
                        }
                    }
                }
                Spacer(Modifier.height(if (short) 6.dp else 9.dp))
                BottomNavigationBar(AppPage.AUTH, onNavigate, if (short) 62.dp else 68.dp)
            }
        }
    }

    @Composable
    private fun SetupPanel(onEnrolled: () -> Unit) {
        var url by remember { mutableStateOf(prefs.getString("bootstrapUrl", prefs.getString("url", BuildConfig.PW_BOOTSTRAP_URL)).orEmpty()) }
        var code by remember { mutableStateOf(prefs.getString("bootstrapToken", BuildConfig.PW_BOOTSTRAP_TOKEN).orEmpty()) }
        var deviceName by remember { mutableStateOf(prefs.getString("deviceName", defaultDeviceName()).orEmpty()) }
        var status by remember { mutableStateOf("") }
        var busy by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()

        Column(
            Modifier.fillMaxSize().padding(horizontal = 28.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            PromptWorksMark(112.dp)
            Spacer(Modifier.height(8.dp))
            PromptWorksWordmark(fontSize = 25.sp, secureBelow = false)
            Spacer(Modifier.height(18.dp))
            Surface(
                color = Color(0xFF132536),
                shape = RoundedCornerShape(999.dp),
                border = BorderStroke(1.dp, Color(0xFF2B465B)),
            ) {
                Text("CANDIDATE · sudo remains protected by the previous PromptWorks", modifier = Modifier.padding(horizontal = 14.dp, vertical = 7.dp), color = Color(0xFFFFC266), fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(18.dp))
            Text("Secure provisioning", fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text("The installer has securely delivered this candidate's one-time connection details.", color = MUTED, lineHeight = 19.sp, textAlign = TextAlign.Center)
            Spacer(Modifier.height(18.dp))
            OutlinedTextField(url, { url = it }, label = { Text("Provisioning server URL") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(deviceName, { deviceName = it }, label = { Text("Device name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(code, { code = it }, label = { Text("One-time enrollment token") }, visualTransformation = PasswordVisualTransformation(), singleLine = true, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(16.dp))
            Button(
                enabled = !busy && url.isNotBlank() && code.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    scope.launch {
                        busy = true
                        status = ""
                        try {
                            require(BiometricManager.from(this@MainActivity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS) {
                                "A strong biometric must be enrolled before PromptWorks provisioning"
                            }
                            require(validServerUrl(url)) { "Use HTTPS for the provisioning server" }
                            ensureKeys()
                            val cleanUrl = url.trim().trimEnd('/')
                            val result = JSONObject(
                                call(
                                    "POST",
                                    "/v1/devices/enroll",
                                    JSONObject()
                                        .put("token", code.trim())
                                        .put("deviceName", deviceName.trim().ifBlank { defaultDeviceName() })
                                        .put("approvalPublicKeyPem", publicKeyPem(APPROVAL_ALIAS))
                                        .put("transportPublicKeyPem", publicKeyPem(TRANSPORT_ALIAS)),
                                    baseOverride = cleanUrl,
                                )
                            )
                            val secret = result.getString("offlineSecretHex")
                            val hostId = result.getString("offlineHostId")
                            val pairingId = result.getString("pairingId")
                            val hostKeyFingerprint = result.getString("hostKeyFingerprint").lowercase()
                            val approvalKeyFingerprint = result.getString("approvalKeyFingerprint").lowercase()
                            require(approvalKeyFingerprint == publicKeyFingerprint(APPROVAL_ALIAS)) { "Provisioning server returned a phone-key binding that does not match this APK installation" }
                            val previousPairing = prefs.getString("pairingId", "").orEmpty()
                            require(previousPairing.isBlank() || previousPairing == pairingId) { "This APK installation is already bound to a different Linux host. Reset pairing explicitly before replacement." }
                            prefs.edit()
                                .putString("url", cleanUrl)
                                .putString("deviceName", deviceName.trim().ifBlank { defaultDeviceName() })
                                .putString("deviceId", result.getString("deviceId"))
                                .putString("pairedUserId", result.getString("userId"))
                                .putBoolean("offlineReady", false)
                                .apply()
                            withContext(Dispatchers.Main) {
                                protectOfflineSecretWithBiometric(secret, hostId, pairingId, hostKeyFingerprint, approvalKeyFingerprint) { error ->
                                    if (error != null) {
                                        prefs.edit().remove("deviceId").remove("offlineReady").apply()
                                        status = error
                                        busy = false
                                    } else {
                                        scope.launch {
                                            try {
                                                val deviceId = result.getString("deviceId")
                                                val userId = result.getString("userId")
                                                val proof = offlineReadyProof(secret, pairingId, hostId, deviceId, userId, approvalKeyFingerprint, hostKeyFingerprint)
                                                call(
                                                    "POST",
                                                    "/v1/devices/$deviceId/offline-ready",
                                                    JSONObject()
                                                        .put("proof", proof)
                                                        .put("pairingId", pairingId)
                                                        .put("hostKeyFingerprint", hostKeyFingerprint),
                                                    baseOverride = cleanUrl,
                                                )
                                                prefs.edit()
                                                    .putBoolean("offlineReady", true)
                                                    .remove("bootstrapToken")
                                                    .remove("bootstrapUrl")
                                                    .apply()
                                                status = "Candidate ready — sudo is still protected by the previous PromptWorks"
                                                onEnrolled()
                                            } catch (e: Exception) {
                                                prefs.edit().putBoolean("offlineReady", false).apply()
                                                status = e.message ?: "Offline-ready verification failed; rerun provisioning"
                                            } finally {
                                                busy = false
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            status = when {
                                e.message?.contains("CertPathValidatorException", ignoreCase = true) == true ||
                                e.message?.contains("trust anchor", ignoreCase = true) == true ->
                                    "Secure connection rejected: this APK and the candidate backend do not share the same provisioning CA. Sudo is unchanged; restart the installer to rebuild the candidate."
                                else -> e.message ?: "Provisioning failed"
                            }
                            busy = false
                        }
                    }
                },
            ) { Text(if (busy) "Verifying secure binding…" else "Verify & enroll candidate", fontWeight = FontWeight.Bold) }
            if (status.isNotBlank()) {
                Spacer(Modifier.height(12.dp))
                Text(status, color = if (status.startsWith("Candidate ready")) GREEN else RED)
            }
            Spacer(Modifier.height(24.dp))
            Text("The runtime time-match key is uniquely derived from this Linux host identity and this APK installation's hardware-backed approval public key. The host rejects a second APK until pairing is explicitly reset.", color = MUTED, fontSize = 12.sp, lineHeight = 18.sp)
        }
    }

    @Composable
    private fun SettingsPage(onOpenDrawer: () -> Unit, onEnrollmentChanged: () -> Unit) {
        val provisioned = prefs.getBoolean("offlineReady", false) && prefs.getString("offlineCiphertext", "").orEmpty().isNotBlank()
        var resetStatus by remember { mutableStateOf("") }
        Column(Modifier.fillMaxSize().background(BG)) {
            TopBar("Security", onOpenDrawer)
            Column(
                Modifier.fillMaxSize().padding(horizontal = 18.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SecuritySummaryCard(Icons.Outlined.Link, "1:1 Binding", if (provisioned) "Device locked" else "Not provisioned", CYAN)
                SecuritySummaryCard(Icons.Outlined.Fingerprint, "Strong Biometric", "On-device auth", Color(0xFF00E6B8))
                SecuritySummaryCard(Icons.Outlined.WifiOff, "Offline Runtime", "No cloud needed", Color(0xFF91A8C1))
                Card(
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0C1926)),
                    border = BorderStroke(1.dp, Color(0xFF20394E)),
                    shape = RoundedCornerShape(18.dp),
                ) {
                    Column(Modifier.fillMaxSize().padding(18.dp), verticalArrangement = Arrangement.SpaceBetween) {
                        Column {
                            Text("Protected binding", color = Color.White, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                            Spacer(Modifier.height(10.dp))
                            Info("Host", prefs.getString("offlineHostId", "").orEmpty())
                            Info("Runtime", if (provisioned) (if (prefs.getString("activationState", "candidate") == "active") "ACTIVE — protecting sudo" else "CANDIDATE — not active in PAM") else "Provisioning required")
                            Text("A failed upgrade restores the previous PromptWorks PAM/backend binding; it does not intentionally fall back to original password-only mode.", color = MUTED, fontSize = 12.sp, lineHeight = 17.sp)
                        }
                        OutlinedButton(
                            modifier = Modifier.fillMaxWidth().height(50.dp),
                            border = BorderStroke(1.dp, Color(0xFF39546B)),
                            onClick = {
                                val prompt = BiometricPrompt(
                                    this@MainActivity,
                                    ContextCompat.getMainExecutor(this@MainActivity),
                                    object : BiometricPrompt.AuthenticationCallback() {
                                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                            prefs.edit().clear().apply()
                                            try { keyStore().deleteEntry(OFFLINE_WRAP_ALIAS) } catch (_: Exception) {}
                                            try { keyStore().deleteEntry(APPROVAL_ALIAS) } catch (_: Exception) {}
                                            try { keyStore().deleteEntry(TRANSPORT_ALIAS) } catch (_: Exception) {}
                                            resetStatus = "Phone-side pairing reset"
                                            onEnrollmentChanged()
                                        }
                                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { resetStatus = errString.toString() }
                                    },
                                )
                                val info = BiometricPrompt.PromptInfo.Builder()
                                    .setTitle("Reset PromptWorks pairing")
                                    .setSubtitle("This destroys this APK installation's pairing keys")
                                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                                    .setNegativeButtonText("Cancel")
                                    .build()
                                prompt.authenticate(info)
                            },
                        ) { Text("Securely reset phone pairing", color = Color(0xFFD7E5F5)) }
                    }
                }
                if (resetStatus.isNotBlank()) Text(resetStatus, color = MUTED, fontSize = 12.sp, maxLines = 1)
            }
        }
    }



    @Composable
    private fun AboutPage(onOpenDrawer: () -> Unit) {
        Column(Modifier.fillMaxSize().background(BG)) {
            TopBar("About", onOpenDrawer)
            Column(
                Modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 14.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                PromptWorksMark(124.dp)
                Spacer(Modifier.height(10.dp))
                PromptWorksWordmark(fontSize = 27.sp, secureBelow = true)
                Spacer(Modifier.height(24.dp))
                Card(
                    Modifier.fillMaxWidth().weight(1f),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0C1926)),
                    border = BorderStroke(1.dp, Color(0xFF20394E)),
                    shape = RoundedCornerShape(18.dp),
                ) {
                    Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                        Text("PromptWorks Secure", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        Text("v3.8.0 · protected side-by-side authenticator", color = CYAN, fontWeight = FontWeight.SemiBold)
                        Text("Each request is bound to one Linux host and one APK installation. The phone requires BIOMETRIC_STRONG before deriving the local APPROVE or DENY code. The 8-digit response is transferred manually; no runtime backend is involved.", color = Color(0xFFD4E1EE), lineHeight = 20.sp)
                        Text("Upgrade safety", fontSize = 17.sp, fontWeight = FontWeight.Bold)
                        Text("If commissioning does not succeed, recovery restores the previous PromptWorks PAM/backend binding rather than intentionally switching to the original mode.", color = MUTED, lineHeight = 19.sp)
                    }
                }
            }
        }
    }



    @Composable
    private fun HomeScreen(
        status: String,
        onOpenDrawer: () -> Unit,
        onRefresh: () -> Unit,
        onNavigate: (AppPage) -> Unit,
    ) {
        BoxWithConstraints(
            Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        listOf(Color(0xFF07131E), Color(0xFF06111B), Color(0xFF07131D))
                    )
                )
        ) {
            val short = maxHeight < 735.dp
            val mark = if (short) 84.dp else 100.dp
            val titleSize = if (short) 26.sp else 30.sp
            val heroTitle = if (short) 29.sp else 34.sp
            val heroPad = if (short) 17.dp else 22.dp
            val navHeight = if (short) 65.dp else 72.dp
            val featureHeight = if (short) 63.dp else 70.dp

            Column(Modifier.fillMaxSize()) {
                // Header block deliberately mirrors the supplied Home reference.
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 16.dp, top = if (short) 3.dp else 7.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Row(
                        Modifier.fillMaxWidth().height(if (short) 28.dp else 32.dp),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        IconButton(onClick = onOpenDrawer, modifier = Modifier.size(32.dp)) {
                            Icon(Icons.Outlined.MoreVert, "Menu", tint = Color.White, modifier = Modifier.size(24.dp))
                        }
                    }
                    PromptWorksMark(mark)
                    Spacer(Modifier.height(if (short) 4.dp else 7.dp))
                    PromptWorksWordmark(fontSize = titleSize, secureBelow = false)
                    Spacer(Modifier.height(if (short) 9.dp else 13.dp))
                    PairedPill()
                    Spacer(Modifier.height(if (short) 12.dp else 17.dp))
                }

                Card(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .padding(horizontal = 15.dp),
                    shape = RoundedCornerShape(21.dp),
                    border = BorderStroke(1.dp, Color(0xFF2C475D)),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0A1722)),
                ) {
                    Column(
                        Modifier.fillMaxSize().padding(horizontal = heroPad, vertical = if (short) 12.dp else 17.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.SpaceEvenly,
                    ) {
                        ShieldEmblem(if (short) 112.dp else 132.dp)

                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                "Ready for",
                                color = Color(0xFFF3F8FF),
                                fontSize = heroTitle,
                                fontWeight = FontWeight.ExtraBold,
                                lineHeight = heroTitle,
                            )
                            Text(
                                "sudo approval",
                                color = Color(0xFF12CFFF),
                                fontSize = heroTitle,
                                fontWeight = FontWeight.ExtraBold,
                                lineHeight = heroTitle,
                            )
                        }

                        Text(
                            "A request from ${shortHost()} is waiting\nfor your approval.",
                            color = Color(0xFF91AAC6),
                            fontSize = if (short) 13.sp else 15.sp,
                            lineHeight = if (short) 18.sp else 21.sp,
                            textAlign = TextAlign.Center,
                            maxLines = 2,
                        )

                        GradientActionButton(
                            text = "Approve with Biometrics",
                            icon = Icons.Outlined.Fingerprint,
                            height = if (short) 49.dp else 56.dp,
                            onClick = onRefresh,
                        )

                        Row(
                            Modifier.clickable { onRefresh() },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                "Review Details",
                                color = Color(0xFF8FA8C4),
                                fontSize = if (short) 13.sp else 15.sp,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Spacer(Modifier.width(2.dp))
                            Icon(
                                Icons.Outlined.KeyboardArrowRight,
                                null,
                                tint = Color(0xFF8FA8C4),
                                modifier = Modifier.size(21.dp),
                            )
                        }
                    }
                }

                if (status.isNotBlank()) {
                    Text(
                        status,
                        color = MUTED,
                        fontSize = 10.sp,
                        maxLines = 1,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 2.dp),
                        textAlign = TextAlign.Center,
                    )
                } else {
                    Spacer(Modifier.height(if (short) 7.dp else 10.dp))
                }

                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 15.dp),
                    horizontalArrangement = Arrangement.spacedBy(9.dp),
                ) {
                    FeatureCard(
                        Icons.Outlined.Link,
                        "1:1 Binding",
                        "Device locked",
                        Color(0xFF00E6B8),
                        Modifier.weight(1f).height(featureHeight),
                    )
                    FeatureCard(
                        Icons.Outlined.Fingerprint,
                        "Strong Biometric",
                        "On-device auth",
                        Color(0xFF00E6B8),
                        Modifier.weight(1f).height(featureHeight),
                    )
                    FeatureCard(
                        Icons.Outlined.WifiOff,
                        "Offline Runtime",
                        "No cloud needed",
                        Color(0xFF91A8C1),
                        Modifier.weight(1f).height(featureHeight),
                    )
                }
                Spacer(Modifier.height(if (short) 7.dp else 10.dp))
                BottomNavigationBar(AppPage.AUTH, onNavigate, navHeight)
            }
        }
    }

    @Composable
    private fun GradientActionButton(
        text: String,
        icon: ImageVector,
        height: androidx.compose.ui.unit.Dp,
        onClick: () -> Unit,
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .height(height)
                .clip(RoundedCornerShape(height / 2))
                .background(
                    Brush.horizontalGradient(
                        listOf(Color(0xFF0AA9FF), Color(0xFF126DFF), Color(0xFF1462FF))
                    )
                )
                .clickable { onClick() }
                .padding(horizontal = 22.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(icon, null, tint = Color.White, modifier = Modifier.size(27.dp))
            Spacer(Modifier.width(14.dp))
            Text(text, color = Color.White, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
        }
    }

    @Composable
    private fun RequestScreen(
        request: AuthRequest,
        nowMs: Long,
        status: String,
        decisionBusy: Boolean,
        onOpenDrawer: () -> Unit,
        onDecision: (String) -> Unit,
    ) {
        BoxWithConstraints(
            Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        listOf(Color(0xFF07131E), Color(0xFF06111B), Color(0xFF07131D))
                    )
                )
        ) {
            val short = maxHeight < 735.dp
            val remaining = try {
                ((Instant.parse(request.expiresAt).toEpochMilli() - nowMs) / 1000L).coerceAtLeast(0L)
            } catch (_: Exception) {
                0L
            }
            val mark = if (short) 76.dp else 88.dp
            val digitH = if (short) 82.dp else 94.dp
            val digitW = if (short) 70.dp else 78.dp

            Column(
                Modifier
                    .fillMaxSize()
                    .padding(start = 15.dp, end = 15.dp, top = if (short) 4.dp else 7.dp, bottom = 8.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Row(
                    Modifier.fillMaxWidth().height(if (short) 30.dp else 34.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClick = onOpenDrawer, modifier = Modifier.size(32.dp)) {
                        Icon(
                            Icons.Outlined.Settings,
                            "Settings",
                            tint = Color(0xFFBFD1E6),
                            modifier = Modifier.size(25.dp),
                        )
                    }
                }

                PromptWorksMark(mark)
                Spacer(Modifier.height(2.dp))
                PromptWorksWordmark(fontSize = if (short) 24.sp else 27.sp, secureBelow = true)
                Spacer(Modifier.height(if (short) 9.dp else 13.dp))

                Card(
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    shape = RoundedCornerShape(20.dp),
                    border = BorderStroke(1.dp, Color(0xFF2C475D)),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0A1722)),
                ) {
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(horizontal = if (short) 16.dp else 20.dp, vertical = if (short) 12.dp else 16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(
                            "Sudo Request",
                            color = Color(0xFFF5F8FC),
                            fontSize = if (short) 29.sp else 34.sp,
                            fontWeight = FontWeight.ExtraBold,
                            lineHeight = if (short) 33.sp else 38.sp,
                        )
                        Spacer(Modifier.height(if (short) 10.dp else 14.dp))

                        RequestDetail(Icons.Outlined.Computer, "Host", request.device.ifBlank { shortHost() }, short)
                        Spacer(Modifier.height(if (short) 8.dp else 11.dp))
                        RequestDetail(Icons.Outlined.Terminal, "Command", request.action.ifBlank { "sudo" }, short, monospace = true)

                        HorizontalDivider(
                            Modifier.padding(vertical = if (short) 11.dp else 15.dp),
                            color = Color(0xFF2A4258),
                        )

                        Text(
                            "Enter the number shown on your device",
                            color = Color(0xFFA1B5D0),
                            fontSize = if (short) 13.sp else 15.sp,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(if (short) 9.dp else 12.dp))

                        Row(horizontalArrangement = Arrangement.spacedBy(if (short) 7.dp else 9.dp)) {
                            request.code.take(3).padEnd(3, '•').forEach { digit ->
                                Box(
                                    Modifier
                                        .width(digitW)
                                        .height(digitH)
                                        .clip(RoundedCornerShape(14.dp))
                                        .background(
                                            Brush.verticalGradient(
                                                listOf(Color(0xFF11364E), Color(0xFF0B2232), Color(0xFF091A27))
                                            )
                                        )
                                        .border(2.dp, Color(0xFF0DA8FF), RoundedCornerShape(14.dp)),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text(
                                        digit.toString(),
                                        color = Color(0xFFD8FAFF),
                                        fontSize = if (short) 48.sp else 56.sp,
                                        fontWeight = FontWeight.Black,
                                    )
                                }
                            }
                        }

                        Spacer(Modifier.height(if (short) 8.dp else 11.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("◷", color = CYAN, fontSize = 22.sp)
                            Spacer(Modifier.width(8.dp))
                            Text("Expires in ", color = Color(0xFFA6B8CE), fontSize = if (short) 14.sp else 16.sp)
                            Text(
                                "${remaining}s",
                                color = if (remaining <= 10) RED else CYAN,
                                fontSize = if (short) 18.sp else 21.sp,
                                fontWeight = FontWeight.Bold,
                            )
                        }

                        Spacer(Modifier.height(if (short) 10.dp else 14.dp))
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            DecisionButton(
                                text = "DENY",
                                enabled = !decisionBusy && remaining > 0,
                                icon = Icons.Outlined.Close,
                                accent = RED,
                                fill = Color(0x331A0710),
                                height = if (short) 54.dp else 61.dp,
                                modifier = Modifier.weight(1f),
                            ) { onDecision("deny") }
                            DecisionButton(
                                text = "APPROVE",
                                enabled = !decisionBusy && remaining > 0,
                                icon = Icons.Outlined.Check,
                                accent = CYAN,
                                fill = Color(0x2200BFEF),
                                height = if (short) 54.dp else 61.dp,
                                modifier = Modifier.weight(1f),
                            ) { onDecision("approve") }
                        }

                        if (status.isNotBlank()) {
                            Spacer(Modifier.height(if (short) 7.dp else 10.dp))
                            Text(
                                status,
                                color = if (status.startsWith("Secure response not confirmed") || status.contains("failed", true)) RED else MUTED,
                                fontSize = if (short) 11.sp else 12.sp,
                                textAlign = TextAlign.Center,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        Spacer(Modifier.weight(1f))
                        HorizontalDivider(color = Color(0xFF294158))
                        Spacer(Modifier.height(if (short) 8.dp else 11.dp))
                        Icon(
                            Icons.Outlined.Fingerprint,
                            null,
                            tint = Color(0xFF839AB5),
                            modifier = Modifier.size(if (short) 34.dp else 41.dp),
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(
                            "Use fingerprint to approve",
                            color = Color(0xFFA2B6D0),
                            fontSize = if (short) 12.sp else 14.sp,
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun DecisionButton(
        text: String,
        enabled: Boolean = true,
        icon: ImageVector,
        accent: Color,
        fill: Color,
        height: androidx.compose.ui.unit.Dp,
        modifier: Modifier = Modifier,
        onClick: () -> Unit,
    ) {
        Row(
            modifier
                .height(height)
                .clip(RoundedCornerShape(17.dp))
                .background(fill)
                .border(1.5.dp, accent, RoundedCornerShape(17.dp))
                .clickable(enabled = enabled) { onClick() },
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(icon, null, tint = accent, modifier = Modifier.size(25.dp))
            Spacer(Modifier.width(9.dp))
            Text(text, color = accent, fontWeight = FontWeight.Black, fontSize = 16.sp)
        }
    }

    @Composable
    private fun HistoryPage(onOpenDrawer: () -> Unit, onNavigate: (AppPage) -> Unit) {
        Column(Modifier.fillMaxSize().background(BG)) {
            TopBar("History", onOpenDrawer)
            Column(Modifier.weight(1f).fillMaxWidth().padding(18.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                Icon(Icons.Outlined.History, null, tint = CYAN, modifier = Modifier.size(62.dp))
                Spacer(Modifier.height(14.dp))
                Text("Approval history", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(7.dp))
                Text("Offline sudo decisions remain local to this device; no network history is collected.", color = MUTED, textAlign = TextAlign.Center)
            }
            BottomNavigationBar(AppPage.HISTORY, onNavigate)
        }
    }

    @Composable
    private fun BottomNavigationBar(
        page: AppPage,
        onNavigate: (AppPage) -> Unit,
        height: androidx.compose.ui.unit.Dp = 68.dp,
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .height(height)
                .background(Color(0xFF09141E))
                .border(0.5.dp, Color(0xFF1B3042), RoundedCornerShape(0.dp)),
            horizontalArrangement = Arrangement.SpaceAround,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            BottomNavItem(Icons.Filled.Home, "Home", page == AppPage.AUTH) { onNavigate(AppPage.AUTH) }
            BottomNavItem(Icons.Outlined.History, "History", page == AppPage.HISTORY) { onNavigate(AppPage.HISTORY) }
            BottomNavItem(Icons.Outlined.Settings, "Settings", page == AppPage.SETTINGS) { onNavigate(AppPage.SETTINGS) }
        }
    }

    @Composable
    private fun RowScope.BottomNavItem(icon: ImageVector, label: String, selected: Boolean, onClick: () -> Unit) {
        Column(
            Modifier.weight(1f).fillMaxHeight().clickable { onClick() }.padding(top = 7.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(icon, null, tint = if (selected) CYAN else Color(0xFF7189A3), modifier = Modifier.size(27.dp))
            Text(label, color = if (selected) CYAN else Color(0xFF7189A3), fontSize = 12.sp, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
            if (selected) Box(Modifier.padding(top = 4.dp).width(28.dp).height(3.dp).clip(RoundedCornerShape(2.dp)).background(Color(0xFF429CFF)))
        }
    }

    @Composable
    private fun FeatureCard(icon: ImageVector, title: String, subtitle: String, tint: Color, modifier: Modifier = Modifier) {
        Card(
            modifier = modifier,
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1925)),
            border = BorderStroke(1.dp, Color(0xFF20384A)),
            shape = RoundedCornerShape(15.dp),
        ) {
            Row(Modifier.fillMaxSize().padding(horizontal = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, null, tint = tint, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(8.dp))
                Column {
                    Text(title, color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
                    Text(subtitle, color = Color(0xFF86A0BB), fontSize = 10.sp, maxLines = 1)
                }
            }
        }
    }

    @Composable
    private fun SecuritySummaryCard(icon: ImageVector, title: String, subtitle: String, tint: Color) {
        Card(
            Modifier.fillMaxWidth().height(72.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1925)),
            border = BorderStroke(1.dp, Color(0xFF20384A)),
            shape = RoundedCornerShape(16.dp),
        ) {
            Row(Modifier.fillMaxSize().padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, null, tint = tint, modifier = Modifier.size(28.dp))
                Spacer(Modifier.width(14.dp))
                Column {
                    Text(title, color = Color.White, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                    Text(subtitle, color = Color(0xFF86A0BB), fontSize = 12.sp)
                }
            }
        }
    }

    @Composable
    private fun RequestDetail(icon: ImageVector, label: String, value: String, compact: Boolean, monospace: Boolean = false) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(if (compact) 43.dp else 50.dp).clip(RoundedCornerShape(10.dp))
                    .background(Color(0xFF102136)).border(1.dp, Color(0xFF31577A), RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, null, tint = Color(0xFFC0D4EA), modifier = Modifier.size(if (compact) 23.dp else 27.dp))
            }
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(label, color = Color(0xFF9AB0CC), fontSize = if (compact) 12.sp else 14.sp)
                Text(
                    value,
                    color = Color(0xFFE9F3FF),
                    fontSize = if (compact) 16.sp else 18.sp,
                    fontWeight = if (monospace) FontWeight.Medium else FontWeight.Normal,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }

    @Composable
    private fun PromptWorksWordmark(fontSize: androidx.compose.ui.unit.TextUnit, secureBelow: Boolean) {
        if (secureBelow) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Prompt", color = Color.White, fontWeight = FontWeight.Black, fontSize = fontSize)
                    Text("Works", color = CYAN, fontWeight = FontWeight.Black, fontSize = fontSize)
                }
                Text("S e c u r e", color = Color.White, fontSize = fontSize * 0.53f, letterSpacing = 2.sp)
            }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Prompt", color = Color.White, fontWeight = FontWeight.Black, fontSize = fontSize)
                Text("Works", color = CYAN, fontWeight = FontWeight.Black, fontSize = fontSize)
                Spacer(Modifier.width(8.dp))
                Text("Secure", color = Color.White, fontWeight = FontWeight.Bold, fontSize = fontSize * 0.92f)
            }
        }
    }

    @Composable
    private fun PromptWorksMark(size: androidx.compose.ui.unit.Dp) {
        // Use the exact emblem artwork from the supplied reference design instead of
        // approximating the PromptWorks mark with a generated/vector shape.
        Image(
            painter = painterResource(com.promptworks.authenticator.R.drawable.promptworks_mark_reference),
            contentDescription = "PromptWorks",
            modifier = Modifier.size(size),
            contentScale = androidx.compose.ui.layout.ContentScale.Fit,
        )
    }

    @Composable
    private fun ShieldEmblem(size: androidx.compose.ui.unit.Dp) {
        Box(Modifier.size(size), contentAlignment = Alignment.Center) {
            Box(Modifier.fillMaxSize().border(1.dp, Color(0xFF083A63), CircleShape))
            Box(Modifier.fillMaxSize(0.78f).border(1.dp, Color(0xFF0B5C9A), CircleShape))
            Box(Modifier.fillMaxSize(0.58f).border(2.dp, Color(0xFF0B8FE4), CircleShape), contentAlignment = Alignment.Center) {
                Icon(Icons.Outlined.Shield, null, tint = CYAN, modifier = Modifier.fillMaxSize(0.62f))
            }
        }
    }

    @Composable
    private fun PairedPill() {
        val activationState = prefs.getString("activationState", "candidate").orEmpty().lowercase()
        val active = activationState == "active"
        Row(
            Modifier.clip(RoundedCornerShape(28.dp)).background(Color(0xFF102536)).border(1.dp, Color(0xFF28495D), RoundedCornerShape(28.dp))
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(13.dp).background(if (active) Color(0xFF00E6B8) else Color(0xFFFFB74D), CircleShape))
            Spacer(Modifier.width(9.dp))
            Text(if (active) "ACTIVE · " else "CANDIDATE · ", color = if (active) Color(0xFF00E6B8) else Color(0xFFFFB74D), fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Text(shortHost(), color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold, maxLines = 1)
        }
    }

    private fun shortHost(): String {
        val host = prefs.getString("offlineHostId", "Linux host").orEmpty().ifBlank { "Linux host" }
        return host.substringBeforeLast('-').ifBlank { host }
    }

    @Composable
    private fun SettingsCard(title: String, content: @Composable ColumnScope.() -> Unit) {
        Spacer(Modifier.height(10.dp))
        Card(colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text(title, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                content()
            }
        }
    }

    @Composable
    private fun Brand(size: androidx.compose.ui.unit.Dp) {
        Image(painterResource(com.promptworks.authenticator.R.drawable.authenticator_brand), null, Modifier.size(size))
    }

    @Composable
    private fun Info(label: String, value: String) {
        Text(label.uppercase(), color = MUTED, fontSize = 11.sp)
        Text(value.ifBlank { "—" }, fontSize = 15.sp, modifier = Modifier.padding(bottom = 8.dp))
    }

    private fun defaultDeviceName(): String {
        return (Build.MANUFACTURER + " " + Build.MODEL).trim().ifBlank { "Android Device" }
    }
}
