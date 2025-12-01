package app.alextran.immich

import android.content.Context
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayInputStream
import java.security.KeyStore
import javax.net.ssl.KeyManager
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Android plugin for SSL/TLS configuration with mTLS support.
 * 
 * Security model:
 * - Client certificates are imported into Android KeyStore
 * - Private keys never leave the KeyStore (hardware-backed when available)
 * - Only the KeyStore alias is stored in app preferences
 * 
 * The plugin uses the system trust store by default, which means:
 * - User-installed CA certificates are trusted (via network_security_config.xml)
 * - No certificate bypass/pinning is needed for self-signed CAs
 */
class HttpSSLOptionsPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private var methodChannel: MethodChannel? = null
    private var applicationContext: Context? = null

    companion object {
        private const val TAG = "HttpSSLOptionsPlugin"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val IMMICH_KEY_ALIAS = "immich_client_cert"
        
        // SSL configuration (exposed for potential use by native HTTP clients)
        private var sslSocketFactory: SSLSocketFactory? = null
        private var trustManager: X509TrustManager? = null
        
        /**
         * Check if a client certificate is installed in the KeyStore.
         */
        fun hasClientCertificate(): Boolean {
            return try {
                val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
                ks.load(null)
                ks.containsAlias(IMMICH_KEY_ALIAS)
            } catch (e: Exception) {
                Log.e(TAG, "Error checking KeyStore", e)
                false
            }
        }
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext
        methodChannel = MethodChannel(binding.binaryMessenger, "immich/httpSSLOptions")
        methodChannel?.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel?.setMethodCallHandler(null)
        methodChannel = null
        applicationContext = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "importClientCert" -> {
                    val args = call.arguments<Map<String, Any?>>()!!
                    val certData = args["data"] as ByteArray
                    val password = args["password"] as String
                    importClientCertificate(certData, password, result)
                }
                "applyConfig" -> {
                    applySSLConfig(result)
                }
                "removeClientCert" -> {
                    removeClientCertificate(result)
                }
                "hasClientCert" -> {
                    result.success(hasClientCertificate())
                }
                else -> result.notImplemented()
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error in method call ${call.method}", e)
            result.error("SSL_ERROR", e.message, e.stackTraceToString())
        }
    }

    /**
     * Import a PKCS12 certificate into Android KeyStore.
     * The private key is stored securely and never leaves the KeyStore.
     */
    private fun importClientCertificate(certData: ByteArray, password: String, result: MethodChannel.Result) {
        Log.d(TAG, "Importing client certificate into Android KeyStore")
        
        try {
            // Load the PKCS12 data
            val p12KeyStore = KeyStore.getInstance("PKCS12")
            p12KeyStore.load(ByteArrayInputStream(certData), password.toCharArray())
            
            // Get the first alias from the P12
            val aliases = p12KeyStore.aliases()
            if (!aliases.hasMoreElements()) {
                result.error("NO_CERT", "No certificate found in PKCS12 file", null)
                return
            }
            val sourceAlias = aliases.nextElement()
            
            // Get the private key and certificate chain
            val privateKey = p12KeyStore.getKey(sourceAlias, password.toCharArray())
            val certChain = p12KeyStore.getCertificateChain(sourceAlias)
            
            if (privateKey == null || certChain == null) {
                result.error("INVALID_CERT", "Could not extract key or certificate chain", null)
                return
            }
            
            // Import into Android KeyStore
            val androidKs = KeyStore.getInstance(ANDROID_KEYSTORE)
            androidKs.load(null)
            
            // Delete existing entry if present
            if (androidKs.containsAlias(IMMICH_KEY_ALIAS)) {
                androidKs.deleteEntry(IMMICH_KEY_ALIAS)
            }
            
            // Store in Android KeyStore
            androidKs.setKeyEntry(IMMICH_KEY_ALIAS, privateKey, null, certChain)
            
            Log.d(TAG, "Client certificate imported successfully")
            
            // Apply the new configuration
            applySSLConfigInternal()
            
            result.success(IMMICH_KEY_ALIAS)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to import client certificate", e)
            result.error("IMPORT_FAILED", e.message, e.stackTraceToString())
        }
    }

    /**
     * Apply SSL configuration using certificate from Android KeyStore.
     */
    private fun applySSLConfig(result: MethodChannel.Result) {
        try {
            applySSLConfigInternal()
            result.success(true)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to apply SSL config", e)
            result.error("CONFIG_FAILED", e.message, e.stackTraceToString())
        }
    }
    
    private fun applySSLConfigInternal() {
        Log.d(TAG, "Applying SSL configuration")
        
        // Get the default trust manager (trusts system + user-installed CAs)
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        trustManager = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        
        // Load key managers from Android KeyStore if certificate exists
        val keyManagers: Array<KeyManager>? = if (hasClientCertificate()) {
            Log.d(TAG, "Loading client certificate from Android KeyStore")
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            val androidKs = KeyStore.getInstance(ANDROID_KEYSTORE)
            androidKs.load(null)
            kmf.init(androidKs, null) // Android KeyStore doesn't need password
            kmf.keyManagers
        } else {
            Log.d(TAG, "No client certificate configured")
            null
        }
        
        // Create SSL context
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(keyManagers, arrayOf(trustManager), null)
        sslSocketFactory = sslContext.socketFactory
        
        // Set for HttpsURLConnection (legacy support)
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory)
        
        Log.d(TAG, "SSL configuration applied successfully")
    }

    /**
     * Remove client certificate from Android KeyStore.
     */
    private fun removeClientCertificate(result: MethodChannel.Result) {
        Log.d(TAG, "Removing client certificate from Android KeyStore")
        
        try {
            val androidKs = KeyStore.getInstance(ANDROID_KEYSTORE)
            androidKs.load(null)
            
            if (androidKs.containsAlias(IMMICH_KEY_ALIAS)) {
                androidKs.deleteEntry(IMMICH_KEY_ALIAS)
            }
            
            // Re-apply SSL config without client cert
            applySSLConfigInternal()
            
            result.success(true)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove client certificate", e)
            result.error("REMOVE_FAILED", e.message, e.stackTraceToString())
        }
    }
}
