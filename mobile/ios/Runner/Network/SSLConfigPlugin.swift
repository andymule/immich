import Flutter
import Security
import Foundation

/**
 * iOS plugin for SSL/TLS configuration with mTLS support.
 *
 * This plugin manages client certificates for mTLS authentication:
 * - Imports PKCS12 (.p12) client certificates into the iOS Keychain
 * - Provides the identity for URLSession authentication challenges
 *
 * For server CA trust:
 * - Users install the CA certificate via iOS Settings or a .mobileconfig profile
 * - iOS automatically trusts the CA in Settings → General → About → Certificate Trust Settings
 *
 * The client certificate is stored in the Keychain and retrieved when needed
 * for URLSession authentication challenges.
 */
class SSLConfigPlugin: NSObject, FlutterPlugin {
    private static let keychainService = "app.alextran.immich.ssl"
    private static let keychainAccount = "clientCert"
    private static let keychainAccessGroup = "group.app.immich.share"
    
    // Cached identity for authentication challenges
    private static var cachedIdentity: SecIdentity?
    private static var cachedCertificateChain: [SecCertificate]?
    
    static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "immich/sslConfig", binaryMessenger: registrar.messenger())
        let instance = SSLConfigPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
        
        // Load existing certificate from keychain on startup
        loadCachedIdentity()
    }
    
    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "importClientCert":
            guard let args = call.arguments as? [String: Any],
                  let data = args["data"] as? FlutterStandardTypedData,
                  let password = args["password"] as? String else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing data or password", details: nil))
                return
            }
            importClientCert(data: data.data, password: password, result: result)
            
        case "removeClientCert":
            removeClientCert(result: result)
            
        case "hasClientCert":
            result(SSLConfigPlugin.cachedIdentity != nil)
            
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    private func importClientCert(data: Data, password: String, result: @escaping FlutterResult) {
        var items: CFArray?
        let options: [CFString: Any] = [kSecImportExportPassphrase: password]
        
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        
        guard status == errSecSuccess else {
            let errorMsg = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            result(FlutterError(code: "IMPORT_FAILED", message: "Failed to import certificate: \(errorMsg)", details: "Status: \(status)"))
            return
        }
        
        guard let itemsArray = items as? [[CFString: Any]],
              let firstItem = itemsArray.first,
              let identityRef = firstItem[kSecImportItemIdentity],
              CFGetTypeID(identityRef as CFTypeRef) == SecIdentityGetTypeID() else {
            result(FlutterError(code: "NO_IDENTITY", message: "No identity found in certificate", details: nil))
            return
        }
        let identity = identityRef as! SecIdentity
        
        // Extract certificate chain if available
        var chain: [SecCertificate] = []
        if let certChain = firstItem[kSecImportItemCertChain] as? [SecCertificate] {
            chain = certChain
        }
        
        // Store in keychain for persistence
        let storeSuccess = storeInKeychain(data: data, password: password)
        if !storeSuccess {
            print("SSLConfigPlugin: Warning - Failed to store certificate in keychain")
        }
        
        // Cache for immediate use
        SSLConfigPlugin.cachedIdentity = identity
        SSLConfigPlugin.cachedCertificateChain = chain
        
        print("SSLConfigPlugin: Client certificate imported successfully")
        result(true)
    }
    
    private func storeInKeychain(data: Data, password: String) -> Bool {
        // First, delete any existing entry
        let deleteQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: SSLConfigPlugin.keychainService,
            kSecAttrAccount: SSLConfigPlugin.keychainAccount,
            kSecAttrAccessGroup: SSLConfigPlugin.keychainAccessGroup
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // Store both data and password as JSON
        let storageDict: [String: Any] = [
            "data": data.base64EncodedString(),
            "password": password
        ]
        
        guard let storageData = try? JSONSerialization.data(withJSONObject: storageDict) else {
            return false
        }
        
        let addQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: SSLConfigPlugin.keychainService,
            kSecAttrAccount: SSLConfigPlugin.keychainAccount,
            kSecAttrAccessGroup: SSLConfigPlugin.keychainAccessGroup,
            kSecValueData: storageData,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    private static func loadCachedIdentity() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecAttrAccessGroup: keychainAccessGroup,
            kSecReturnData: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess,
              let storageData = item as? Data,
              let storageDict = try? JSONSerialization.jsonObject(with: storageData) as? [String: Any],
              let base64Data = storageDict["data"] as? String,
              let certData = Data(base64Encoded: base64Data),
              let password = storageDict["password"] as? String else {
            print("SSLConfigPlugin: No cached certificate found in keychain")
            return
        }
        
        // Import the certificate
        var items: CFArray?
        let options: [CFString: Any] = [kSecImportExportPassphrase: password]
        let importStatus = SecPKCS12Import(certData as CFData, options as CFDictionary, &items)
        
        guard importStatus == errSecSuccess,
              let itemsArray = items as? [[CFString: Any]],
              let firstItem = itemsArray.first,
              let identityRef = firstItem[kSecImportItemIdentity],
              CFGetTypeID(identityRef as CFTypeRef) == SecIdentityGetTypeID() else {
            print("SSLConfigPlugin: Failed to load cached certificate")
            return
        }
        let identity = identityRef as! SecIdentity
        
        cachedIdentity = identity
        if let certChain = firstItem[kSecImportItemCertChain] as? [SecCertificate] {
            cachedCertificateChain = certChain
        }
        
        print("SSLConfigPlugin: Loaded cached client certificate from keychain")
    }
    
    private func removeClientCert(result: @escaping FlutterResult) {
        let deleteQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: SSLConfigPlugin.keychainService,
            kSecAttrAccount: SSLConfigPlugin.keychainAccount,
            kSecAttrAccessGroup: SSLConfigPlugin.keychainAccessGroup
        ]
        
        SecItemDelete(deleteQuery as CFDictionary)
        SSLConfigPlugin.cachedIdentity = nil
        SSLConfigPlugin.cachedCertificateChain = nil
        
        print("SSLConfigPlugin: Client certificate removed")
        result(true)
    }
}

