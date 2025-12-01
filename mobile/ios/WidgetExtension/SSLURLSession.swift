import Foundation
import Security

/// URLSession with mTLS and self-signed certificate support for widgets.
class SSLURLSession: NSObject, URLSessionDelegate {
    
    static let shared: URLSession = {
        let delegate = SSLURLSession()
        return URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
    }()
    
    private static let keychainService = "app.alextran.immich.ssl"
    private static let keychainAccount = "clientCert"
    private static let keychainAccessGroup = "group.app.immich.share"
    
    private static var clientIdentity: SecIdentity?
    private static var certChain: [SecCertificate]?
    
    override init() {
        super.init()
        SSLURLSession.loadClientIdentity()
    }
    
    // MARK: - URLSessionDelegate
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            handleServerTrust(challenge, completionHandler)
        case NSURLAuthenticationMethodClientCertificate:
            handleClientCert(challenge, completionHandler)
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
    
    // MARK: - Server Trust (Self-Signed)
    
    private func handleServerTrust(
        _ challenge: URLAuthenticationChallenge,
        _ completion: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completion(.cancelAuthenticationChallenge, nil)
            return
        }
        
        if isSelfSignedAllowed() {
            completion(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completion(.performDefaultHandling, nil)
        }
    }
    
    private func isSelfSignedAllowed() -> Bool {
        guard let defaults = UserDefaults(suiteName: "group.app.immich.share") else { return false }
        return defaults.string(forKey: "widget_allow_self_signed")?.lowercased() == "true"
    }
    
    // MARK: - Client Certificate (mTLS)
    
    private func handleClientCert(
        _ challenge: URLAuthenticationChallenge,
        _ completion: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let identity = SSLURLSession.clientIdentity else {
            completion(.performDefaultHandling, nil)
            return
        }
        completion(.useCredential, URLCredential(identity: identity, certificates: SSLURLSession.certChain, persistence: .forSession))
    }
    
    // MARK: - Keychain
    
    private static func loadClientIdentity() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecAttrAccessGroup: keychainAccessGroup,
            kSecReturnData: true
        ]
        
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let b64 = dict["data"] as? String,
              let certData = Data(base64Encoded: b64),
              let password = dict["password"] as? String else { return }
        
        var items: CFArray?
        guard SecPKCS12Import(certData as CFData, [kSecImportExportPassphrase: password] as CFDictionary, &items) == errSecSuccess,
              let arr = items as? [[CFString: Any]],
              let first = arr.first,
              let identityRef = first[kSecImportItemIdentity],
              CFGetTypeID(identityRef as CFTypeRef) == SecIdentityGetTypeID() else { return }
        
        clientIdentity = (identityRef as! SecIdentity)
        certChain = first[kSecImportItemCertChain] as? [SecCertificate]
    }
}
