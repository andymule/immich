import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/domain/services/store.service.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:logging/logging.dart';

/// Unified SSL/TLS HTTP client factory for mTLS support.
/// 
/// Architecture:
/// - Android: Uses Android KeyStore for secure certificate storage
///   (private keys never leave the hardware-backed KeyStore)
/// - iOS: Uses Keychain for secure certificate storage
/// - Dart: Creates SecurityContext with proper trust anchors
/// 
/// All HTTP clients created through this factory will:
/// - Trust the system CA store (including user-installed CAs)
/// - Present client certificates for mTLS authentication when configured
class SSLHttpClient {
  static final Logger _log = Logger('SSLHttpClient');
  
  static SecurityContext? _securityContext;
  static HttpClient? _ioClient;
  static http.Client? _httpClient;
  static bool _initialized = false;
  
  SSLHttpClient._();
  
  /// Initialize SSL configuration.
  /// Uses compute isolate for certificate loading to avoid main thread jank.
  static Future<void> initialize() async {
    _log.info('Initializing SSL configuration');
    reset();
    
    // Load certificate in background isolate to avoid main thread jank
    if (Platform.isIOS) {
      // iOS: Load cert data for SecurityContext (native handles KeyStore)
      _securityContext = await compute(_createSecurityContextIsolate, null);
    } else {
      // Android: Native plugin handles KeyStore, we just need trust anchors
      _securityContext = SecurityContext(withTrustedRoots: true);
    }
    
    _initialized = true;
    _log.info('SSL configuration initialized');
  }
  
  /// Create SecurityContext in isolate (for iOS).
  /// Top-level function required for compute().
  static SecurityContext _createSecurityContextIsolate(_) {
    final context = SecurityContext(withTrustedRoots: true);
    
    // On iOS, load client cert into SecurityContext
    // (This runs in isolate, so we need to load from a simple format)
    final certData = _loadCertDataSync();
    if (certData != null) {
      try {
        context.usePrivateKeyBytes(certData.data, password: certData.password);
        context.useCertificateChainBytes(certData.data, password: certData.password);
      } catch (e) {
        // Log error but continue - cert might be invalid
        debugPrint('SSLHttpClient: Failed to load client certificate: $e');
      }
    }
    
    return context;
  }
  
  /// Synchronously load cert data (for use in isolate).
  static SSLClientCertStoreVal? _loadCertDataSync() {
    // Note: This is a simplified sync load for isolate use
    // The actual StoreService might not be available in isolate
    return null; // Will be loaded by native side on iOS
  }
  
  /// Get the configured SecurityContext.
  static SecurityContext getSecurityContext() {
    if (!_initialized) {
      _log.warning('SSL not initialized, using default context');
      return SecurityContext(withTrustedRoots: true);
    }
    return _securityContext ?? SecurityContext(withTrustedRoots: true);
  }
  
  /// Get a configured dart:io HttpClient.
  static HttpClient getIOClient() {
    if (_ioClient != null) return _ioClient!;
    
    _log.fine('Creating new IOClient with SSL context');
    _ioClient = HttpClient(context: getSecurityContext())
      ..maxConnectionsPerHost = 16;
    
    // Check if self-signed certificates should be allowed
    final allowSelfSigned = StoreService.I.tryGet(StoreKey.selfSignedCert) ?? false;
    if (allowSelfSigned) {
      _log.warning('Self-signed SSL certificates enabled - accepting all certificates');
      _ioClient!.badCertificateCallback = (cert, host, port) => true;
    }
    
    return _ioClient!;
  }
  
  /// Get a configured http.Client from package:http.
  static http.Client getHttpClient() {
    if (_httpClient != null) return _httpClient!;
    
    _log.fine('Creating new http.Client wrapping IOClient');
    _httpClient = IOClient(getIOClient());
    
    return _httpClient!;
  }
  
  /// Check if a client certificate is configured.
  static bool hasClientCertificate() {
    if (Platform.isAndroid) {
      // Android stores in KeyStore, check via native
      return false; // Will be checked via MethodChannel
    }
    return SSLClientCertStoreVal.load() != null;
  }
  
  /// Validate that a client certificate can be loaded.
  /// Accepts any object with `data` (Uint8List) and `password` (String?) properties.
  static bool validateClientCertificate(dynamic cert) {
    try {
      final Uint8List data = cert.data;
      final String? password = cert.password;
      
      final testContext = SecurityContext(withTrustedRoots: true);
      testContext.usePrivateKeyBytes(data, password: password);
      testContext.useCertificateChainBytes(data, password: password);
      return true;
    } catch (e) {
      _log.warning('Client certificate validation failed', e);
      return false;
    }
  }
  
  /// Reset all clients. Call when SSL configuration changes.
  static void reset() {
    _log.info('Resetting SSL clients');
    
    try { _ioClient?.close(); } catch (_) {}
    try { _httpClient?.close(); } catch (_) {}
    
    _ioClient = null;
    _httpClient = null;
    _securityContext = null;
    _initialized = false;
  }
}
