import 'dart:io';

import 'package:flutter/services.dart';
import 'package:immich_mobile/entities/store.entity.dart';
import 'package:immich_mobile/utils/http_ssl_cert_override.dart';
import 'package:immich_mobile/utils/ssl_http_client.dart';
import 'package:logging/logging.dart';

/// Central SSL/TLS configuration manager for the Immich app.
/// 
/// Platform-specific security:
/// - Android: Certificates stored in Android KeyStore (hardware-backed)
/// - iOS: Certificates stored in iOS Keychain
/// 
/// For mTLS to work:
/// 1. Install your CA certificate on the device
///    - Android: Settings → Security → Install certificates
///    - iOS: Install profile, then Settings → General → About → Certificate Trust Settings
/// 2. Import your client certificate (.p12) in Immich app settings
class HttpSSLOptions {
  static final Logger _log = Logger('HttpSSLOptions');
  static const MethodChannel _androidChannel = MethodChannel('immich/httpSSLOptions');
  static const MethodChannel _iosChannel = MethodChannel('immich/sslConfig');

  /// Apply SSL configuration across all HTTP clients.
  /// Call this at app startup and after certificate changes.
  /// 
  /// Set `applyNative: false` when running in isolates (native MethodChannel
  /// calls are not available in isolates).
  static Future<void> apply({bool applyNative = true}) async {
    _log.info('Applying SSL configuration');
    
    // Initialize the SSL client factory
    await SSLHttpClient.initialize();
    
    // Set global HTTP overrides for dart:io HttpClient
    HttpOverrides.global = HttpSSLCertOverride();
    
    // Apply native platform configuration (skip in isolates)
    if (applyNative) {
      await _applyNativeConfig();
    }
    
    _log.info('SSL configuration applied successfully');
  }

  /// Import a client certificate (.p12 file).
  /// Returns true on success, throws on failure.
  static Future<bool> importClientCertificate(Uint8List data, String password) async {
    _log.info('Importing client certificate');
    
    if (Platform.isAndroid) {
      // Android: Import into Android KeyStore (secure, hardware-backed)
      await _androidChannel.invokeMethod('importClientCert', {
        'data': data,
        'password': password,
      });
      _log.info('Client certificate imported to Android KeyStore');
    } else if (Platform.isIOS) {
      // iOS: Import into Keychain
      await _iosChannel.invokeMethod('importClientCert', {
        'data': data,
        'password': password,
      });
      // Also save to local storage for SecurityContext
      final cert = SSLClientCertStoreVal(data, password);
      await cert.save();
      _log.info('Client certificate imported to iOS Keychain');
    }
    
    // Re-apply configuration with new certificate
    await apply();
    return true;
  }

  /// Remove the client certificate.
  static Future<void> removeClientCertificate() async {
    _log.info('Removing client certificate');
    
    if (Platform.isAndroid) {
      await _androidChannel.invokeMethod('removeClientCert');
    } else if (Platform.isIOS) {
      await _iosChannel.invokeMethod('removeClientCert');
      await SSLClientCertStoreVal.delete();
    }
    
    // Re-apply configuration without certificate
    await apply();
  }

  /// Check if a client certificate is configured.
  static Future<bool> hasClientCertificate() async {
    if (Platform.isAndroid) {
      return await _androidChannel.invokeMethod('hasClientCert') ?? false;
    } else if (Platform.isIOS) {
      return await _iosChannel.invokeMethod('hasClientCert') ?? false;
    }
    return false;
  }

  /// Apply native platform SSL configuration.
  static Future<void> _applyNativeConfig() async {
    try {
      if (Platform.isAndroid) {
        await _androidChannel.invokeMethod('applyConfig');
        _log.fine('Android SSL configuration applied');
      } else if (Platform.isIOS) {
        // iOS SSL is configured via Keychain, just ensure cert is loaded
        final cert = SSLClientCertStoreVal.load();
        if (cert != null) {
          await _iosChannel.invokeMethod('importClientCert', {
            'data': cert.data,
            'password': cert.password,
          });
        }
        _log.fine('iOS SSL configuration applied');
      }
    } on PlatformException catch (e) {
      _log.severe('Failed to apply native SSL configuration', e);
    }
  }

  /// Legacy method for settings changes.
  @Deprecated('Use apply() instead')
  static void applyFromSettings() {
    apply();
  }
}
