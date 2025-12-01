import 'dart:io';

import 'package:immich_mobile/domain/models/store.model.dart';
import 'package:immich_mobile/domain/services/store.service.dart';
import 'package:immich_mobile/utils/ssl_http_client.dart';
import 'package:logging/logging.dart';

/// HTTP overrides for SSL/TLS configuration.
/// 
/// This class configures dart:io's HttpClient to use proper SSL settings:
/// - Uses the system trust store (trusts user-installed CAs)
/// - Presents client certificates for mTLS authentication
/// - Optionally accepts self-signed certificates when enabled in settings
/// 
/// For self-signed CA support:
/// - Enable "Allow self-signed SSL certificates" in Advanced Settings
/// - This will trust ALL certificates - use with caution on trusted networks only
class HttpSSLCertOverride extends HttpOverrides {
  static final Logger _log = Logger('HttpSSLCertOverride');

  HttpSSLCertOverride();

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    // Always use our configured security context for consistent SSL behavior.
    final effectiveContext = context ?? SSLHttpClient.getSecurityContext();
    
    _log.fine('Creating HttpClient with SSL context');
    
    final client = super.createHttpClient(effectiveContext);
    
    // Configure connection settings
    client.maxConnectionsPerHost = 16;
    
    // Check if self-signed certificates should be allowed
    final allowSelfSigned = StoreService.I.tryGet(StoreKey.selfSignedCert) ?? false;
    
    if (allowSelfSigned) {
      _log.warning('Self-signed SSL certificates enabled - accepting all certificates');
      client.badCertificateCallback = (X509Certificate cert, String host, int port) {
        _log.fine('Accepting certificate for $host:$port');
        return true;
      };
    }
    
    return client;
  }
}
