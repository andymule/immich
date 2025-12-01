import 'dart:io';

import 'package:easy_localization/easy_localization.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:immich_mobile/extensions/build_context_extensions.dart';
import 'package:immich_mobile/extensions/theme_extensions.dart';
import 'package:immich_mobile/utils/http_ssl_options.dart';
import 'package:immich_mobile/utils/ssl_http_client.dart';

class SslClientCertSettings extends StatefulWidget {
  const SslClientCertSettings({super.key, required this.isLoggedIn});

  final bool isLoggedIn;

  @override
  State<StatefulWidget> createState() => _SslClientCertSettingsState();
}

class _SslClientCertSettingsState extends State<SslClientCertSettings> {
  bool isCertExist = false;
  bool isLoading = false;

  @override
  void initState() {
    super.initState();
    _checkCertExists();
  }

  Future<void> _checkCertExists() async {
    final exists = await HttpSSLOptions.hasClientCertificate();
    if (mounted) {
      setState(() => isCertExist = exists);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 20),
      horizontalTitleGap: 20,
      isThreeLine: true,
      title: Text("client_cert_title".tr(), style: context.textTheme.bodyLarge?.copyWith(fontWeight: FontWeight.w500)),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            "client_cert_subtitle".tr(),
            style: context.textTheme.bodyMedium?.copyWith(color: context.colorScheme.onSurfaceSecondary),
          ),
          const SizedBox(height: 6),
          Row(
            mainAxisSize: MainAxisSize.max,
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              ElevatedButton(
                onPressed: widget.isLoggedIn || isLoading ? null : () => importCert(context),
                child: isLoading
                    ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                    : Text("client_cert_import".tr()),
              ),
              const SizedBox(width: 15),
              ElevatedButton(
                onPressed: widget.isLoggedIn || !isCertExist || isLoading ? null : () async => await removeCert(context),
                child: Text("remove".tr()),
              ),
            ],
          ),
        ],
      ),
    );
  }

  void showMessage(BuildContext context, String message) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        content: Text(message),
        actions: [TextButton(onPressed: () => ctx.pop(), child: Text("client_cert_dialog_msg_confirm".tr()))],
      ),
    );
  }

  Future<void> storeCert(BuildContext context, Uint8List data, String? password) async {
    if (password != null && password.isEmpty) {
      password = null;
    }

    setState(() => isLoading = true);

    try {
      // Validate certificate format first
      if (!SSLHttpClient.validateClientCertificate(
        _TempCertVal(data, password),
      )) {
        showMessage(context, "client_cert_invalid_msg".tr());
        return;
      }

      // Import certificate (uses KeyStore on Android, Keychain on iOS)
      await HttpSSLOptions.importClientCertificate(data, password ?? '');
      
      setState(() => isCertExist = true);
      showMessage(context, "client_cert_import_success_msg".tr());
    } catch (e) {
      showMessage(context, "client_cert_invalid_msg".tr());
    } finally {
      if (mounted) {
        setState(() => isLoading = false);
      }
    }
  }

  void setPassword(BuildContext context, Uint8List data) {
    final password = TextEditingController();
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        content: TextField(
          controller: password,
          obscureText: true,
          obscuringCharacter: "*",
          decoration: InputDecoration(hintText: "client_cert_enter_password".tr()),
        ),
        actions: [
          TextButton(
            onPressed: () async => {ctx.pop(), await storeCert(context, data, password.text)},
            child: Text("client_cert_dialog_msg_confirm".tr()),
          ),
        ],
      ),
    );
  }

  Future<void> importCert(BuildContext ctx) async {
    FilePickerResult? res = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['p12', 'pfx'],
    );
    if (res != null) {
      File file = File(res.files.single.path!);
      final bytes = await file.readAsBytes();
      setPassword(ctx, bytes);
    }
  }

  Future<void> removeCert(BuildContext context) async {
    setState(() => isLoading = true);
    
    try {
      await HttpSSLOptions.removeClientCertificate();
      setState(() => isCertExist = false);
      showMessage(context, "client_cert_remove_msg".tr());
    } finally {
      if (mounted) {
        setState(() => isLoading = false);
      }
    }
  }
}

/// Temporary class for validation only (matches SSLClientCertStoreVal interface)
class _TempCertVal {
  final Uint8List data;
  final String? password;
  const _TempCertVal(this.data, this.password);
}
