import 'package:chameleonultragui/gui/component/error_page.dart';
import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/ulc.dart';
import 'package:chameleonultragui/helpers/validators.dart';
import 'package:chameleonultragui/main.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:chameleonultragui/generated/i18n/app_localizations.dart';

class UlcChangeKeyMenu extends StatefulWidget {
  const UlcChangeKeyMenu({super.key});

  @override
  UlcChangeKeyMenuState createState() => UlcChangeKeyMenuState();
}

class UlcChangeKeyMenuState extends State<UlcChangeKeyMenu> {
  final GlobalKey<FormState> formKey = GlobalKey<FormState>();
  final TextEditingController oldKeyController = TextEditingController(
      text: mfUltralightCKnownKeys.first.$2);
  final TextEditingController newKeyController = TextEditingController();
  bool isProcessing = false;

  @override
  void dispose() {
    oldKeyController.dispose();
    newKeyController.dispose();
    super.dispose();
  }

  Future<void> _changeKey() async {
    if (!formKey.currentState!.validate()) return;

    var appState = context.read<ChameleonGUIState>();
    var localizations = AppLocalizations.of(context)!;

    final oldKey = hexToBytes(oldKeyController.text);
    final newKey = hexToBytes(newKeyController.text);

    setState(() => isProcessing = true);

    try {
      if (!await appState.communicator!.isReaderDeviceMode()) {
        await appState.communicator!.setReaderDeviceMode(true);
      }

      if (await appState.communicator!.scan14443aTag() == null) {
        setState(() => isProcessing = false);
        if (mounted) {
          _showResult(localizations.ulc_change_key_failed,
              localizations.no_card_found);
        }
        return;
      }

      // Verify the old key first so we fail cleanly instead of half-writing.
      if (!await appState.communicator!.mf0UlcAuth(oldKey)) {
        setState(() => isProcessing = false);
        if (mounted) {
          _showResult(localizations.ulc_change_key_failed,
              localizations.ulc_old_key_wrong);
        }
        return;
      }

      final ok = await appState.communicator!.mf0UlcSetKey(oldKey, newKey);
      setState(() => isProcessing = false);

      if (mounted) {
        _showResult(
            ok
                ? localizations.ulc_change_key_success
                : localizations.ulc_change_key_failed,
            ok
                ? localizations.ulc_change_key_success_body
                : localizations.ulc_change_key_write_failed,
            popOnOk: ok);
      }
    } catch (e) {
      setState(() => isProcessing = false);
      if (mounted) {
        showDialog(
          context: context,
          builder: (_) => ErrorPage(errorMessage: e.toString()),
        );
      }
    }
  }

  void _showResult(String title, String body, {bool popOnOk = false}) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(title),
          content: Text(body),
          actions: [
            TextButton(
              onPressed: () {
                Navigator.of(context).pop();
                if (popOnOk && mounted) {
                  Navigator.of(this.context).pop();
                }
              },
              child: Text(AppLocalizations.of(context)!.ok),
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    var localizations = AppLocalizations.of(context)!;

    return AlertDialog(
      title: Text(localizations.ulc_change_key),
      content: Form(
        key: formKey,
        autovalidateMode: AutovalidateMode.onUserInteraction,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Card(
                color: Colors.orange.withValues(alpha: 0.1),
                child: Padding(
                  padding: const EdgeInsets.all(12.0),
                  child: Row(
                    children: [
                      const Icon(Icons.warning, color: Colors.orange),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          localizations.ulc_change_key_warning,
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              TextFormField(
                controller: oldKeyController,
                enabled: !isProcessing,
                decoration: InputDecoration(
                  border: const OutlineInputBorder(),
                  labelText: localizations.ulc_old_key,
                ),
                inputFormatters: hexFormatter,
                validator: (value) => validateHex(value, localizations,
                    exactBytes: 16,
                    fieldName: localizations.key,
                    required: true),
              ),
              const SizedBox(height: 16),
              TextFormField(
                controller: newKeyController,
                enabled: !isProcessing,
                decoration: InputDecoration(
                  border: const OutlineInputBorder(),
                  labelText: localizations.ulc_new_key,
                ),
                inputFormatters: hexFormatter,
                validator: (value) => validateHex(value, localizations,
                    exactBytes: 16,
                    fieldName: localizations.key,
                    required: true),
              ),
              if (isProcessing) ...[
                const SizedBox(height: 16),
                const LinearProgressIndicator(),
              ],
            ],
          ),
        ),
      ),
      actions: [
        ElevatedButton(
          onPressed:
              isProcessing ? null : () => Navigator.of(context).pop(),
          child: Text(localizations.cancel),
        ),
        ElevatedButton(
          onPressed: isProcessing ? null : _changeKey,
          child: Text(localizations.ulc_change_key),
        ),
      ],
    );
  }
}
