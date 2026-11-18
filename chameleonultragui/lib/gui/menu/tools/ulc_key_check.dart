import 'package:chameleonultragui/gui/component/error_page.dart';
import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/ulc.dart';
import 'package:chameleonultragui/helpers/validators.dart';
import 'package:chameleonultragui/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import 'package:chameleonultragui/generated/i18n/app_localizations.dart';

class UlcKeyCheckMenu extends StatefulWidget {
  const UlcKeyCheckMenu({super.key});

  @override
  UlcKeyCheckMenuState createState() => UlcKeyCheckMenuState();
}

class UlcKeyCheckMenuState extends State<UlcKeyCheckMenu> {
  final TextEditingController extraKeyController = TextEditingController();
  String? selectedDictionaryId;
  bool isProcessing = false;
  int currentKeyIndex = 0;
  int totalKeys = 0;
  String? foundKey;
  String? currentKey;

  @override
  void dispose() {
    extraKeyController.dispose();
    super.dispose();
  }

  /// Builds the ordered, de-duplicated candidate list: the built-in keys, an
  /// optional extra key typed by the user and every key from the selected
  /// 16-byte dictionary.
  List<(String, Uint8List)> _buildCandidates(
      ChameleonGUIState appState, AppLocalizations localizations) {
    final List<(String, Uint8List)> candidates = [];
    final Set<String> seen = {};

    // Add a key and, since tools disagree on byte order, its swapped form too.
    void add(String label, Uint8List key) {
      if (key.length != 16) return;
      for (final variant in <Uint8List>[key, mfUltralightSwapUlcKeyOrder(key)]) {
        final hex = bytesToHex(variant);
        if (seen.add(hex)) {
          candidates.add((label, variant));
        }
      }
    }

    final extra = extraKeyController.text.replaceAll(" ", "");
    if (extra.length == 32) {
      add(localizations.custom_key, hexToBytes(extra));
    }

    for (final entry in mfUltralightCKnownKeys) {
      add(entry.$1, hexToBytes(entry.$2));
    }

    if (selectedDictionaryId != null) {
      final dict = appState.sharedPreferencesProvider
          .getDictionaries(keyLength: 32)
          .where((d) => d.id == selectedDictionaryId)
          .firstOrNull;
      if (dict != null) {
        for (final key in dict.keys) {
          add(dict.name, key);
        }
      }
    }

    return candidates;
  }

  Future<void> _startCheck() async {
    var appState = context.read<ChameleonGUIState>();
    var localizations = AppLocalizations.of(context)!;

    final candidates = _buildCandidates(appState, localizations);
    if (candidates.isEmpty) return;

    setState(() {
      isProcessing = true;
      currentKeyIndex = 0;
      totalKeys = candidates.length;
      foundKey = null;
      currentKey = null;
    });

    try {
      if (!await appState.communicator!.isReaderDeviceMode()) {
        await appState.communicator!.setReaderDeviceMode(true);
      }

      if (await appState.communicator!.scan14443aTag() == null) {
        setState(() => isProcessing = false);
        if (mounted) {
          showFailureDialog(localizations, localizations.no_card_found);
        }
        return;
      }

      for (int i = 0; i < candidates.length; i++) {
        if (!isProcessing) break;

        setState(() {
          currentKeyIndex = i + 1;
          currentKey = bytesToHexSpace(candidates[i].$2);
        });

        bool ok = false;
        try {
          ok = await appState.communicator!.mf0UlcAuth(candidates[i].$2);
        } catch (_) {
          ok = false;
        }

        if (ok) {
          setState(() {
            foundKey = bytesToHex(candidates[i].$2);
            isProcessing = false;
          });
          if (mounted) {
            showSuccessDialog(
                localizations, candidates[i].$1, foundKey!);
          }
          return;
        }
      }

      if (isProcessing) {
        setState(() => isProcessing = false);
        if (mounted) {
          showFailureDialog(localizations, localizations.ulc_no_key_found);
        }
      }
    } catch (e) {
      setState(() => isProcessing = false);
      if (mounted) {
        showErrorDialog(e.toString());
      }
    }
  }

  void showSuccessDialog(
      AppLocalizations localizations, String label, String key) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(localizations.ulc_key_found),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label),
              const SizedBox(height: 8),
              SelectableText(bytesToHexSpace(hexToBytes(key))),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: key));
              },
              child: Text(localizations.copy),
            ),
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text(localizations.ok),
            ),
          ],
        );
      },
    );
  }

  void showFailureDialog(AppLocalizations localizations, String message) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(localizations.ulc_no_key_found),
          content: Text(message),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text(localizations.ok),
            ),
          ],
        );
      },
    );
  }

  void showErrorDialog(String error) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return ErrorPage(errorMessage: error);
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    var appState = context.watch<ChameleonGUIState>();
    var localizations = AppLocalizations.of(context)!;

    final dictionaries =
        appState.sharedPreferencesProvider.getDictionaries(keyLength: 32);

    return AlertDialog(
      title: Text(localizations.ulc_key_check),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              localizations.ulc_key_check_description,
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: extraKeyController,
              enabled: !isProcessing,
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                labelText: localizations.ulc_extra_key,
                hintText: localizations.ulc_extra_key_hint,
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              ),
              inputFormatters: hexFormatter,
              validator: (value) => validateHex(value, localizations,
                  exactBytes: 16, fieldName: localizations.key),
              onChanged: (_) => setState(() {}),
            ),
            const SizedBox(height: 16),
            if (dictionaries.isNotEmpty) ...[
              Text(
                localizations.ulc_optional_dictionary,
                style: Theme.of(context).textTheme.titleSmall,
              ),
              const SizedBox(height: 8),
              DropdownButtonFormField<String>(
                initialValue: selectedDictionaryId,
                isExpanded: true,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  contentPadding:
                      EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                ),
                hint: Text(localizations.none),
                items: [
                  DropdownMenuItem<String>(
                    value: null,
                    child: Text(localizations.none),
                  ),
                  ...dictionaries.map((dictionary) {
                    return DropdownMenuItem<String>(
                      value: dictionary.id,
                      child: Text(dictionary.name),
                    );
                  }),
                ],
                onChanged: isProcessing
                    ? null
                    : (value) => setState(() => selectedDictionaryId = value),
              ),
              const SizedBox(height: 16),
            ],
            if (isProcessing) ...[
              LinearProgressIndicator(
                value: totalKeys > 0 ? currentKeyIndex / totalKeys : null,
              ),
              const SizedBox(height: 8),
              Text('$currentKeyIndex / $totalKeys'),
              if (currentKey != null) ...[
                const SizedBox(height: 4),
                Text('${localizations.trying_password}: $currentKey'),
              ],
            ],
          ],
        ),
      ),
      actions: [
        if (isProcessing)
          TextButton(
            onPressed: () => setState(() => isProcessing = false),
            child: Text(localizations.cancel),
          )
        else ...[
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(localizations.cancel),
          ),
          ElevatedButton(
            onPressed: _startCheck,
            child: Text(localizations.ulc_start_key_check),
          ),
        ],
      ],
    );
  }
}
