import 'dart:typed_data';

import 'package:chameleonultragui/helpers/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/general.dart';
import 'package:chameleonultragui/helpers/mifare_ultralight/ulc.dart';
import 'package:chameleonultragui/helpers/nfc_manufacturers.dart';
import 'package:flutter_test/flutter_test.dart';

/// Builds a list of [count] zeroed 4-byte pages.
List<Uint8List> blankPages(int count) =>
    List.generate(count, (_) => Uint8List(4));

void main() {
  group('nfcManufacturerName', () {
    test('decodes known manufacturer IDs', () {
      expect(nfcManufacturerName(0x04), 'NXP Semiconductors');
      expect(nfcManufacturerName(0x02), 'STMicroelectronics');
      expect(nfcManufacturerName(0x05), 'Infineon Technologies');
    });

    test('returns null for unknown IDs', () {
      expect(nfcManufacturerName(0xFE), isNull);
      expect(nfcManufacturerName(0x00), isNull);
    });
  });

  group('mfUltralightSwapUlcKeyOrder', () {
    test('NXP default auth-order key maps to the BREAKMEIFYOUCAN! card order',
        () {
      final authOrder = hexToBytes('49454d4b41455242214e4143554f5946');
      final cardOrder = mfUltralightSwapUlcKeyOrder(authOrder);
      // "BREAKMEIFYOUCAN!" in ASCII hex.
      expect(bytesToHex(cardOrder), '425245414b4d454946594f5543414e21');
    });

    test('swapping twice is the identity', () {
      final key = hexToBytes('000102030405060708090a0b0c0d0e0f');
      final twice = mfUltralightSwapUlcKeyOrder(
          mfUltralightSwapUlcKeyOrder(key));
      expect(bytesToHex(twice), bytesToHex(key));
    });

    test('leaves non 16-byte input untouched', () {
      final short = Uint8List.fromList([1, 2, 3, 4]);
      expect(mfUltralightSwapUlcKeyOrder(short), short);
    });
  });

  group('mfUltralightCKnownKeyBytes', () {
    test('every built-in key is exactly 16 bytes', () {
      for (final key in mfUltralightCKnownKeyBytes()) {
        expect(key.length, 16);
      }
    });

    test('includes the NXP factory key first', () {
      expect(bytesToHex(mfUltralightCKnownKeyBytes().first),
          '49454d4b41455242214e4143554f5946');
    });
  });

  group('ulcDecodeConfig', () {
    test('returns null when the dump is too short', () {
      expect(ulcDecodeConfig(blankPages(0x20)), isNull);
    });

    test('AUTH0 >= 0x30 means protection disabled', () {
      final pages = blankPages(0x30);
      pages[0x2A] = Uint8List.fromList([0x30, 0, 0, 0]);
      final config = ulcDecodeConfig(pages)!;
      expect(config.auth0, 0x30);
      expect(config.protectionDisabled, isTrue);
    });

    test('AUTH0 low value means protection enabled from that page', () {
      final pages = blankPages(0x30);
      pages[0x2A] = Uint8List.fromList([0x04, 0, 0, 0]);
      final config = ulcDecodeConfig(pages)!;
      expect(config.auth0, 0x04);
      expect(config.protectionDisabled, isFalse);
    });

    test('AUTH1 bit 0 selects the protection mode', () {
      final rw = blankPages(0x30);
      rw[0x2B] = Uint8List.fromList([0x00, 0, 0, 0]);
      expect(ulcDecodeConfig(rw)!.protectionMode,
          UlcProtectionMode.readAndWrite);

      final wo = blankPages(0x30);
      wo[0x2B] = Uint8List.fromList([0x01, 0, 0, 0]);
      expect(ulcDecodeConfig(wo)!.protectionMode, UlcProtectionMode.writeOnly);
    });

    test('counter is read little-endian from page 0x29', () {
      final pages = blankPages(0x30);
      pages[0x29] = Uint8List.fromList([0x34, 0x12, 0, 0]);
      expect(ulcDecodeConfig(pages)!.counter, 0x1234);
    });

    test('static lock bytes map to the right pages (3..15)', () {
      final pages = blankPages(0x30);
      // byte2 bit3 -> page 3, byte3 bit (15-8)=7 -> page 15.
      pages[0x02] = Uint8List.fromList([0x00, 0x00, 0x08, 0x80]);
      final locked = ulcDecodeConfig(pages)!.staticLockedPages;
      expect(locked, containsAll(<int>[3, 15]));
      expect(locked, isNot(contains(4)));
    });

    test('dynamic lock bytes map to pages 16..', () {
      final pages = blankPages(0x30);
      // byte0 bits 0,1 -> pages 16, 17.
      pages[0x28] = Uint8List.fromList([0x03, 0x00, 0, 0]);
      expect(ulcDecodeConfig(pages)!.dynamicLockedPages, [16, 17]);
    });
  });
}
