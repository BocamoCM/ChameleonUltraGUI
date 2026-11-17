import 'package:chameleonultragui/helpers/general.dart';
import 'package:flutter/services.dart';

// Helpers specific to MIFARE Ultralight C (MF0ICU2).
//
// Memory map (48 pages of 4 bytes):
//   0x00-0x01  UID
//   0x02       BCC1 / internal / static lock bytes (bytes 2-3, lock pages 0x03-0x0F)
//   0x03       OTP
//   0x04-0x27  user data (36 pages)
//   0x28       dynamic lock bytes (bytes 0-1, lock pages 0x10-0x2B)
//   0x29       16-bit one-way counter (bytes 0-1, little endian)
//   0x2A       AUTH0 (byte 0): first page that requires authentication
//   0x2B       AUTH1 (byte 0, bit 0): 0 = read+write protected, 1 = write-only protected
//   0x2C-0x2F  3DES authentication key (write-only), stored in "card order"
//
// References:
//   https://www.nxp.com/docs/en/data-sheet/MF0ICU2.pdf

/// Common MIFARE Ultralight C 3DES keys, listed in *authentication* byte order
/// (the order the firmware feeds straight into the DES engine).
///
/// Many tools store the key with the two 8-byte halves reversed, so the on-card
/// page order and the auth order differ. The key-check tool tries each of these
/// in *both* orders, so it does not matter which convention a given tag used.
///
/// Sources: NXP MF0ICU2 data sheet, Proxmark3 `default_3des_keys`, libnfc.
/// Entries are `(label, 16-byte hex)`.
const List<(String, String)> mfUltralightCKnownKeys = [
  // NXP factory / transport key. On the card this reads as the ASCII string
  // "BREAKMEIFYOUCAN!"; in auth order each 8-byte half is byte-reversed.
  ('NXP default (BREAKMEIFYOUCAN!)', '49454d4b41455242214e4143554f5946'),
  // Same key in the other (on-card ASCII) order, in case a tag/tool used it.
  ('NXP default (card order)', '425245414b4d454946594f5543414e21'),
  // All zero / all FF are common after a careless or failed key change.
  ('All zeros', '00000000000000000000000000000000'),
  ('All FF', 'ffffffffffffffffffffffffffffffff'),
  // Incremental sample keys seen in documentation and demos.
  ('Incremental 00..0F', '000102030405060708090a0b0c0d0e0f'),
  ('Incremental 00..15', '00010203040506070809101112131415'),
  ('Incremental 10..1F', '101112131415161718191a1b1c1d1e1f'),
  // "AEBASEMUSEUMNFC\\0" — a known museum/exhibit default (Proxmark list).
  ('Museum (AEBASEMUSEUMNFC)', '4145424153454d555345554d4e464300'),
  // Other keys that have shown up in the wild / dictionaries.
  ('Ultralight-C demo 404142..', '404142434445464748494a4b4c4d4e4f'),
  ('ASCII "1234..." ', '31323334353637383132333435363738'),
];

List<Uint8List> mfUltralightCKnownKeyBytes() {
  return mfUltralightCKnownKeys
      .map((entry) => hexToBytes(entry.$2))
      .toList();
}

enum UlcProtectionMode { readAndWrite, writeOnly }

class UlcConfig {
  /// First page from which authentication is required (AUTH0, page 0x2A byte 0).
  /// Values >= 0x30 effectively disable protection.
  final int auth0;

  /// What the protection covers (AUTH1, page 0x2B byte 0 bit 0).
  final UlcProtectionMode protectionMode;

  /// 16-bit one-way counter (page 0x29, bytes 0-1, little endian).
  final int counter;

  /// Raw static lock bytes (page 0x02 bytes 2-3). Covers pages 0x03-0x0F.
  final int staticLock;

  /// Raw dynamic lock bytes (page 0x28 bytes 0-1). Covers pages 0x10-0x2B.
  final int dynamicLock;

  const UlcConfig({
    required this.auth0,
    required this.protectionMode,
    required this.counter,
    required this.staticLock,
    required this.dynamicLock,
  });

  /// True when AUTH0 points past the last real page, so nothing is protected.
  bool get protectionDisabled => auth0 >= 0x30;

  /// Pages (3..15) locked by the static lock bytes, in ascending order.
  List<int> get staticLockedPages {
    final List<int> pages = [];
    // Bit layout per MF0ICU2: byte0 (lock0) bit1->page3 ... bit7->page9,
    // byte1 (lock1) bit0->page10 ... bit7->page15. bit0 of byte0 and the two
    // low bits that map to pages 0-2 are block-locking bits, not page locks.
    for (int page = 3; page <= 15; page++) {
      if ((staticLock & (1 << page)) != 0) {
        pages.add(page);
      }
    }
    return pages;
  }

  /// Pages (16..43) locked by the dynamic lock bytes, in ascending order.
  List<int> get dynamicLockedPages {
    final List<int> pages = [];
    // Dynamic lock: byte0 bit0->pages 16-19, ... grouped. We report the
    // individual bit mapping NXP uses: bit i of the 16-bit field -> page 16+i
    // for the first 12 bits; the upper bits are block-locking bits.
    for (int i = 0; i < 12; i++) {
      if ((dynamicLock & (1 << i)) != 0) {
        pages.add(16 + i);
      }
    }
    return pages;
  }
}

/// Decodes the Ultralight C configuration pages from a dump.
///
/// [pages] is the list of 4-byte pages (index == page number). Returns null if
/// the dump is too short to contain the configuration pages.
UlcConfig? ulcDecodeConfig(List<Uint8List> pages) {
  if (pages.length < 0x2C) {
    return null;
  }

  int pageByte(int page, int offset) {
    if (page >= pages.length || pages[page].length <= offset) {
      return 0;
    }
    return pages[page][offset];
  }

  final int auth0 = pageByte(0x2A, 0);
  final int auth1 = pageByte(0x2B, 0);
  final int counter = pageByte(0x29, 0) | (pageByte(0x29, 1) << 8);
  final int staticLock = pageByte(0x02, 2) | (pageByte(0x02, 3) << 8);
  final int dynamicLock = pageByte(0x28, 0) | (pageByte(0x28, 1) << 8);

  return UlcConfig(
    auth0: auth0,
    protectionMode:
        (auth1 & 0x01) == 0 ? UlcProtectionMode.readAndWrite : UlcProtectionMode.writeOnly,
    counter: counter,
    staticLock: staticLock,
    dynamicLock: dynamicLock,
  );
}
