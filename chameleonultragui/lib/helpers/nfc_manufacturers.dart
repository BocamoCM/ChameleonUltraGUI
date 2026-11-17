// Manufacturer lookup for ISO/IEC 14443 tags.
//
// The first byte of a 7-byte UID (and of a single/double UID's cascade) encodes
// the chip manufacturer, per ISO/IEC 7816-6 / the registered RID list. This is
// the same decode Proxmark3 prints as "Manufacturer" in `hf 14a info`.
//
// Only a subset relevant to HF 13.56 MHz tags is listed; unknown IDs return
// null so the caller can show the raw byte instead.

const Map<int, String> _nfcManufacturers = {
  0x02: 'STMicroelectronics',
  0x04: 'NXP Semiconductors',
  0x05: 'Infineon Technologies',
  0x07: 'Texas Instruments',
  0x08: 'Fujitsu',
  0x09: 'Matsushita (Panasonic)',
  0x0A: 'NEC',
  0x0B: 'Oki Electric',
  0x0C: 'Toshiba',
  0x0D: 'Mitsubishi Electric',
  0x16: 'EM Microelectronic-Marin',
  0x1D: 'Innovatron (ASK)',
  0x21: 'EM Microelectronic-Marin',
  0x28: 'LG-Semiconductors',
  0x29: 'Shanghai Fudan Microelectronics',
  0x2B: 'Shanghai Fudan Microelectronics',
  0x33: 'AuthenTec',
  0x57: 'Shenzhen Huada (HED)',
};

/// Returns the manufacturer name for a UID's first byte, or null if unknown.
String? nfcManufacturerName(int uidFirstByte) {
  return _nfcManufacturers[uidFirstByte];
}
