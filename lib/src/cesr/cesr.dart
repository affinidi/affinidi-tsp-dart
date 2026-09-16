import 'dart:typed_data';

import '../errors.dart';

/// Binary-domain (qb2) CESR primitives as used by TSP Rev 3.
///
/// TSP only ever puts CESR on the wire in its binary form. Every primitive and
/// group this library emits is quadlet-aligned: its length is a multiple of
/// three bytes, which is what makes the binary form a lossless transcode of
/// the text (qb64) form printed in the specification.
///
/// Three frame kinds are used:
///
/// * **count codes** (`-X##` / `--X#####`) open a group and carry its length
///   in quadlets;
/// * **fixed-size primitives** (`I`, `F`, `0A`, `B#`, `1AAQ`) whose code size
///   is implied by the raw length;
/// * **variable-size primitives** (`4X##`…`9AAX####`) whose code carries the
///   lead-pad size (0, 1 or 2 zero bytes) and the length.
abstract final class Cesr {
  /// Base64url index of `'-'`.
  static const int dash = 62;

  /// Base64url index of `'0'`.
  static const int d0 = 52;

  /// Largest count a short (`-X##`) count code can carry.
  static const int maxShortCount = 4095;

  /// Largest count a long (`--X#####`) count code can carry.
  static const int maxLongCount = (1 << 30) - 1;

  /// Largest quadlet count a short variable-size code (`4X##`) can carry.
  static const int maxShortVariableQuadlets = 4095;

  /// Largest quadlet count a long variable-size code (`7AAX####`) can carry.
  static const int maxLongVariableQuadlets = (1 << 24) - 1;

  /// Returns the base64url index of a single character.
  static int b64Index(int charCode) {
    if (charCode >= 0x41 && charCode <= 0x5a) return charCode - 0x41;
    if (charCode >= 0x61 && charCode <= 0x7a) return charCode - 0x61 + 26;
    if (charCode >= 0x30 && charCode <= 0x39) return charCode - 0x30 + 52;
    if (charCode == 0x2d) return 62;
    if (charCode == 0x5f) return 63;
    throw ArgumentError.value(charCode, 'charCode', 'not base64url');
  }

  /// Interprets [code] as a big-endian integer of 6-bit symbols.
  static int codeInt(String code) {
    var acc = 0;
    for (final unit in code.codeUnits) {
      acc = (acc << 6) | b64Index(unit);
    }
    return acc;
  }

  /// The three binary bytes of a four-character code such as `XSCS`.
  static Uint8List code3(String fourChars) {
    assert(fourChars.length == 4);
    final v = codeInt(fourChars);
    return Uint8List.fromList([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
  }

  /// Rounds [n] up to the next multiple of three.
  static int nextMul3(int n) => n + ((3 - n % 3) % 3);
}

/// Appends CESR primitives to a growing buffer.
final class CesrWriter {
  final BytesBuilder _out = BytesBuilder(copy: false);

  /// Number of bytes written so far.
  int get length => _out.length;

  /// Appends raw, already-framed bytes.
  void raw(List<int> bytes) => _out.add(bytes);

  /// Returns the written bytes. The writer must not be reused afterwards.
  Uint8List takeBytes() => _out.takeBytes();

  /// Writes a count code for group [identifier] (one base64url character,
  /// given as its index) carrying [count] quadlets, choosing the short form
  /// when it fits.
  void count(int identifier, int count) {
    if (count < 0 || count > Cesr.maxLongCount) {
      throw TspInvalidInputException('CESR count $count out of range');
    }
    if (count <= Cesr.maxShortCount) {
      _word((Cesr.dash << 18) | ((identifier & 0x3f) << 12) | count);
    } else {
      _word(
        (Cesr.dash << 18) |
            (Cesr.dash << 12) |
            ((identifier & 0x3f) << 6) |
            ((count >> 24) & 0x3f),
      );
      _word(count & 0xffffff);
    }
  }

  /// Writes a fixed-size primitive.
  ///
  /// The code size follows from the raw length: one character for a raw
  /// length of `3k+2` (e.g. `I`/`F` digests), two characters with a leading
  /// `0` for `3k+1` (e.g. `0A` nonces), and four characters with a leading
  /// `1` for `3k` (e.g. `1AAQ`). [identifier] carries the remaining 6 or 18
  /// bits of the code.
  void fixed(int identifier, List<int> data) {
    final hdr = Cesr.nextMul3(data.length + 1) - data.length;
    switch (hdr) {
      case 1:
        _out.addByte((identifier & 0x3f) << 2);
      case 2:
        final w = (Cesr.d0 << 18) | ((identifier & 0x3f) << 12);
        _out
          ..addByte((w >> 16) & 0xff)
          ..addByte((w >> 8) & 0xff);
      default:
        _word(((Cesr.d0 + 1) << 18) | (identifier & 0x3ffff));
    }
    _out.add(data);
  }

  /// Writes a variable-size primitive with [identifier] (the code's type
  /// character, as its base64url index; `B` for bytes/VIDs, `F` for HPKE
  /// ciphertext, `C` for sealed-box ciphertext).
  void variable(int identifier, List<int> data) {
    final padded = Cesr.nextMul3(data.length);
    final lead = padded - data.length;
    final quadlets = padded ~/ 3;
    if (quadlets <= Cesr.maxShortVariableQuadlets) {
      _word(
        ((Cesr.d0 + 4 + lead) << 18) | ((identifier & 0x3f) << 12) | quadlets,
      );
    } else if (quadlets <= Cesr.maxLongVariableQuadlets) {
      _word(((Cesr.d0 + 7 + lead) << 18) | (identifier & 0x3f));
      _word(quadlets);
    } else {
      throw TspInvalidInputException(
        'variable-size field of ${data.length} bytes exceeds the CESR limit',
      );
    }
    for (var i = 0; i < lead; i++) {
      _out.addByte(0);
    }
    _out.add(data);
  }

  void _word(int w) {
    _out
      ..addByte((w >> 16) & 0xff)
      ..addByte((w >> 8) & 0xff)
      ..addByte(w & 0xff);
  }
}

/// A bounds-checked cursor over binary CESR.
///
/// Every read either advances past a complete, canonically encoded primitive
/// or throws [TspMalformedException]; it never reads past [end].
final class CesrReader {
  /// Creates a reader over `bytes[start, end)`.
  CesrReader(this.bytes, {int start = 0, int? end})
    : pos = start,
      end = end ?? bytes.length {
    if (start < 0 || this.end > bytes.length || start > this.end) {
      throw const TspMalformedException('reader bounds out of range');
    }
  }

  /// The underlying buffer.
  final Uint8List bytes;

  /// The current read offset.
  int pos;

  /// The exclusive end offset this reader may not cross.
  final int end;

  /// Bytes remaining before [end].
  int get remaining => end - pos;

  /// Whether the reader has consumed everything up to [end].
  bool get isAtEnd => pos == end;

  int _wordAt(int at) =>
      (bytes[at] << 16) | (bytes[at + 1] << 8) | bytes[at + 2];

  void _need(int n, String what) {
    if (n < 0 || pos + n > end) {
      throw TspMalformedException('truncated $what');
    }
  }

  /// Whether a count code for [identifier] starts at the cursor.
  bool peekCount(int identifier) {
    if (remaining < 3) return false;
    final w = _wordAt(pos);
    if (w >> 18 != Cesr.dash) return false;
    final second = (w >> 12) & 0x3f;
    if (second == (identifier & 0x3f)) return true;
    return second == Cesr.dash &&
        ((w >> 6) & 0x3f) == (identifier & 0x3f) &&
        remaining >= 6;
  }

  /// Reads a count code for group [identifier] and returns its quadlet count.
  int readCount(int identifier, String what) {
    _need(3, what);
    final w = _wordAt(pos);
    if (w >> 18 != Cesr.dash) {
      throw TspMalformedException('expected $what count code');
    }
    final second = (w >> 12) & 0x3f;
    if (second == (identifier & 0x3f)) {
      pos += 3;
      return w & 0xfff;
    }
    if (second == Cesr.dash && ((w >> 6) & 0x3f) == (identifier & 0x3f)) {
      _need(6, what);
      final lo = _wordAt(pos + 3);
      pos += 6;
      return ((w & 0x3f) << 24) | lo;
    }
    throw TspMalformedException('expected $what count code');
  }

  /// Reads a count code for [identifier] and returns a sub-reader spanning
  /// exactly the group it announces, advancing past the group.
  CesrReader readGroup(int identifier, String what) {
    final quadlets = readCount(identifier, what);
    final len = quadlets * 3;
    _need(len, what);
    final sub = CesrReader(bytes, start: pos, end: pos + len);
    pos += len;
    return sub;
  }

  /// Reads a fixed-size primitive of [length] raw bytes with [identifier].
  ///
  /// Rejects a non-canonical encoding whose pad bits are not zero.
  Uint8List readFixed(int identifier, int length, String what) {
    final total = Cesr.nextMul3(length + 1);
    final hdr = total - length;
    _need(total, what);
    switch (hdr) {
      case 1:
        final b = bytes[pos];
        if (b >> 2 != (identifier & 0x3f)) {
          throw TspMalformedException('expected $what');
        }
        if (b & 0x03 != 0) {
          throw TspMalformedException('non-canonical pad bits in $what');
        }
      case 2:
        final w = (bytes[pos] << 8) | bytes[pos + 1];
        if (w >> 4 != ((Cesr.d0 << 6) | (identifier & 0x3f))) {
          throw TspMalformedException('expected $what');
        }
        if (w & 0x0f != 0) {
          throw TspMalformedException('non-canonical pad bits in $what');
        }
      default:
        if (_wordAt(pos) != (((Cesr.d0 + 1) << 18) | (identifier & 0x3ffff))) {
          throw TspMalformedException('expected $what');
        }
    }
    final out = Uint8List.fromList(
      Uint8List.sublistView(bytes, pos + hdr, pos + total),
    );
    pos += total;
    return out;
  }

  /// Whether the fixed-size code at the cursor has the one-character
  /// [identifier] (used to tell `I` from `F`).
  bool peekFixed1(int identifier) =>
      remaining >= 1 && bytes[pos] >> 2 == (identifier & 0x3f);

  /// The identifier of the variable-size primitive at the cursor, or `null`
  /// if none starts here.
  int? peekVariableIdentifier() {
    if (remaining < 3) return null;
    final w = _wordAt(pos);
    final sel = w >> 18;
    if (sel >= Cesr.d0 + 4 && sel <= Cesr.d0 + 6) return (w >> 12) & 0x3f;
    if (sel >= Cesr.d0 + 7 && sel <= Cesr.d0 + 9) {
      final id = w & 0x3ffff;
      return id <= 0x3f ? id : null;
    }
    return null;
  }

  /// Reads a variable-size primitive with [identifier], returning the offsets
  /// of its content within [bytes].
  ///
  /// [maxLength] bounds the content length before any copy is made. Rejects
  /// non-zero lead bytes.
  ({int start, int end}) readVariableRange(
    int identifier,
    String what, {
    required int maxLength,
  }) {
    _need(3, what);
    final w = _wordAt(pos);
    final sel = w >> 18;
    int lead;
    int quadlets;
    int hdr;
    if (sel >= Cesr.d0 + 4 && sel <= Cesr.d0 + 6) {
      if ((w >> 12) & 0x3f != (identifier & 0x3f)) {
        throw TspMalformedException('expected $what');
      }
      lead = sel - (Cesr.d0 + 4);
      quadlets = w & 0xfff;
      hdr = 3;
    } else if (sel >= Cesr.d0 + 7 && sel <= Cesr.d0 + 9) {
      if (w & 0x3ffff != (identifier & 0x3f)) {
        throw TspMalformedException('expected $what');
      }
      _need(6, what);
      lead = sel - (Cesr.d0 + 7);
      quadlets = _wordAt(pos + 3);
      hdr = 6;
    } else {
      throw TspMalformedException('expected $what');
    }
    final padded = quadlets * 3;
    if (padded < lead) {
      throw TspMalformedException('$what shorter than its lead pad');
    }
    if (padded - lead > maxLength) {
      throw TspMalformedException(
        '$what of ${padded - lead} bytes exceeds the limit of $maxLength',
      );
    }
    _need(hdr + padded, what);
    for (var i = 0; i < lead; i++) {
      if (bytes[pos + hdr + i] != 0) {
        throw TspMalformedException('non-zero lead byte in $what');
      }
    }
    final start = pos + hdr + lead;
    final stop = pos + hdr + padded;
    pos = stop;
    return (start: start, end: stop);
  }

  /// Reads a variable-size primitive and returns a copy of its content.
  Uint8List readVariable(
    int identifier,
    String what, {
    required int maxLength,
  }) {
    final r = readVariableRange(identifier, what, maxLength: maxLength);
    return Uint8List.fromList(Uint8List.sublistView(bytes, r.start, r.end));
  }

  /// Reads exactly [n] raw bytes.
  Uint8List readRaw(int n, String what) {
    _need(n, what);
    final out = Uint8List.fromList(Uint8List.sublistView(bytes, pos, pos + n));
    pos += n;
    return out;
  }

  /// Throws unless the reader is exactly at [end].
  void expectEnd(String what) {
    if (!isAtEnd) {
      throw TspMalformedException(
        '$remaining unexpected trailing bytes in $what',
      );
    }
  }
}
