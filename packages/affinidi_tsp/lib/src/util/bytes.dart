import 'dart:convert';
import 'dart:typed_data';

/// Concatenates [parts] into a single new buffer.
Uint8List concatBytes(List<List<int>> parts) {
  var total = 0;
  for (final p in parts) {
    total += p.length;
  }
  final out = Uint8List(total);
  var at = 0;
  for (final p in parts) {
    out.setAll(at, p);
    at += p.length;
  }
  return out;
}

/// Compares [a] and [b] in time that depends only on their lengths.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Lexicographic byte comparison: negative if [a] sorts before [b].
int compareBytes(List<int> a, List<int> b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length - b.length;
}

/// Encodes [bytes] as unpadded base64url (RFC 4648 §5).
String base64UrlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Decodes unpadded (or padded) base64url.
///
/// Throws [FormatException] on invalid input.
Uint8List base64UrlDecodeLenient(String input) {
  final s = input.replaceAll('=', '');
  if (s.length % 4 == 1) {
    throw const FormatException('invalid base64url length');
  }
  final padded = s.padRight(s.length + (4 - s.length % 4) % 4, '=');
  return base64Url.decode(padded);
}

/// Fills a new buffer of [length] bytes with [value].
Uint8List filledBytes(int length, int value) =>
    Uint8List(length)..fillRange(0, length, value);
