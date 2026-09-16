import 'dart:typed_data';

import 'package:crypto/crypto.dart' as dart_crypto;

/// HKDF-SHA256 (RFC 5869), built on the `crypto` package's HMAC.
abstract final class HkdfSha256 {
  /// Output length of the underlying hash.
  static const int hashLength = 32;

  /// HKDF-Extract. An empty [salt] is replaced by a zero-filled one, as
  /// RFC 5869 §2.2 requires.
  static Uint8List extract(List<int> salt, List<int> ikm) {
    final key = salt.isEmpty ? Uint8List(hashLength) : salt;
    return Uint8List.fromList(
      dart_crypto.Hmac(dart_crypto.sha256, key).convert(ikm).bytes,
    );
  }

  /// HKDF-Expand to [length] bytes.
  static Uint8List expand(List<int> prk, List<int> info, int length) {
    if (length < 0 || length > 255 * hashLength) {
      throw ArgumentError.value(length, 'length');
    }
    final hmac = dart_crypto.Hmac(dart_crypto.sha256, prk);
    final out = Uint8List(length);
    var t = <int>[];
    var at = 0;
    for (var i = 1; at < length; i++) {
      t = hmac.convert([...t, ...info, i]).bytes;
      final take = (length - at) < t.length ? length - at : t.length;
      out.setRange(at, at + take, t);
      at += take;
    }
    return out;
  }
}
