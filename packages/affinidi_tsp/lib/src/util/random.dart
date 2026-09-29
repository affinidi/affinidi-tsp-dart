import 'dart:math';
import 'dart:typed_data';

final Random _secure = Random.secure();

/// Returns [length] bytes from the platform's cryptographically secure RNG.
Uint8List secureRandomBytes(int length) {
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = _secure.nextInt(256);
  }
  return out;
}
