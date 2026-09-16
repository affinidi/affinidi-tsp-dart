import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';

/// Decodes unpadded base64url (the qb64 text domain transcodes to binary).
Uint8List b64(String s) =>
    base64Url.decode(s.padRight(s.length + (4 - s.length % 4) % 4, '='));

/// The Rev 3 Appendix A fixture.
final class SpecVectors {
  SpecVectors._(this.identifiers, this.vectors);

  factory SpecVectors.load([String path = 'test/fixtures/spec-vectors.json']) {
    final json = jsonDecode(File(path).readAsStringSync()) as Map<String, Object?>;
    return SpecVectors._(
      (json['identifiers']! as Map<String, Object?>).cast<String, Map<String, Object?>>(),
      (json['vectors']! as Map<String, Object?>).cast<String, Map<String, Object?>>(),
    );
  }

  final Map<String, Map<String, Object?>> identifiers;
  final Map<String, Map<String, Object?>> vectors;

  String id(String name) => identifiers[name]!['id']! as String;

  PrivateVid privateVid(String name) {
    final i = identifiers[name]!;
    return PrivateVid(
      id: i['id']! as String,
      signingKey: Ed25519SigningKey.fromSeed(b64(i['skS']! as String)),
      decryptionKey: X25519DecryptionKey.fromSecret(b64(i['skE']! as String)),
    );
  }

  PublicVid publicVid(String name) {
    final i = identifiers[name]!;
    return PublicVid(
      id: i['id']! as String,
      verificationKey: Ed25519VerificationKey(b64(i['pkS']! as String)),
      encryptionKey: X25519EncryptionKey(b64(i['pkE']! as String)),
    );
  }
}
