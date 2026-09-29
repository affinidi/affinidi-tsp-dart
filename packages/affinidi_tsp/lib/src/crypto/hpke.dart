import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';
import '../keys/keys.dart';
import '../util/bytes.dart';
import 'chacha20_poly1305.dart';
import 'hkdf.dart';

/// The HPKE key schedule output for one context.
final class HpkeKeySchedule {
  /// Creates a key schedule result.
  const HpkeKeySchedule({
    required this.key,
    required this.baseNonce,
    required this.exporterSecret,
  });

  /// The AEAD key.
  final Uint8List key;

  /// The AEAD base nonce.
  final Uint8List baseNonce;

  /// The exporter secret.
  final Uint8List exporterSecret;
}

/// The result of a single-shot HPKE seal.
final class HpkeSealed {
  /// Creates a seal result.
  const HpkeSealed({required this.enc, required this.ciphertext});

  /// The encapsulated key.
  final Uint8List enc;

  /// The AEAD ciphertext with its tag appended.
  final Uint8List ciphertext;
}

/// RFC 9180 HPKE in Base mode with HKDF-SHA256 (`0x0001`) and
/// ChaCha20Poly1305 (`0x0003`), over any KEM supplied through
/// [TspEncryptionKey] / [TspDecryptionKey].
abstract final class Hpke {
  /// `mode_base`.
  static const int modeBase = 0x00;

  /// KDF id of HKDF-SHA256.
  static const int kdfId = 0x0001;

  /// AEAD id of ChaCha20Poly1305.
  static const int aeadId = 0x0003;

  static final Uint8List _version = Uint8List.fromList(ascii.encode('HPKE-v1'));

  /// Two-byte big-endian encoding of [n].
  static Uint8List i2osp2(int n) =>
      Uint8List.fromList([(n >> 8) & 0xff, n & 0xff]);

  /// `suite_id = "KEM" ‖ I2OSP(kem_id, 2)`, used inside a KEM.
  static Uint8List kemSuiteId(int kemId) =>
      concatBytes([ascii.encode('KEM'), i2osp2(kemId)]);

  /// `suite_id = "HPKE" ‖ kem_id ‖ kdf_id ‖ aead_id`, used by the schedule.
  static Uint8List suiteId(int kemId) => concatBytes([
    ascii.encode('HPKE'),
    i2osp2(kemId),
    i2osp2(kdfId),
    i2osp2(aeadId),
  ]);

  /// RFC 9180 §4 `LabeledExtract`.
  static Uint8List labeledExtract(
    List<int> suiteId,
    List<int> salt,
    String label,
    List<int> ikm,
  ) => HkdfSha256.extract(
    salt,
    concatBytes([_version, suiteId, ascii.encode(label), ikm]),
  );

  /// RFC 9180 §4 `LabeledExpand`.
  static Uint8List labeledExpand(
    List<int> suiteId,
    List<int> prk,
    String label,
    List<int> info,
    int length,
  ) => HkdfSha256.expand(
    prk,
    concatBytes([i2osp2(length), _version, suiteId, ascii.encode(label), info]),
    length,
  );

  /// RFC 9180 §5.1 `KeySchedule` for Base mode (no PSK).
  static HpkeKeySchedule keySchedule({
    required int kemId,
    required List<int> sharedSecret,
    required List<int> info,
  }) {
    final sid = suiteId(kemId);
    const empty = <int>[];
    final pskIdHash = labeledExtract(sid, empty, 'psk_id_hash', empty);
    final infoHash = labeledExtract(sid, empty, 'info_hash', info);
    final context = concatBytes([
      [modeBase],
      pskIdHash,
      infoHash,
    ]);
    final secret = labeledExtract(sid, sharedSecret, 'secret', empty);
    return HpkeKeySchedule(
      key: labeledExpand(
        sid,
        secret,
        'key',
        context,
        ChaCha20Poly1305.keyLength,
      ),
      baseNonce: labeledExpand(
        sid,
        secret,
        'base_nonce',
        context,
        ChaCha20Poly1305.nonceLength,
      ),
      exporterSecret: labeledExpand(sid, secret, 'exp', context, 32),
    );
  }

  /// Single-shot `SealBase(pkR, info, aad, pt)`.
  static Future<HpkeSealed> sealBase({
    required TspEncryptionKey recipient,
    required List<int> info,
    required List<int> aad,
    required List<int> plaintext,
    Uint8List? ephemeral,
  }) async {
    final encapsulation = await recipient.encapsulate(ephemeral: ephemeral);
    final schedule = keySchedule(
      kemId: recipient.kem.id,
      sharedSecret: encapsulation.sharedSecret,
      info: info,
    );
    final ct = await ChaCha20Poly1305.seal(
      key: schedule.key,
      nonce: schedule.baseNonce,
      aad: aad,
      plaintext: plaintext,
    );
    return HpkeSealed(enc: encapsulation.enc, ciphertext: ct);
  }

  /// Single-shot `OpenBase(enc, skR, info, aad, ct)`.
  static Future<Uint8List> openBase({
    required TspDecryptionKey recipient,
    required Uint8List enc,
    required List<int> info,
    required List<int> aad,
    required List<int> ciphertext,
  }) async {
    if (enc.length != recipient.kem.encLength) {
      throw TspDecryptionException(
        'encapsulated key is ${enc.length} bytes, expected ${recipient.kem.encLength}',
      );
    }
    final sharedSecret = await recipient.decapsulate(enc);
    final schedule = keySchedule(
      kemId: recipient.kem.id,
      sharedSecret: sharedSecret,
      info: info,
    );
    return ChaCha20Poly1305.open(
      key: schedule.key,
      nonce: schedule.baseNonce,
      aad: aad,
      ciphertextAndTag: ciphertext,
    );
  }
}
