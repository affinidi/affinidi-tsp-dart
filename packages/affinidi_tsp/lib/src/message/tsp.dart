import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../cesr/cesr.dart';
import '../cesr/tsp_codes.dart';
import '../crypto/digest.dart';
import '../crypto/hpke.dart';
import '../crypto/sealed_box.dart';
import '../errors.dart';
import '../keys/keys.dart';
import 'frame.dart';
import 'model.dart';

/// Parsed, unverified structure of a message's envelope and body.
final class _Parsed {
  _Parsed({
    required this.version,
    required this.sender,
    required this.receiver,
    required this.fieldsStart,
    required this.fieldsEnd,
    required this.contentEnd,
    required this.scheme,
    required this.bodyStart,
    required this.bodyEnd,
    required this.signature,
  });

  final TspVersion version;
  final String sender;
  final String? receiver;
  final int fieldsStart;
  final int fieldsEnd;
  final int contentEnd;
  final TspScheme scheme;

  /// Ciphertext content range for confidential schemes; the `-Z` frame range
  /// for signed-only.
  final int bodyStart;
  final int bodyEnd;
  final DecodedSignature signature;
}

/// Low-level TSP Rev 3 message operations over raw keys.
///
/// ```dart
/// final packed = await Tsp.pack(
///   sender: alice,              // PrivateVid
///   receiver: bob,              // PublicVid
///   payload: ScsPayload(utf8.encode('hello world')),
/// );
/// final message = await Tsp.open(packed.bytes, receiver: bobPrivate, sender: alicePublic);
/// ```
abstract final class Tsp {
  /// Leading byte of a message framed with a short `-E##` count code.
  static const int magicByte = 0xf8;

  /// Leading byte of a message framed with a long `--E#####` count code
  /// (messages over about 12 KB).
  static const int magicByteLong = 0xfb;

  /// Cheap ingress classifier: whether [bytes] start like a binary TSP
  /// message. DIDComm (JSON or compact JWS) never starts with either byte.
  /// This does not validate anything; use [peek] or [open] for that.
  static bool looksLikeTsp(List<int> bytes) =>
      bytes.isNotEmpty &&
      (bytes.first == magicByte || bytes.first == magicByteLong);

  /// Packs [payload] from [sender] to [receiver] under [scheme].
  ///
  /// Returns the wire bytes and, for an invite or accept, the self-addressing
  /// digest the library computed.
  static Future<PackedTspMessage> pack({
    required PrivateVid sender,
    required PublicVid receiver,
    required TspPayload payload,
    TspScheme scheme = TspScheme.hpkeBase,
    TspPackOptions options = const TspPackOptions(),
  }) => _pack(
    sender: sender,
    receiver: receiver,
    payload: payload,
    scheme: scheme,
    options: options,
  );

  /// Packs a test vector using fixed encryption randomness.
  ///
  /// Reusing [ephemeral] for production messages breaks confidentiality and
  /// integrity. This API exists only to reproduce published test vectors.
  @visibleForTesting
  static Future<PackedTspMessage> packForTestVector({
    required PrivateVid sender,
    required PublicVid receiver,
    required TspPayload payload,
    required Uint8List ephemeral,
    TspScheme scheme = TspScheme.hpkeBase,
    TspPackOptions options = const TspPackOptions(),
  }) => _pack(
    sender: sender,
    receiver: receiver,
    payload: payload,
    scheme: scheme,
    options: options,
    ephemeral: ephemeral,
  );

  static Future<PackedTspMessage> _pack({
    required PrivateVid sender,
    required PublicVid receiver,
    required TspPayload payload,
    required TspScheme scheme,
    required TspPackOptions options,
    Uint8List? ephemeral,
  }) async {
    final limits = options.limits;
    checkPayloadAllowed(payload, scheme);

    final String? payloadSender;
    switch (options.payloadSender) {
      case PayloadSenderMode.schemeDefault:
        payloadSender = scheme == TspScheme.sealedBox ? sender.id : null;
      case PayloadSenderMode.nullVid:
        if (scheme == TspScheme.sealedBox) {
          throw const TspInvalidInputException(
            'the sealed box requires the ESSR sender VID in the payload (§8.3)',
          );
        }
        payloadSender = null;
      case PayloadSenderMode.present:
        payloadSender = sender.id;
    }

    final digestAlgorithm = scheme == TspScheme.sealedBox
        ? TspDigestAlgorithm.blake2b256
        : TspDigestAlgorithm.sha256;

    final fields = encodeEnvelopeFields(
      sender.id,
      options.nullReceiver ? null : receiver.id,
      limits,
    );
    final encoded = await encodePayloadFrame(
      payload: payload,
      envelopeFields: fields,
      payloadSender: payloadSender,
      digestAlgorithm: digestAlgorithm,
      limits: limits,
    );

    final Uint8List body;
    switch (scheme) {
      case TspScheme.signedOnly:
        body = encoded.frame;
      case TspScheme.hpkeBase:
        final key = receiver.encryptionKey;
        if (key == null) {
          throw TspInvalidInputException(
            'receiver ${receiver.id} has no encryption key',
          );
        }
        final sealed = await Hpke.sealBase(
          recipient: key,
          info: TspCodes.hpkeInfo,
          aad: fields,
          plaintext: encoded.frame,
          ephemeral: ephemeral,
        );
        body =
            (CesrWriter()..variable(TspCodes.hpkeBaseCiphertext, [
                  ...sealed.enc,
                  ...sealed.ciphertext,
                ]))
                .takeBytes();
      case TspScheme.sealedBox:
        final key = receiver.encryptionKey;
        if (key == null) {
          throw TspInvalidInputException(
            'receiver ${receiver.id} has no encryption key',
          );
        }
        if (key.kem != TspKem.x25519) {
          throw const TspUnsupportedException(
            'the sealed box is defined only for X25519 encryption keys',
          );
        }
        if (ephemeral != null && ephemeral.length != 32) {
          throw const TspInvalidInputException(
            'sealed box skEm must be 32 bytes',
          );
        }
        final ct = SealedBox.seal(
          encoded.frame,
          key.bytes,
          ephemeralSecretKey: ephemeral,
        );
        body = (CesrWriter()..variable(TspCodes.sealedBoxCiphertext, ct))
            .takeBytes();
    }

    final signable =
        (CesrWriter()
              ..count(TspCodes.envelope, (fields.length + body.length) ~/ 3)
              ..raw(fields)
              ..raw(body))
            .takeBytes();
    final signature = await sender.signingKey.sign(signable);
    final out =
        (CesrWriter()
              ..raw(signable)
              ..raw(
                encodeSignatureAttachment(
                  sender.signingKey.algorithm,
                  signature,
                ),
              ))
            .takeBytes();
    if (out.length > limits.maxMessageLength) {
      throw TspInvalidInputException(
        'message of ${out.length} bytes exceeds the limit of ${limits.maxMessageLength}',
      );
    }
    return PackedTspMessage(bytes: out, digest: encoded.said);
  }

  /// Reads the envelope of [message] without any keys: what an intermediary
  /// can see. The sender is **not** authenticated.
  static TspEnvelopeInfo peek(
    Uint8List message, {
    TspLimits limits = TspLimits.defaults,
  }) {
    final p = _guard(() => _parse(message, limits));
    return TspEnvelopeInfo(
      version: p.version,
      sender: p.sender,
      receiver: p.receiver,
      scheme: p.scheme,
    );
  }

  /// Verifies and opens [message] sent by [sender] to [receiver].
  ///
  /// Checks, in order: framing and version; that the envelope names [sender]
  /// and [receiver]; the signature; decryption (with the envelope as aad); the
  /// ESSR sender field; and every self-addressing digest. A nested or routed
  /// payload's inner message is returned unopened.
  static Future<TspMessage> open(
    Uint8List message, {
    required PrivateVid receiver,
    required PublicVid sender,
    TspLimits limits = TspLimits.defaults,
  }) => _guardAsync(() async {
    final p = _parse(message, limits);

    if (p.sender != sender.id) {
      throw const TspSenderException(
        'the envelope sender is not the expected sender',
      );
    }
    if (p.receiver != null && p.receiver != receiver.id) {
      throw const TspReceiverException(
        'the message is not addressed to this receiver',
      );
    }

    if (p.signature.algorithm != sender.verificationKey.algorithm) {
      throw const TspSignatureException(
        "the signature algorithm does not match the sender's key type",
      );
    }
    final signable = Uint8List.sublistView(message, 0, p.contentEnd);
    if (!await sender.verificationKey.verify(signable, p.signature.signature)) {
      throw const TspSignatureException(
        'the message signature does not verify',
      );
    }

    final fields = Uint8List.fromList(
      Uint8List.sublistView(message, p.fieldsStart, p.fieldsEnd),
    );
    final body = Uint8List.sublistView(message, p.bodyStart, p.bodyEnd);
    Uint8List plaintext;
    TspKem? kem;
    switch (p.scheme) {
      case TspScheme.signedOnly:
        plaintext = body;
      case TspScheme.hpkeBase:
        final key = receiver.decryptionKey;
        if (key == null) {
          throw TspUnsupportedException(
            'receiver ${receiver.id} has no decryption key',
          );
        }
        kem = key.kem;
        if (body.length < key.kem.encLength + 16) {
          throw const TspDecryptionException('HPKE ciphertext is truncated');
        }
        plaintext = await Hpke.openBase(
          recipient: key,
          enc: Uint8List.fromList(
            Uint8List.sublistView(body, 0, key.kem.encLength),
          ),
          info: TspCodes.hpkeInfo,
          aad: fields,
          ciphertext: Uint8List.sublistView(body, key.kem.encLength),
        );
      case TspScheme.sealedBox:
        final key = receiver.decryptionKey;
        if (key is! X25519KeyAgreement) {
          throw const TspUnsupportedException(
            'the sealed box requires an X25519 key-agreement decryption key',
          );
        }
        plaintext = await SealedBox.open(
          Uint8List.fromList(body),
          key as X25519KeyAgreement,
        );
    }

    final decoded = decodePayloadFrame(
      plaintext: plaintext,
      envelopeFields: fields,
      envelopeSender: p.sender,
      limits: limits,
    );
    if (p.scheme == TspScheme.sealedBox && decoded.payloadSender == null) {
      throw const TspSenderException(
        'a sealed-box payload must carry the ESSR sender VID (§8.3)',
      );
    }
    if (decoded.payload is HopPayload && p.scheme == TspScheme.signedOnly) {
      throw const TspMalformedException(
        'a nested or routed message must be confidential (§4.1)',
      );
    }
    return TspMessage(
      version: p.version,
      sender: p.sender,
      receiver: p.receiver,
      scheme: p.scheme,
      kem: kem,
      payloadSender: decoded.payloadSender,
      payload: decoded.payload,
    );
  });

  /// Verifies the `Signature_new` of a referral decoded by [open].
  ///
  /// Not done during [open]: it needs the key of the VID being introduced,
  /// which has to be resolved first. Until it is verified a referral says only
  /// that the sender *wishes* to introduce the VID.
  static Future<bool> verifyReferral(
    TspMessage message,
    TspVerificationKey newVidKey,
  ) {
    final payload = message.payload;
    if (payload is! RfiPayload) {
      throw const TspInvalidInputException('the message is not an invite');
    }
    return verifyReferralSignature(
      invite: payload,
      payloadSender: message.payloadSender,
      verificationKey: newVidKey,
    );
  }

  static _Parsed _parse(Uint8List message, TspLimits limits) {
    if (message.length > limits.maxMessageLength) {
      throw TspMalformedException(
        'message of ${message.length} bytes exceeds the limit of ${limits.maxMessageLength}',
      );
    }
    final r = CesrReader(message);
    final content = r.readGroup(TspCodes.envelope, 'envelope');
    final fieldsStart = content.pos;
    if (content.remaining < 6 ||
        message[content.pos] != TspCodes.ytsp[0] ||
        message[content.pos + 1] != TspCodes.ytsp[1] ||
        message[content.pos + 2] != TspCodes.ytsp[2]) {
      throw const TspMalformedException('missing YTSP version marker');
    }
    content.pos += 3;
    final vw =
        message[content.pos] << 16 |
        message[content.pos + 1] << 8 |
        message[content.pos + 2];
    if (vw >> 18 != Cesr.dash) {
      throw const TspMalformedException('malformed version code');
    }
    content.pos += 3;
    final version = TspVersion((vw >> 12) & 0x3f, vw & 0xfff);
    if (version.major != TspVersion.current.major ||
        version.minor < TspVersion.current.minor) {
      throw TspVersionException('unsupported TSP version $version');
    }

    final senderBytes = content.readVariable(
      TspCodes.bytes,
      'sender VID',
      maxLength: limits.maxVidLength,
    );
    if (senderBytes.isEmpty) {
      throw const TspMalformedException('the envelope sender is the NULL VID');
    }
    final receiverBytes = content.readVariable(
      TspCodes.bytes,
      'receiver VID',
      maxLength: limits.maxVidLength,
    );
    final fieldsEnd = content.pos;

    final String sender;
    final String? receiver;
    try {
      sender = utf8.decode(senderBytes);
      receiver = receiverBytes.isEmpty ? null : utf8.decode(receiverBytes);
    } on FormatException catch (e) {
      throw TspMalformedException('envelope VID is not valid UTF-8', cause: e);
    }

    final TspScheme scheme;
    final int bodyStart;
    final int bodyEnd;
    final id = content.peekVariableIdentifier();
    if (id == TspCodes.hpkeBaseCiphertext ||
        id == TspCodes.sealedBoxCiphertext) {
      scheme = id == TspCodes.hpkeBaseCiphertext
          ? TspScheme.hpkeBase
          : TspScheme.sealedBox;
      final range = content.readVariableRange(
        id!,
        'ciphertext',
        maxLength: limits.maxMessageLength,
      );
      bodyStart = range.start;
      bodyEnd = range.end;
      content.expectEnd('envelope');
    } else if (content.peekCount(TspCodes.payload)) {
      scheme = TspScheme.signedOnly;
      bodyStart = content.pos;
      content.readGroup(TspCodes.payload, 'payload frame');
      content.expectEnd('envelope');
      bodyEnd = content.pos;
    } else {
      throw const TspMalformedException(
        'expected a ciphertext or payload frame',
      );
    }

    final signature = decodeSignatureAttachment(r, 'message');
    r.expectEnd('message');

    return _Parsed(
      version: version,
      sender: sender,
      receiver: receiver,
      fieldsStart: fieldsStart,
      fieldsEnd: fieldsEnd,
      contentEnd: content.end,
      scheme: scheme,
      bodyStart: bodyStart,
      bodyEnd: bodyEnd,
      signature: signature,
    );
  }

  static T _guard<T>(T Function() f) {
    try {
      return f();
    } on TspException {
      rethrow;
    } on Object catch (e) {
      throw TspMalformedException('unparseable message', cause: e);
    }
  }

  static Future<T> _guardAsync<T>(Future<T> Function() f) async {
    try {
      return await f();
    } on TspException {
      rethrow;
    } on Object catch (e) {
      throw TspMalformedException('message could not be processed', cause: e);
    }
  }
}
