import 'dart:convert';
import 'dart:typed_data';

import '../cesr/cesr.dart';
import '../cesr/tsp_codes.dart';
import '../crypto/digest.dart';
import '../errors.dart';
import '../keys/keys.dart';
import '../util/bytes.dart';
import '../util/random.dart';
import 'model.dart';

/// Nonce length (128 bits, §9.2).
const int nonceLength = 16;

/// Encodes a VID string as UTF-8, rejecting an over-long one.
Uint8List encodeVid(String vid, TspLimits limits) {
  final b = utf8.encode(vid);
  if (b.length > limits.maxVidLength) {
    throw TspInvalidInputException(
      'VID of ${b.length} bytes exceeds the limit of ${limits.maxVidLength}',
    );
  }
  return b;
}

String _decodeVid(Uint8List bytes, String what) {
  try {
    return utf8.decode(bytes);
  } on FormatException catch (e) {
    throw TspMalformedException('$what is not valid UTF-8', cause: e);
  }
}

/// The encoded envelope fields `TSP_Version ‖ VID_sndr ‖ VID_rcvr` — the
/// HPKE-Base aad and the leading part of every SAID input.
Uint8List encodeEnvelopeFields(
  String sender,
  String? receiver,
  TspLimits limits,
) {
  if (sender.isEmpty) {
    throw const TspInvalidInputException(
      'the envelope sender may not be empty',
    );
  }
  final w = CesrWriter()
    ..raw(TspCodes.ytsp)
    ..count(TspVersion.current.major, TspVersion.current.minor)
    ..variable(TspCodes.bytes, encodeVid(sender, limits))
    ..variable(
      TspCodes.bytes,
      receiver == null ? const [] : encodeVid(receiver, limits),
    );
  return w.takeBytes();
}

Uint8List _vidListBytes(List<String> vids, TspLimits limits) {
  if (vids.length > limits.maxHops) {
    throw TspInvalidInputException(
      'VID list of ${vids.length} entries exceeds the limit of ${limits.maxHops}',
    );
  }
  final body = CesrWriter();
  for (final v in vids) {
    if (v.isEmpty) {
      throw const TspInvalidInputException(
        'a VID list may not contain the NULL VID',
      );
    }
    body.variable(TspCodes.bytes, encodeVid(v, limits));
  }
  final content = body.takeBytes();
  return (CesrWriter()
        ..count(TspCodes.vidList, content.length ~/ 3)
        ..raw(content))
      .takeBytes();
}

Uint8List _digestField(TspDigest d) =>
    (CesrWriter()..fixed(d.algorithm.cesrIdentifier, d.bytes)).takeBytes();

Uint8List _nonceField(Uint8List nonce) =>
    (CesrWriter()..fixed(TspCodes.nonce, nonce)).takeBytes();

Uint8List _bareVidField(String vid, TspLimits limits) =>
    (CesrWriter()..variable(TspCodes.bytes, encodeVid(vid, limits)))
        .takeBytes();

Uint8List _paddingField(Uint8List padding) =>
    (CesrWriter()..variable(TspCodes.bytes, padding)).takeBytes();

/// Encodes a signature attachment: `-C## -K## <primitive>`.
Uint8List encodeSignatureAttachment(
  TspSignatureAlgorithm alg,
  Uint8List signature,
) {
  if (signature.length != alg.signatureLength) {
    throw TspInvalidInputException(
      '${alg.wireName} signature must be ${alg.signatureLength} bytes, got ${signature.length}',
    );
  }
  final prim = CesrWriter();
  switch (alg) {
    case TspSignatureAlgorithm.ed25519:
      // `B` + index 0: 12 code bits then 4 zero pad bits.
      prim
        ..raw([TspCodes.ed25519IndexedSignature << 2, 0])
        ..raw(signature);
    case TspSignatureAlgorithm.mlDsa65:
      prim.fixed(TspCodes.mlDsa65Signature, signature);
  }
  final p = prim.takeBytes();
  final k = CesrWriter()
    ..count(TspCodes.indexedSignatureGroup, p.length ~/ 3)
    ..raw(p);
  final kb = k.takeBytes();
  return (CesrWriter()
        ..count(TspCodes.attachmentGroup, kb.length ~/ 3)
        ..raw(kb))
      .takeBytes();
}

/// A decoded signature primitive.
typedef DecodedSignature = ({
  TspSignatureAlgorithm algorithm,
  Uint8List signature,
});

/// Decodes a signature attachment at the cursor, returning its first
/// signature. Every primitive in the group must be well formed.
DecodedSignature decodeSignatureAttachment(CesrReader r, String what) {
  final c = r.readGroup(TspCodes.attachmentGroup, '$what attachment group');
  final k = c.readGroup(
    TspCodes.indexedSignatureGroup,
    '$what signature group',
  );
  c.expectEnd('$what attachment group');
  DecodedSignature? first;
  while (!k.isAtEnd) {
    final DecodedSignature sig;
    if (k.remaining >= 3 &&
        (k.bytes[k.pos] << 16 | k.bytes[k.pos + 1] << 8 | k.bytes[k.pos + 2]) ==
            ((Cesr.d0 + 1) << 18 | TspCodes.mlDsa65Signature)) {
      sig = (
        algorithm: TspSignatureAlgorithm.mlDsa65,
        signature: k.readFixed(
          TspCodes.mlDsa65Signature,
          3309,
          '$what ML-DSA-65 signature',
        ),
      );
    } else if (k.remaining >= 2 &&
        k.bytes[k.pos] >> 2 == TspCodes.ed25519IndexedSignature) {
      final w = k.bytes[k.pos] << 8 | k.bytes[k.pos + 1];
      if (w & 0x0f != 0) {
        throw TspMalformedException(
          'non-canonical pad bits in $what signature',
        );
      }
      final index = (w >> 4) & 0x3f;
      k.pos += 2;
      final s = k.readRaw(64, '$what Ed25519 signature');
      if (index != 0) {
        throw TspSignatureException(
          '$what signature names key index $index; only index 0 is supported',
        );
      }
      sig = (algorithm: TspSignatureAlgorithm.ed25519, signature: s);
    } else {
      throw TspMalformedException('unsupported signature primitive in $what');
    }
    first ??= sig;
  }
  if (first == null) {
    throw TspMalformedException('empty $what signature group');
  }
  return first;
}

/// Whether [payload] may be carried under [scheme].
void checkPayloadAllowed(TspPayload payload, TspScheme scheme) {
  if (payload is HopPayload && scheme == TspScheme.signedOnly) {
    throw const TspInvalidInputException(
      'a nested or routed message must be confidential (§4.1)',
    );
  }
}

/// The encoded `-Z` payload frame and the self-addressing digest it carries.
typedef EncodedFrame = ({Uint8List frame, TspDigest? said});

/// Encodes [payload] as a `-Z` frame.
Future<EncodedFrame> encodePayloadFrame({
  required TspPayload payload,
  required Uint8List envelopeFields,
  required String? payloadSender,
  required TspDigestAlgorithm digestAlgorithm,
  required TspLimits limits,
}) async {
  if (payload.padding.length > limits.maxPaddingLength) {
    throw TspInvalidInputException(
      'padding of ${payload.padding.length} bytes exceeds the limit',
    );
  }
  final senderField =
      (CesrWriter()..variable(
            TspCodes.bytes,
            payloadSender == null ? const [] : encodeVid(payloadSender, limits),
          ))
          .takeBytes();
  final padding = _paddingField(payload.padding);
  final body = CesrWriter();
  TspDigest? said;

  switch (payload) {
    case ScsPayload(:final stream) || CtlPayload(:final stream):
      body
        ..raw(payload is ScsPayload ? TspCodes.xscs : TspCodes.xctl)
        ..raw(senderField)
        ..raw(padding)
        ..count(TspCodes.genericStream, stream.length ~/ 3)
        ..raw(stream);
    case PadPayload(:final nonce):
      body
        ..raw(TspCodes.xpad)
        ..raw(senderField)
        ..raw(_nonceField(_checkNonce(nonce)))
        ..raw(padding);
    case HopPayload(:final hops, :final inner):
      if (inner.isEmpty || inner.length % 3 != 0) {
        throw const TspInvalidInputException(
          'the inner message must be a non-empty, quadlet-aligned TSP message',
        );
      }
      body
        ..raw(TspCodes.xhop)
        ..raw(senderField)
        ..raw(_vidListBytes(hops, limits))
        ..raw(padding)
        ..raw(inner);
    case RfiPayload(:final nonce, :final replyPath, :final referral):
      final n = _nonceField(_checkNonce(nonce));
      final path = _vidListBytes(replyPath, limits);
      if (referral != null && referral.vid.isEmpty) {
        throw const TspInvalidInputException(
          'a referral may not name the NULL VID',
        );
      }
      final digestBytes = digestAlgorithm.hash(
        concatBytes([
          envelopeFields,
          TspCodes.xrfi,
          senderField,
          filledBytes(TspCodes.encodedDigestLength, TspCodes.saidDummy),
          n,
          path,
          if (referral != null)
            _bareVidField(referral.vid, limits)
          else
            _vidListBytes(const [], limits),
        ]),
      );
      said = TspDigest(digestBytes, digestAlgorithm);
      final digestField = _digestField(said);
      Uint8List referralField;
      if (referral == null) {
        referralField = _vidListBytes(const [], limits);
      } else {
        final Uint8List sig;
        final TspSignatureAlgorithm alg;
        final key = referral.signingKey;
        if (key != null) {
          alg = key.algorithm;
          sig = await key.sign(
            concatBytes([
              TspCodes.xrfi,
              senderField,
              digestField,
              n,
              path,
              _bareVidField(referral.vid, limits),
            ]),
          );
        } else {
          final a = referral.algorithm;
          if (a == null) {
            throw const TspInvalidInputException(
              'referral signature has an unrecognised length',
            );
          }
          alg = a;
          sig = referral.signature!;
        }
        final group = concatBytes([
          _bareVidField(referral.vid, limits),
          encodeSignatureAttachment(alg, sig),
        ]);
        referralField =
            (CesrWriter()
                  ..count(TspCodes.vidList, group.length ~/ 3)
                  ..raw(group))
                .takeBytes();
      }
      body
        ..raw(TspCodes.xrfi)
        ..raw(senderField)
        ..raw(digestField)
        ..raw(n)
        ..raw(path)
        ..raw(referralField)
        ..raw(padding);
    case RfaPayload(:final digest):
      final echoed = _digestField(digest);
      final own = digestAlgorithm.hash(
        concatBytes([
          envelopeFields,
          TspCodes.xrfa,
          senderField,
          echoed,
          filledBytes(TspCodes.encodedDigestLength, TspCodes.saidDummy),
        ]),
      );
      said = TspDigest(own, digestAlgorithm);
      body
        ..raw(TspCodes.xrfa)
        ..raw(senderField)
        ..raw(echoed)
        ..raw(_digestField(said))
        ..raw(padding);
    case RfdPayload(:final digest):
      body
        ..raw(TspCodes.xrfd)
        ..raw(senderField)
        ..raw(_digestField(digest))
        ..raw(padding);
  }

  final content = body.takeBytes();
  final frame =
      (CesrWriter()
            ..count(TspCodes.payload, content.length ~/ 3)
            ..raw(content))
          .takeBytes();
  return (frame: frame, said: said);
}

Uint8List _checkNonce(Uint8List? nonce) {
  if (nonce == null) return secureRandomBytes(nonceLength);
  if (nonce.length != nonceLength) {
    throw TspInvalidInputException(
      'nonce must be $nonceLength bytes, got ${nonce.length}',
    );
  }
  return nonce;
}

/// A decoded payload frame.
typedef DecodedFrame = ({TspPayload payload, String? payloadSender});

bool _is(Uint8List code, Uint8List bytes, int at) =>
    bytes[at] == code[0] &&
    bytes[at + 1] == code[1] &&
    bytes[at + 2] == code[2];

/// Decodes and verifies a `-Z` payload frame occupying all of [plaintext].
///
/// Checks the ESSR sender field against [envelopeSender] and recomputes every
/// self-addressing digest.
DecodedFrame decodePayloadFrame({
  required Uint8List plaintext,
  required Uint8List envelopeFields,
  required String envelopeSender,
  required TspLimits limits,
}) {
  final outer = CesrReader(plaintext);
  final r = outer.readGroup(TspCodes.payload, 'payload frame');
  outer.expectEnd('payload');
  if (r.remaining < 3) {
    throw const TspMalformedException('truncated payload type code');
  }
  final at = r.pos;
  r.pos += 3;

  final senderStart = r.pos;
  final senderBytes = r.readVariable(
    TspCodes.bytes,
    'ESSR sender field',
    maxLength: limits.maxVidLength,
  );
  final senderField = Uint8List.sublistView(plaintext, senderStart, r.pos);
  String? payloadSender;
  if (senderBytes.isNotEmpty) {
    payloadSender = _decodeVid(senderBytes, 'ESSR sender VID');
    if (payloadSender != envelopeSender) {
      throw const TspSenderException(
        'the ESSR sender VID does not match the envelope sender',
      );
    }
  }

  Uint8List readPadding() => r.readVariable(
    TspCodes.bytes,
    'padding field',
    maxLength: limits.maxPaddingLength,
  );

  TspDigest readDigest(String what) {
    if (r.peekFixed1(TspCodes.sha256Digest)) {
      return TspDigest(
        r.readFixed(TspCodes.sha256Digest, 32, what),
        TspDigestAlgorithm.sha256,
      );
    }
    if (r.peekFixed1(TspCodes.blake2b256Digest)) {
      return TspDigest(
        r.readFixed(TspCodes.blake2b256Digest, 32, what),
        TspDigestAlgorithm.blake2b256,
      );
    }
    throw TspMalformedException('expected $what');
  }

  List<String> readVidList(String what) {
    final g = r.readGroup(TspCodes.vidList, what);
    final vids = <String>[];
    while (!g.isAtEnd) {
      if (vids.length >= limits.maxHops) {
        throw TspMalformedException('$what exceeds ${limits.maxHops} entries');
      }
      final b = g.readVariable(
        TspCodes.bytes,
        'VID in $what',
        maxLength: limits.maxVidLength,
      );
      if (b.isEmpty) throw TspMalformedException('NULL VID in $what');
      vids.add(_decodeVid(b, 'VID in $what'));
    }
    return vids;
  }

  final TspPayload payload;
  if (_is(TspCodes.xscs, plaintext, at) || _is(TspCodes.xctl, plaintext, at)) {
    final padding = readPadding();
    final stream = r.readGroup(TspCodes.genericStream, 'generic CESR stream');
    r.expectEnd('payload frame');
    // Exactly one Bytes primitive, nothing after it (issue #77).
    final data = stream.readVariable(
      TspCodes.bytes,
      'payload body',
      maxLength: stream.remaining,
    );
    stream.expectEnd('generic CESR stream');
    payload = _is(TspCodes.xscs, plaintext, at)
        ? ScsPayload(data, padding: padding)
        : CtlPayload(data, padding: padding);
  } else if (_is(TspCodes.xpad, plaintext, at)) {
    final nonce = r.readFixed(TspCodes.nonce, nonceLength, 'nonce');
    final padding = readPadding();
    r.expectEnd('payload frame');
    payload = PadPayload(nonce: nonce, padding: padding);
  } else if (_is(TspCodes.xhop, plaintext, at)) {
    final hops = readVidList('hop list');
    final padding = readPadding();
    if (r.isAtEnd) {
      throw const TspMalformedException(
        'nested payload carries no inner message',
      );
    }
    final inner = r.readRaw(r.remaining, 'inner message');
    payload = HopPayload(hops: hops, inner: inner, padding: padding);
  } else if (_is(TspCodes.xrfi, plaintext, at)) {
    final digest = readDigest('invite digest');
    final nonceStart = r.pos;
    final nonce = r.readFixed(TspCodes.nonce, nonceLength, 'nonce');
    final nonceField = Uint8List.sublistView(plaintext, nonceStart, r.pos);
    final pathStart = r.pos;
    final replyPath = readVidList('reply path');
    final pathField = Uint8List.sublistView(plaintext, pathStart, r.pos);
    final refGroup = r.readGroup(TspCodes.vidList, 'referral field');
    Referral? referral;
    Uint8List? bareVid;
    if (!refGroup.isAtEnd) {
      final vidStart = refGroup.pos;
      final vb = refGroup.readVariable(
        TspCodes.bytes,
        'referral VID',
        maxLength: limits.maxVidLength,
      );
      if (vb.isEmpty) {
        throw const TspMalformedException('referral names the NULL VID');
      }
      bareVid = Uint8List.sublistView(plaintext, vidStart, refGroup.pos);
      final sig = decodeSignatureAttachment(refGroup, 'referral');
      refGroup.expectEnd('referral field');
      referral = Referral(
        vid: _decodeVid(vb, 'referral VID'),
        signature: sig.signature,
      );
    }
    final padding = readPadding();
    r.expectEnd('payload frame');
    final recomputed = digest.algorithm.hash(
      concatBytes([
        envelopeFields,
        TspCodes.xrfi,
        senderField,
        filledBytes(TspCodes.encodedDigestLength, TspCodes.saidDummy),
        nonceField,
        pathField,
        bareVid ?? (CesrWriter()..count(TspCodes.vidList, 0)).takeBytes(),
      ]),
    );
    if (!constantTimeEquals(recomputed, digest.bytes)) {
      throw const TspDigestException('the invite digest does not verify');
    }
    payload = RfiPayload(
      nonce: nonce,
      replyPath: replyPath,
      referral: referral,
      digest: digest,
      padding: padding,
    );
  } else if (_is(TspCodes.xrfa, plaintext, at)) {
    final echoedStart = r.pos;
    final echoed = readDigest('accepted invite digest');
    final echoedField = Uint8List.sublistView(plaintext, echoedStart, r.pos);
    final own = readDigest('reply digest');
    final padding = readPadding();
    r.expectEnd('payload frame');
    final recomputed = own.algorithm.hash(
      concatBytes([
        envelopeFields,
        TspCodes.xrfa,
        senderField,
        echoedField,
        filledBytes(TspCodes.encodedDigestLength, TspCodes.saidDummy),
      ]),
    );
    if (!constantTimeEquals(recomputed, own.bytes)) {
      throw const TspDigestException('the accept reply digest does not verify');
    }
    payload = RfaPayload(digest: echoed, replyDigest: own, padding: padding);
  } else if (_is(TspCodes.xrfd, plaintext, at)) {
    final digest = readDigest('relationship digest');
    final padding = readPadding();
    r.expectEnd('payload frame');
    payload = RfdPayload(digest: digest, padding: padding);
  } else {
    throw const TspUnsupportedException('unsupported payload type code');
  }
  return (payload: payload, payloadSender: payloadSender);
}

/// Verifies a decoded referral's `Signature_new` against the introduced VID's
/// [verificationKey]. [payloadSender] is the ESSR sender field of the
/// message that carried [invite].
Future<bool> verifyReferralSignature({
  required RfiPayload invite,
  required String? payloadSender,
  required TspVerificationKey verificationKey,
  TspLimits limits = TspLimits.defaults,
}) async {
  final referral = invite.referral;
  final sig = referral?.signature;
  final digest = invite.digest;
  final nonce = invite.nonce;
  if (referral == null || sig == null || digest == null || nonce == null) {
    throw const TspInvalidInputException(
      'the invite carries no decoded referral',
    );
  }
  if (referral.algorithm != verificationKey.algorithm) return false;
  final senderField =
      (CesrWriter()..variable(
            TspCodes.bytes,
            payloadSender == null ? const [] : encodeVid(payloadSender, limits),
          ))
          .takeBytes();
  final data = concatBytes([
    TspCodes.xrfi,
    senderField,
    _digestField(digest),
    _nonceField(nonce),
    _vidListBytes(invite.replyPath, limits),
    _bareVidField(referral.vid, limits),
  ]);
  return verificationKey.verify(data, sig);
}
