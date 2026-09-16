import 'dart:typed_data';

import '../cesr/cesr.dart';
import '../cesr/tsp_codes.dart';
import '../crypto/digest.dart';
import '../errors.dart';
import '../keys/keys.dart';

final Uint8List _empty = Uint8List(0);

/// A TSP protocol version: MAJOR and MINOR, carried as `YTSP-###`.
final class TspVersion {
  /// Creates a version.
  const TspVersion(this.major, this.minor);

  /// The version this library packs: `YTSP-AAC`, i.e. 0.2 (Rev 3).
  static const TspVersion current = TspVersion(0, 2);

  /// The MAJOR revision (the first character after `YTSP-`).
  final int major;

  /// The MINOR revision (the 12-bit count of the version code).
  final int minor;

  @override
  bool operator ==(Object other) =>
      other is TspVersion && other.major == major && other.minor == minor;

  @override
  int get hashCode => Object.hash(major, minor);

  @override
  String toString() => '$major.$minor';
}

/// How a TSP payload is protected.
enum TspScheme {
  /// HPKE-Base (§8.2). The KEM — X25519 or the MLKEM768-X25519 hybrid — is
  /// selected by the receiver's encryption key type.
  hpkeBase('hpke-base'),

  /// The libsodium anonymous sealed box (§8.3).
  sealedBox('sealed-box'),

  /// Non-confidential: the payload is carried in the clear, still signed.
  signedOnly('signed-only');

  const TspScheme(this.wireName);

  /// The scheme name used by the conformance driver protocol.
  final String wireName;

  /// Whether the payload is encrypted.
  bool get confidential => this != TspScheme.signedOnly;
}

/// Bounds applied to untrusted input. Every length is checked before any
/// allocation proportional to it.
final class TspLimits {
  /// Creates a set of limits.
  const TspLimits({
    this.maxMessageLength = 16 * 1024 * 1024,
    this.maxVidLength = 64 * 1024,
    this.maxHops = 32,
    this.maxPaddingLength = 1024 * 1024,
  });

  /// The default limits.
  static const TspLimits defaults = TspLimits();

  /// Largest accepted message, in bytes.
  final int maxMessageLength;

  /// Largest accepted VID, in UTF-8 bytes.
  final int maxVidLength;

  /// Largest number of VIDs in a hop list or reply path.
  final int maxHops;

  /// Largest accepted padding field, in bytes.
  final int maxPaddingLength;
}

/// The public half of a VID: its identifier and the keys it is bound to.
final class PublicVid {
  /// Creates a public VID.
  const PublicVid({
    required this.id,
    required this.verificationKey,
    this.encryptionKey,
  });

  /// The VID string, e.g. a DID.
  final String id;

  /// The key the VID signs with.
  final TspVerificationKey verificationKey;

  /// The key messages to the VID are encrypted to, when it has one.
  final TspEncryptionKey? encryptionKey;

  @override
  String toString() => 'PublicVid($id)';
}

/// A VID this process controls: its identifier and private keys.
final class PrivateVid {
  /// Creates a private VID.
  const PrivateVid({
    required this.id,
    required this.signingKey,
    this.decryptionKey,
  });

  /// The VID string, e.g. a DID.
  final String id;

  /// The key this VID signs with.
  final TspSigningKey signingKey;

  /// The key this VID decrypts with, when it has one.
  final TspDecryptionKey? decryptionKey;

  @override
  String toString() => 'PrivateVid($id)';
}

/// A VID introduced over an existing relationship (§7.2.5).
final class Referral {
  /// A referral carrying an already-computed `Signature_new`.
  Referral({required this.vid, required List<int> signature})
    : signature = Uint8List.fromList(signature),
      signingKey = null;

  /// A referral whose `Signature_new` is computed at pack time with the new
  /// VID's [signingKey]. The signature covers the invite's digest, so it
  /// cannot be made in advance.
  Referral.signWith({required this.vid, required TspSigningKey this.signingKey})
    : signature = null;

  /// `VID_new`.
  final String vid;

  /// `Signature_new`. On a decoded referral it is **unverified**: checking it
  /// requires resolving [vid] — see `Tsp.verifyReferral`.
  final Uint8List? signature;

  /// The new VID's signing key, when the signature is made at pack time.
  final TspSigningKey? signingKey;

  /// The signature algorithm, inferred from the signature length.
  TspSignatureAlgorithm? get algorithm {
    final s = signature;
    if (s == null) return signingKey?.algorithm;
    for (final a in TspSignatureAlgorithm.values) {
      if (a.signatureLength == s.length) return a;
    }
    return null;
  }
}

/// A TSP payload (§9.2). Every layout carries a padding field; its content is
/// discarded by receivers and excluded from digests.
sealed class TspPayload {
  TspPayload({List<int>? padding})
    : padding = padding == null ? _empty : Uint8List.fromList(padding);

  /// The Padding_Field content (empty for `4BAA`).
  final Uint8List padding;

  /// The four-character payload type code, e.g. `XSCS`.
  String get typeCode;
}

/// Shared shape of XSCS and XCTL: a generic CESR stream (`-A##`).
sealed class StreamPayload extends TspPayload {
  StreamPayload._(Uint8List data, {super.padding})
    : stream = _singleBytes(data);

  StreamPayload._stream(List<int> stream, {super.padding})
    : stream = Uint8List.fromList(stream) {
    if (this.stream.length % 3 != 0) {
      throw const TspInvalidInputException(
        'a CESR stream must be a whole number of quadlets',
      );
    }
  }

  /// The content of the `-A` group, as a CESR stream.
  final Uint8List stream;

  /// The bytes of the stream's single Bytes primitive, or `null` if the
  /// stream is anything else (e.g. interleaved `-H` groups, which the upper
  /// layer parses itself).
  Uint8List? get data {
    try {
      final r = CesrReader(stream);
      final d = r.readVariable(
        TspCodes.bytes,
        'payload body',
        maxLength: stream.length,
      );
      if (!r.isAtEnd) return null;
      return d;
    } on TspException {
      return null;
    }
  }

  static Uint8List _singleBytes(Uint8List data) =>
      (CesrWriter()..variable(TspCodes.bytes, data)).takeBytes();
}

/// `XSCS`: an upper-layer (application) message.
final class ScsPayload extends StreamPayload {
  /// Carries [data] as the single Bytes primitive of the stream.
  ScsPayload(List<int> data, {super.padding})
    : super._(Uint8List.fromList(data));

  /// Carries an arbitrary pre-encoded CESR [stream].
  ScsPayload.stream(super.stream, {super.padding}) : super._stream();

  @override
  String get typeCode => 'XSCS';
}

/// `XCTL`: a generic upper-layer control message.
final class CtlPayload extends StreamPayload {
  /// Carries [data] as the single Bytes primitive of the stream.
  CtlPayload(List<int> data, {super.padding})
    : super._(Uint8List.fromList(data));

  /// Carries an arbitrary pre-encoded CESR [stream].
  CtlPayload.stream(super.stream, {super.padding}) : super._stream();

  @override
  String get typeCode => 'XCTL';
}

/// `XPAD`: a padding-only message.
final class PadPayload extends TspPayload {
  /// Creates a padding message. A random [nonce] is generated when omitted.
  PadPayload({List<int>? nonce, super.padding})
    : nonce = nonce == null ? null : Uint8List.fromList(nonce);

  /// The 16-byte nonce.
  final Uint8List? nonce;

  @override
  String get typeCode => 'XPAD';
}

/// `XRFI`: relationship forming invite (§7.2).
final class RfiPayload extends TspPayload {
  /// Creates an invite. A random [nonce] is generated when omitted.
  RfiPayload({
    List<int>? nonce,
    List<String> replyPath = const [],
    this.referral,
    this.digest,
    super.padding,
  }) : nonce = nonce == null ? null : Uint8List.fromList(nonce),
       replyPath = List.unmodifiable(replyPath);

  /// The 16-byte nonce.
  final Uint8List? nonce;

  /// `Reply_Path`: the route for the accept; empty for a direct reply.
  final List<String> replyPath;

  /// `Referral_Field`, when this invite introduces a new VID.
  final Referral? referral;

  /// The invite's own self-addressing digest. Computed by the library; any
  /// value supplied on input is ignored.
  final TspDigest? digest;

  @override
  String get typeCode => 'XRFI';
}

/// `XRFA`: relationship forming accept (§7.2).
final class RfaPayload extends TspPayload {
  /// Creates an accept answering the invite whose digest is [digest].
  RfaPayload({required this.digest, this.replyDigest, super.padding});

  /// `Digest`: the invite's digest, echoed verbatim.
  final TspDigest digest;

  /// `Reply_Digest`: this accept's own self-addressing digest. Computed by
  /// the library; any value supplied on input is ignored.
  final TspDigest? replyDigest;

  @override
  String get typeCode => 'XRFA';
}

/// `XRFD`: relationship forming decline or cancel (§7.3).
final class RfdPayload extends TspPayload {
  /// Creates a decline/cancel naming the relationship [digest].
  RfdPayload({required this.digest, super.padding});

  /// The digest of the relationship being declined or cancelled.
  final TspDigest digest;

  @override
  String get typeCode => 'XRFD';
}

/// `XHOP`: a nested (no hops) or routed (hops) message.
final class HopPayload extends TspPayload {
  /// Wraps the complete encoded TSP message [inner].
  HopPayload({
    List<String> hops = const [],
    required List<int> inner,
    super.padding,
  }) : hops = List.unmodifiable(hops),
       inner = Uint8List.fromList(inner);

  /// The remaining route; empty for a nested message.
  final List<String> hops;

  /// The complete inner TSP message, carried unopened.
  final Uint8List inner;

  /// Whether this is a routed (as opposed to nested) message.
  bool get isRouted => hops.isNotEmpty;

  @override
  String get typeCode => 'XHOP';
}

/// Which ESSR sender field (§3.7 step 7) a packed payload carries.
enum PayloadSenderMode {
  /// The scheme's default: the NULL VID under HPKE-Base and signed-only, the
  /// sender's VID under the sealed box (where it is mandatory).
  schemeDefault,

  /// The NULL VID `4BAA`. Refused for the sealed box.
  nullVid,

  /// The envelope sender's VID.
  present,
}

/// Options for `Tsp.pack`.
final class TspPackOptions {
  /// Creates pack options.
  const TspPackOptions({
    this.payloadSender = PayloadSenderMode.schemeDefault,
    this.ephemeral,
    this.nullReceiver = false,
    this.limits = TspLimits.defaults,
  });

  /// Which ESSR sender field to carry.
  final PayloadSenderMode payloadSender;

  /// Fixed encryption randomness: HPKE `ikmE` (32 bytes for X25519; the
  /// 64-byte encapsulation randomness for MLKEM768-X25519) or the sealed box
  /// ephemeral secret `skEm`.
  ///
  /// **Test vectors only.** Reusing it for two messages breaks both
  /// confidentiality and integrity.
  final Uint8List? ephemeral;

  /// Writes the NULL VID as the envelope receiver (e.g. the inner message of
  /// a nested relationship-forming invite, §7.2.6).
  final bool nullReceiver;

  /// Size bounds for the produced message.
  final TspLimits limits;
}

/// A packed TSP message.
final class PackedTspMessage {
  /// Creates a packed message.
  const PackedTspMessage({required this.bytes, this.digest});

  /// The wire bytes (binary CESR).
  final Uint8List bytes;

  /// The self-addressing digest of an invite (its `Digest`) or of an accept
  /// (its `Reply_Digest`); `null` for other payloads.
  final TspDigest? digest;
}

/// A verified, decrypted TSP message.
final class TspMessage {
  /// Creates an opened message.
  const TspMessage({
    required this.version,
    required this.sender,
    required this.receiver,
    required this.scheme,
    required this.kem,
    required this.payloadSender,
    required this.payload,
  });

  /// The version the message carried.
  final TspVersion version;

  /// The envelope sender VID (signature verified).
  final String sender;

  /// The envelope receiver VID, or `null` for the NULL VID.
  final String? receiver;

  /// The protection scheme.
  final TspScheme scheme;

  /// The HPKE KEM, for [TspScheme.hpkeBase].
  final TspKem? kem;

  /// The ESSR sender field inside the payload, or `null` for the NULL VID.
  /// When present it has been checked against [sender].
  final String? payloadSender;

  /// The payload, with every carried digest verified.
  final TspPayload payload;

  /// Whether the payload was encrypted.
  bool get confidential => scheme.confidential;
}

/// What an intermediary can see of a message without any keys.
final class TspEnvelopeInfo {
  /// Creates envelope information.
  const TspEnvelopeInfo({
    required this.version,
    required this.sender,
    required this.receiver,
    required this.scheme,
  });

  /// The version the message carried.
  final TspVersion version;

  /// The envelope sender VID (**unverified**).
  final String sender;

  /// The envelope receiver VID, or `null` for the NULL VID.
  final String? receiver;

  /// The protection scheme, as indicated by the body's CESR code.
  final TspScheme scheme;

  /// Whether the payload is encrypted.
  bool get confidential => scheme.confidential;
}
