/// Machine-readable classification of a [TspException].
///
/// The values mirror the error taxonomy of the TSP conformance driver
/// protocol so that an adapter can map them one to one.
enum TspErrorCode {
  /// The operation, scheme, payload type or option is not supported.
  unsupported('unsupported'),

  /// The CESR framing could not be parsed, or violated a structural rule.
  malformed('malformed'),

  /// The message carries an unknown or unsupported TSP version.
  version('version'),

  /// The TSP signature did not verify.
  signature('signature'),

  /// Decryption or AEAD authentication failed.
  decrypt('decrypt'),

  /// The envelope or ESSR sender does not match, or the sender key is wrong.
  sender('sender'),

  /// The message is not addressed to the receiving identity.
  receiver('receiver'),

  /// A self-addressing TSP digest (SAID) did not verify.
  digest('digest'),

  /// The relationship state forbids the message.
  relationship('relationship'),

  /// The caller supplied invalid input.
  invalidInput('invalid-input');

  const TspErrorCode(this.wireName);

  /// The code as spelled by the conformance driver protocol.
  final String wireName;
}

/// Base class of every exception this library throws.
///
/// Parsing and opening untrusted input never throws anything else: failures
/// of the underlying primitives are caught and re-thrown as the matching
/// subclass.
sealed class TspException implements Exception {
  const TspException(this.message, {this.cause});

  /// Human-readable description. Not intended for peers: a receiver should
  /// not echo it back, as it may disclose why a message was rejected.
  final String message;

  /// The underlying error, when one exists.
  final Object? cause;

  /// The classification of this failure.
  TspErrorCode get code;

  @override
  String toString() => 'TspException(${code.wireName}): $message';
}

/// The operation, scheme, payload type or option is not supported.
final class TspUnsupportedException extends TspException {
  /// Creates an [TspUnsupportedException].
  const TspUnsupportedException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.unsupported;
}

/// CESR framing could not be parsed, or broke a structural rule.
final class TspMalformedException extends TspException {
  /// Creates a [TspMalformedException].
  const TspMalformedException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.malformed;
}

/// The message carries an unknown or unsupported TSP version.
final class TspVersionException extends TspException {
  /// Creates a [TspVersionException].
  const TspVersionException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.version;
}

/// The TSP signature did not verify.
final class TspSignatureException extends TspException {
  /// Creates a [TspSignatureException].
  const TspSignatureException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.signature;
}

/// Decryption or AEAD authentication failed.
final class TspDecryptionException extends TspException {
  /// Creates a [TspDecryptionException].
  const TspDecryptionException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.decrypt;
}

/// The envelope or ESSR sender does not match the expected sender.
final class TspSenderException extends TspException {
  /// Creates a [TspSenderException].
  const TspSenderException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.sender;
}

/// The message is not addressed to the receiving identity.
final class TspReceiverException extends TspException {
  /// Creates a [TspReceiverException].
  const TspReceiverException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.receiver;
}

/// A self-addressing TSP digest did not verify.
final class TspDigestException extends TspException {
  /// Creates a [TspDigestException].
  const TspDigestException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.digest;
}

/// The relationship state forbids the message or operation.
final class TspRelationshipException extends TspException {
  /// Creates a [TspRelationshipException].
  const TspRelationshipException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.relationship;
}

/// The caller supplied invalid input (a local programming error, not an
/// untrusted-input failure).
final class TspInvalidInputException extends TspException {
  /// Creates a [TspInvalidInputException].
  const TspInvalidInputException(super.message, {super.cause});
  @override
  TspErrorCode get code => TspErrorCode.invalidInput;
}
