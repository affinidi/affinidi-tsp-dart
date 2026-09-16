import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';

import '../crypto/digest.dart';
import '../util/bytes.dart';

/// Resolves `did:peer:4` identifiers — the form TSP uses for private VIDs and
/// the Appendix A test identifiers — and delegates everything else.
///
/// A long-form `did:peer:4<hash>:<document>` embeds its own DID document, so
/// it resolves offline after its hash is checked. A short form resolves only
/// if its long form has been seen by this resolver before.
final class DidPeer4Resolver implements DidResolver {
  /// Creates a resolver delegating other methods to [fallback], by default
  /// `ssi`'s universal resolver.
  DidPeer4Resolver({DidResolver? fallback})
    : fallback = fallback ?? UniversalDIDResolver.defaultResolver;

  /// Resolves DIDs that are not `did:peer:4`.
  final DidResolver fallback;

  final Map<String, String> _longForms = {};

  static const String _prefix = 'did:peer:4';

  @override
  Future<DidDocument> resolveDid(String did) async {
    if (!did.startsWith(_prefix)) return fallback.resolveDid(did);
    final parts = did.substring(_prefix.length).split(':');
    if (parts.length == 1) {
      final long = _longForms[did];
      if (long == null) {
        throw SsiException(
          message: 'short-form did:peer:4 $did has no known long form',
          code: SsiExceptionType.invalidDidDocument.code,
        );
      }
      return _document(long, id: did, alsoKnownAs: long);
    }
    if (parts.length != 2) {
      throw SsiException(
        message: 'malformed did:peer:4',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
    final short = '$_prefix${parts[0]}';
    _checkHash(parts[0], parts[1]);
    _longForms[short] = did;
    return _document(did, id: did, alsoKnownAs: short);
  }

  /// Returns the short form of a long-form `did:peer:4`, after checking it.
  static String shortForm(String longForm) {
    final parts = longForm.substring(_prefix.length).split(':');
    if (!longForm.startsWith(_prefix) || parts.length != 2) {
      throw ArgumentError.value(
        longForm,
        'longForm',
        'not a long-form did:peer:4',
      );
    }
    _checkHash(parts[0], parts[1]);
    return '$_prefix${parts[0]}';
  }

  static void _checkHash(String hash, String encodedDocument) {
    final expected = concatBytes([
      [0x12, 0x20],
      computeSha256(utf8.encode(encodedDocument)),
    ]);
    final actual = multiBaseToUint8List(hash);
    if (!constantTimeEquals(actual, expected)) {
      throw SsiException(
        message: 'did:peer:4 hash does not match its document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
  }

  static DidDocument _document(
    String longForm, {
    required String id,
    required String alsoKnownAs,
  }) {
    final encoded = longForm.split(':').last;
    final bytes = multiBaseToUint8List(encoded);
    // Multicodec 0x0200 (application/json) as a varint: 0x80 0x04.
    if (bytes.length < 2 || bytes[0] != 0x80 || bytes[1] != 0x04) {
      throw SsiException(
        message: 'did:peer:4 document is not multicodec JSON',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
    final json =
        jsonDecode(utf8.decode(Uint8List.sublistView(bytes, 2)))
            as Map<String, dynamic>;
    String abs(Object? ref) =>
        ref is String && ref.startsWith('#') ? '$id$ref' : '$ref';
    Object? absRefs(Object? list) => list is List
        ? [
            for (final e in list)
              e is Map<String, dynamic> ? _contextualise(e, id, abs) : abs(e),
          ]
        : list;
    final doc = <String, dynamic>{
      ...json,
      'id': id,
      'alsoKnownAs': [alsoKnownAs],
      'verificationMethod': absRefs(json['verificationMethod']),
      for (final rel in const [
        'authentication',
        'assertionMethod',
        'keyAgreement',
        'capabilityInvocation',
        'capabilityDelegation',
      ])
        if (json[rel] != null) rel: absRefs(json[rel]),
      if (json['service'] is List)
        'service': [
          for (final s in json['service'] as List)
            if (s is Map<String, dynamic>) {...s, 'id': abs(s['id'])} else s,
        ],
    };
    return DidDocument.fromJson(doc);
  }

  static Map<String, dynamic> _contextualise(
    Map<String, dynamic> vm,
    String id,
    String Function(Object?) abs,
  ) => {...vm, 'id': abs(vm['id']), 'controller': vm['controller'] ?? id};
}
