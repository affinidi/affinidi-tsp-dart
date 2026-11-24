// What the resolver answers, in the shape
// `test/tool/did_webs_resolve_golden.mjs` records the JS reference's answers,
// and the Rust vectors' comparison (vti-didcomm-js
// `test/support-did-webs-vectors.js`). Free of dart:io so the same code runs
// compiled to JavaScript.

import 'dart:typed_data';

import 'package:affinidi_tsp/src/did_webs/resolver.dart';

/// A resolution as the golden file records it: the document, document
/// metadata and resolution metadata, or the refusal's kind and message.
Map<String, Object?> resolveOutcome(
  String did,
  Uint8List keriCesr,
  Uint8List? didJson,
) {
  try {
    final r = resolveDidWebsFromArtifacts(did, keriCesr, didJson);
    return {
      'document': r.didDocument,
      'metadata': r.didDocumentMetadata,
      'resolution': r.didResolutionMetadata,
    };
  } on DidWebsError catch (e) {
    return {'error': e.kind, 'message': e.message};
  } on Exception catch (e) {
    return {'error': 'dart', 'message': '$e'};
  }
}

/// A parse as the golden file records it.
Object? parseOutcome(String did) {
  try {
    final p = parseDidWebs(did);
    return {
      'did': p.did,
      'versionId': p.versionId,
      'host': p.host,
      'path': p.path,
      'aid': p.aid,
    };
  } on DidWebsError catch (e) {
    return {'error': e.kind, 'message': e.message};
  }
}

Object? _sortKeys(Object? v) {
  if (v is List) return [for (final x in v) _sortKeys(x)];
  if (v is Map) {
    final keys = v.keys.cast<String>().toList()..sort();
    return {for (final k in keys) k: _sortKeys(v[k])};
  }
  return v;
}

const _special = {'http': 80, 'https': 443, 'ws': 80, 'wss': 443};

/// A URL as the WHATWG parser writes it, for the special schemes and the
/// simple URLs the vectors carry.
String _href(String s) {
  final m = RegExp(
    r'^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)([^?#]*)(.*)$',
  ).firstMatch(s);
  if (m == null) return s;
  final scheme = m[1]!.toLowerCase();
  final port = _special[scheme];
  if (port == null) return s;
  var authority = m[2]!.toLowerCase();
  if (authority.endsWith(':$port')) {
    authority = authority.substring(0, authority.length - '$port'.length - 1);
  }
  final path = m[3]!.isEmpty ? '/' : m[3]!;
  return '$scheme://$authority$path${m[4]}';
}

/// A resolved document as `affinidi_did_common::Document` serializes it: a
/// service `type` is always a list, and a service endpoint that is a URL is
/// written as the URL parser normalizes it (vti-didcomm-js `asRustDocument`).
Object? asRustDocument(Map<String, Object?> doc) {
  final d = <String, Object?>{...doc};
  final services = d['service'];
  if (services is List) {
    d['service'] = [
      for (final s in services)
        if (s is Map)
          {
            ...s,
            if (s['type'] is String) 'type': [s['type']],
            if (s['serviceEndpoint'] is String)
              'serviceEndpoint': _href(s['serviceEndpoint'] as String),
          }
        else
          s,
    ];
  }
  return _sortKeys(d);
}
