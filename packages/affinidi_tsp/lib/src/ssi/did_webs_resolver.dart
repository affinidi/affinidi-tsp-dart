// did:webs over the network: `keri.cesr` and `did.json` fetched from the
// host the DID names, through the egress guard, then verified and compared
// by `lib/src/did_webs/resolver.dart`.
//
// A did:webs DID names the host its artifacts are fetched from, and DIDs
// reach this library from whoever it talks to. Both artifact URLs are checked
// against the [NetPolicy] before any request, every address the host
// resolves to is checked and the connection pinned to it, redirects are
// refused, each body is capped at 4 MiB and each request has a timeout
// (20 s), as OpenVTC/vti-didcomm-js `src/did-webs.js` and `affinidi-did-webs`
// `fetch.rs` do. Plain `http` is used for a loopback host when
// `allowPrivate` is set (as the Rust `HostPolicy::AllowPrivate` does), and
// for any host when `allowInsecure` is set (its `allow_http`).
import 'dart:async';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:ssi/ssi.dart';

import '../did_webs/resolver.dart';
import 'net_guard.dart';

const String _cesrLabel = 'did:webs keri.cesr';
const String _didJsonLabel = 'did:webs did.json';
const String _prefix = 'did:webs:';

/// The `keri.cesr` and `did.json` URLs a did:webs DID points at.
final class WebsArtifactUrls {
  /// Creates the pair.
  const WebsArtifactUrls(this.keriCesrHref, this.didJsonHref);

  /// The key event stream's URL, as the WHATWG URL parser serializes it.
  final String keriCesrHref;

  /// The published document's URL, as the WHATWG URL parser serializes it.
  final String didJsonHref;

  /// The key event stream.
  Uri get keriCesr => Uri.parse(keriCesrHref);

  /// The published document.
  Uri get didJson => Uri.parse(didJsonHref);
}

String _schemeFor(DidWebs parsed, NetPolicy policy) =>
    policy.allowInsecure || (policy.allowPrivate && isLoopbackDidWebs(parsed))
    ? 'http'
    : 'https';

NetPolicy _artifactPolicy(NetPolicy policy, bool plaintext) => NetPolicy(
  allowInsecure: plaintext,
  allowPrivate: policy.allowPrivate,
  allowHosts: policy.allowHosts,
);

/// The `keri.cesr` and `did.json` URLs a did:webs DID points at, checked
/// against [policy].
///
/// Throws a [BlockedEndpointException] if the host fails the policy, and a
/// [DidWebsError] of kind `InvalidDid` if [did] is not a did:webs DID.
WebsArtifactUrls websArtifactUrls(
  String did, [
  NetPolicy policy = const NetPolicy(),
]) {
  final parsed = parseDidWebs(did);
  final scheme = _schemeFor(parsed, policy);
  final vetted = _artifactPolicy(policy, scheme == 'http');
  String vet(String artifact, String label) {
    final href = websArtifactHref(parsed, scheme, artifact);
    assertSafeEndpoint(Uri.parse(href), vetted, label: label);
    return href;
  }

  return WebsArtifactUrls(
    vet('keri.cesr', _cesrLabel),
    vet('did.json', _didJsonLabel),
  );
}

/// Resolves did:webs DIDs (and DID URLs with a `versionId` parameter) over
/// the network, delegating every other method to [fallback].
///
/// [resolveWithMetadata] returns the document as plain JSON with its
/// metadata; [resolveDid] returns it as an `ssi` [DidDocument], leaving out
/// any verification method `ssi` cannot read (a `ConditionalProof2022`
/// threshold method) and the references to it.
final class DidWebsResolver implements DidResolver {
  /// Creates a resolver.
  ///
  /// [transport] replaces the network transport *after* the egress checks
  /// (for tests); [lookup] replaces DNS resolution (for tests).
  DidWebsResolver({
    DidResolver? fallback,
    this.netPolicy = const NetPolicy(),
    this.timeout = defaultWebsTimeout,
    http.Client? transport,
    HostLookup? lookup,
  }) : fallback = fallback ?? UniversalDIDResolver.defaultResolver,
       _transport = transport,
       _lookup = lookup;

  /// Resolves DIDs that are not did:webs.
  final DidResolver fallback;

  /// Egress policy for the host the DID names. Strict by default.
  final NetPolicy netPolicy;

  /// Per-request timeout.
  final Duration timeout;

  final http.Client? _transport;
  final HostLookup? _lookup;

  @override
  Future<DidDocument> resolveDid(String did) async {
    if (!did.startsWith(_prefix)) return fallback.resolveDid(did);
    final resolution = await resolveWithMetadata(did);
    return DidDocument.fromJson(ssiDocument(resolution.didDocument));
  }

  /// Fetch `keri.cesr` and then `did.json` from the vetted host — both are
  /// required — verify the stream, derive the document and check `did.json`
  /// against it.
  ///
  /// Throws a [BlockedEndpointException] if the host fails the policy, and a
  /// [DidWebsError] otherwise; a deactivated DID is refused (kind
  /// `Deactivated`) at every version, since this is a document provider.
  Future<DidWebsResolution> resolveWithMetadata(String did) async {
    final urls = websArtifactUrls(did, netPolicy);
    final plaintext = urls.keriCesr.scheme == 'http';
    final client = GuardedHttpClient(
      policy: _artifactPolicy(netPolicy, plaintext),
      maxBytes: maxWebsArtifactBytes,
      timeout: timeout,
      label: _cesrLabel,
      lookup: _lookup,
      inner: _transport,
    );
    final Uint8List cesr;
    final Uint8List document;
    try {
      cesr = await _fetchArtifact(client, urls.keriCesrHref, _cesrLabel);
      document = await _fetchArtifact(client, urls.didJsonHref, _didJsonLabel);
    } finally {
      client.close();
    }
    final resolution = resolveDidWebsFromArtifacts(did, cesr, document);
    if (resolution.didDocumentMetadata['deactivated'] == true) {
      throw DidWebsError(
        'Deactivated',
        '${parseDidWebs(did).did} is deactivated',
      );
    }
    return resolution;
  }

  Future<Uint8List> _fetchArtifact(
    GuardedHttpClient client,
    String href,
    String label,
  ) async {
    DidWebsError fetchError(String why, {int? status}) => DidWebsError(
      'Fetch',
      'could not fetch $href: $why',
      status: status,
      url: href,
    );
    final http.StreamedResponse response;
    final Uint8List body;
    try {
      response = await client.send(http.Request('GET', Uri.parse(href)));
      body = await response.stream.toBytes();
    } on BlockedEndpointException catch (e) {
      switch (e.reason) {
        case BlockedReason.tooLarge:
          final declared = e.declaredBytes;
          throw fetchError(
            declared != null
                ? 'the $label declares $declared bytes, over the '
                      '$maxWebsArtifactBytes-byte cap'
                : 'the $label is over the $maxWebsArtifactBytes-byte cap',
          );
        case BlockedReason.timeout:
          throw fetchError('The operation was aborted due to timeout');
        case BlockedReason.invalidUrl:
          // The URL passed the policy; its host did not resolve.
          throw fetchError(e.message);
        default:
          rethrow;
      }
    } on DidWebsError {
      rethrow;
    } on Object catch (e) {
      throw fetchError('$e');
    }
    if (response.statusCode < 200 || response.statusCode > 299) {
      throw fetchError(
        'HTTP ${response.statusCode}',
        status: response.statusCode,
      );
    }
    return body;
  }
}

/// A resolved did:webs document as `ssi` can read it: a JSON-LD context
/// where it has none (`ssi` requires one; did:webs derives none), and
/// verification methods without a public key (a `ConditionalProof2022`
/// threshold method) and the references to them left out.
Map<String, Object?> ssiDocument(Map<String, Object?> document) {
  final out = <String, Object?>{
    if (!document.containsKey('@context'))
      '@context': const [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
      ],
    ...document,
  };
  final methods = document['verificationMethod'];
  if (methods is! List) return out;
  final kept = [
    for (final m in methods)
      if (m is Map && m['publicKeyJwk'] != null) m,
  ];
  final ids = {for (final m in kept) m['id']};
  out['verificationMethod'] = kept;
  for (final rel in const [
    'authentication',
    'assertionMethod',
    'keyAgreement',
    'capabilityInvocation',
    'capabilityDelegation',
  ]) {
    final refs = document[rel];
    if (refs is List) {
      out[rel] = [
        for (final r in refs)
          if (r is! String || ids.contains(r)) r,
      ];
    }
  }
  return out;
}
