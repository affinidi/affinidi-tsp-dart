import 'dart:collection';

import 'package:http/http.dart' as http;
import 'package:ssi/ssi.dart';

import 'net_guard.dart';

// `did:scid:vh:1` — a DID in its own right, verified by a did:webvh log.
//
// The identity is `did:scid:vh:1:<scid>`; `?src=<source>` is a locator, not
// part of the identity (VTI-KEY-160). Resolution derives the did:webvh form
// from the source, verifies that log with `ssi`'s did:webvh verifier, and
// returns the did:scid's own document under the bare DID (VTI-KEY-161). A
// bare DID resolves through the source this resolver last verified for its
// SCID, and an older copy of the log is refused (VTI-KEY-162).
//
// Ported from OpenVTC `vti-didcomm-js` `src/did-scid.js`, which mirrors
// `affinidi_did_common::scid` and `didwebvh-rs` `did_web.rs`. Change them
// together.
const String _prefix = 'did:scid:';
const String _vhPrefix = 'did:scid:vh:1:';
const String _webvhPrefix = 'did:webvh:';

/// Default upper bound on SCIDs a [ScidSourceBook] remembers.
const int defaultScidSourceCapacity = 100000;

// ─── The `src` locator ──────────────────────────────────────────────────

/// `(did, src, fragment)` for a did:scid DID URL whose only query parameter
/// is `src`, or null. `fragment` keeps its leading `#`, or is empty.
(String, String, String)? _splitSrc(String didUrl) {
  if (!didUrl.startsWith(_prefix)) return null;
  final q = didUrl.indexOf('?');
  if (q < 0) return null;
  final did = didUrl.substring(0, q);
  final rest = didUrl.substring(q + 1);
  final hash = rest.indexOf('#');
  final query = hash < 0 ? rest : rest.substring(0, hash);
  final fragment = hash < 0 ? '' : rest.substring(hash);
  if (!query.startsWith('src=')) return null;
  final src = query.substring(4);
  if (src.isEmpty || src.contains('&')) return null;
  return (did, src, fragment);
}

/// Removes the `src` locator from a did:scid DID URL, keeping any fragment:
/// `did:scid:vh:1:Qm?src=example.com#key-1` becomes `did:scid:vh:1:Qm#key-1`.
/// Anything else is returned unchanged.
String stripScidSrc(String didUrl) {
  final parts = _splitSrc(didUrl);
  return parts == null ? didUrl : parts.$1 + parts.$3;
}

/// The `src` locator of a did:scid DID URL, or null if it carries none.
String? scidSrc(String didUrl) => _splitSrc(didUrl)?.$2;

/// Gives a bare did:scid reference the locator [src], before any fragment.
/// A reference that is not a bare did:scid, or already carries a query or a
/// path, is returned unchanged.
String withScidSrc(String reference, String src) {
  if (!reference.startsWith(_prefix) ||
      reference.contains('?') ||
      reference.contains('/')) {
    return reference;
  }
  final hash = reference.indexOf('#');
  return hash < 0
      ? '$reference?src=$src'
      : '${reference.substring(0, hash)}?src=$src${reference.substring(hash)}';
}

/// Whether two references name the same thing, ignoring a did:scid `src`.
bool sameReference(String a, String b) =>
    a == b || stripScidSrc(a) == stripScidSrc(b);

/// The identity a reference names: no fragment, and no did:scid `src`.
String scidIdentity(String reference) =>
    stripScidSrc(reference.split('#').first);

// ─── did:scid ↔ did:webvh ───────────────────────────────────────────────

final RegExp _scidBad = RegExp('[:/?]');
final RegExp _srcBad = RegExp('[&?]');
final RegExp _port = RegExp(r'^\+?\d+$');
final RegExp _trailingSlashes = RegExp(r'/+$');

/// The did:webvh form of a `did:scid:vh:1:<scid>?src=<source>` ID or DID
/// URL, carrying a `#fragment` across, or null for anything else: another
/// method, format or version, no `src`, an empty SCID, another query
/// parameter, or a malformed `src`. `src` may carry an `https://` or
/// `http://` scheme, a trailing `/`, or a literal `:` before a port.
String? scidToWebvhDid(String id) {
  if (!id.startsWith(_vhPrefix)) return null;
  var rest = id.substring(_vhPrefix.length);
  String? fragment;
  final hash = rest.indexOf('#');
  if (hash >= 0) {
    fragment = rest.substring(hash + 1);
    rest = rest.substring(0, hash);
  }
  final marker = rest.indexOf('?src=');
  if (marker < 0) return null;
  final scid = rest.substring(0, marker);
  var src = rest.substring(marker + 5);
  if (scid.isEmpty || _scidBad.hasMatch(scid) || _srcBad.hasMatch(src)) {
    return null;
  }

  if (src.startsWith('https://')) {
    src = src.substring(8);
  } else if (src.startsWith('http://')) {
    src = src.substring(7);
  }
  src = src.replaceAll(_trailingSlashes, '');
  final slash = src.indexOf('/');
  var host = slash < 0 ? src : src.substring(0, slash);
  final path = slash < 0
      ? null
      : src.substring(slash + 1).replaceAll(_trailingSlashes, '');
  final colon = host.indexOf(':');
  if (colon >= 0) {
    final port = host.substring(colon + 1);
    final number = _port.hasMatch(port) ? int.tryParse(port) : null;
    if (number == null || number > 65535) return null;
    host = '${host.substring(0, colon)}%3A$port';
  }
  if (host.isEmpty || host.startsWith('%')) return null;

  var webvh = '$_webvhPrefix$scid:$host';
  if (path != null && path.isNotEmpty) {
    if (path.split('/').any((segment) => segment.isEmpty)) return null;
    webvh += ':${path.replaceAll('/', ':')}';
  }
  if (fragment != null) webvh += '#$fragment';
  return webvh;
}

/// The `did:scid:vh:1:<scid>?src=<source>` DID URL of a did:webvh DID, or
/// null when it has no SCID and host.
String? webvhToScidDidUrl(String webvhDid) {
  if (!webvhDid.startsWith(_webvhPrefix)) return null;
  final rest = webvhDid.substring(_webvhPrefix.length);
  final colon = rest.indexOf(':');
  if (colon < 0) return null;
  return '$_vhPrefix${rest.substring(0, colon)}'
      '?src=${rest.substring(colon + 1).replaceAll(':', '/')}';
}

/// Expresses a did:webvh DID document (as JSON) as the document of its
/// did:scid DID.
///
/// - `id` becomes `did:scid:vh:1:<scid>`, with no `src`.
/// - Every string that is exactly the did:webvh DID, or that DID followed by
///   `#`, is rewritten under the did:scid DID. Other DIDs and URLs, relative
///   references and DID URLs with a path are left as they are.
/// - `alsoKnownAs` keeps the controller's entries, drops the bare did:scid
///   itself, and gains the did:scid DID URL of the log's location and the
///   did:webvh DID, where absent.
///
/// Returns a new map; [state] is not modified.
Map<String, dynamic> toScidDidDocument(Map<String, dynamic> state) {
  final id = state['id'];
  final webvhDid = id is String && id.startsWith(_webvhPrefix) ? id : null;
  if (webvhDid == null) {
    throw SsiException(
      message: "did:scid: couldn't find a did:webvh id attribute",
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }
  final scidUrl = webvhToScidDidUrl(webvhDid);
  final marker = scidUrl?.indexOf('?src=') ?? -1;
  if (scidUrl == null || marker < 0) {
    throw SsiException(
      message: 'did:scid: $webvhDid has no SCID and host to convert',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }
  final scidDid = scidUrl.substring(0, marker);

  Object? rewrite(Object? value) {
    if (value is String) {
      if (value == webvhDid) return scidDid;
      if (value.startsWith('$webvhDid#')) {
        return '$scidDid${value.substring(webvhDid.length)}';
      }
      return value;
    }
    if (value is List) return value.map(rewrite).toList();
    if (value is Map) {
      return <String, dynamic>{
        for (final e in value.entries) e.key as String: rewrite(e.value),
      };
    }
    return value;
  }

  final doc = rewrite(state)! as Map<String, dynamic>;

  final List<Object?> aliases;
  final aka = state['alsoKnownAs'];
  if (aka == null) {
    aliases = [];
  } else if (aka is List) {
    aliases = aka.where((alias) => alias != scidDid).toList();
  } else {
    throw SsiException(
      message: 'did:scid: alsoKnownAs is not an array',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }
  for (final alias in [scidUrl, webvhDid]) {
    if (!aliases.contains(alias)) aliases.add(alias);
  }
  doc['alsoKnownAs'] = aliases;
  return doc;
}

// ─── Source book ────────────────────────────────────────────────────────

/// What a resolver has verified about each did:scid SCID: where its log was
/// last found, and the latest version seen. In memory and bounded; a caller
/// that must resolve a bare did:scid across restarts records the source it
/// learned and seeds it back with [addSource].
final class ScidSourceBook {
  /// Creates a book holding at most [capacity] SCIDs, forgetting the oldest
  /// first.
  ScidSourceBook({this.capacity = defaultScidSourceCapacity}) {
    if (capacity < 1) {
      throw ArgumentError.value(capacity, 'capacity', 'must be positive');
    }
  }

  /// Maximum number of SCIDs held.
  final int capacity;

  final LinkedHashMap<String, _ScidEntry> _seen = LinkedHashMap();

  void _makeRoom() {
    while (_seen.length >= capacity) {
      _seen.remove(_seen.keys.first);
    }
  }

  /// The source last recorded for the SCID of [did], in `src` form.
  String? source(String did) => _seen[scidIdentity(did)]?.source;

  /// Records the `src` of a did:scid DID URL as where to look for that SCID,
  /// without changing the latest version verified for it. Returns false when
  /// [didUrl] carries no `src`.
  bool addSource(String didUrl) {
    final src = scidSrc(didUrl);
    if (src == null) return false;
    final k = scidIdentity(didUrl);
    final entry = _seen[k];
    if (entry != null) {
      entry.source = src;
    } else {
      _makeRoom();
      _seen[k] = _ScidEntry(src);
    }
    return true;
  }

  /// Accepts a verified resolution, or throws if it is older than one
  /// already verified for the same SCID.
  void accept(String did, String source, int versionNumber, String versionId) {
    final k = scidIdentity(did);
    final latest = _seen[k];
    final latestNumber = latest?.versionNumber;
    if (latestNumber != null &&
        (versionNumber < latestNumber ||
            (versionNumber == latestNumber &&
                versionId != latest!.versionId))) {
      throw DidScidResolutionException(
        'did:scid resolve: $k: the log at $source is at version '
        '$versionId, behind ${latest!.versionId} already verified for '
        'this SCID',
        DidScidFailure.rollback,
      );
    }
    if (latest == null) _makeRoom();
    _seen.remove(k);
    _seen[k] = _ScidEntry(source)
      ..versionNumber = versionNumber
      ..versionId = versionId;
  }

  /// Number of SCIDs held.
  int get length => _seen.length;
}

final class _ScidEntry {
  _ScidEntry(this.source);
  String source;
  int? versionNumber;
  String? versionId;
}

// ─── Resolution ─────────────────────────────────────────────────────────

/// Default cap on the entries of a did:webvh log a did:scid resolves
/// through. The reference resolvers bound the log only by its size
/// ([defaultMaxArtifactBytes]); this also bounds the verification work.
const int defaultMaxLogEntries = 1000;

/// Why a did:scid did not resolve.
enum DidScidFailure {
  /// The DID or DID URL is not a usable `did:scid:vh:1` reference.
  malformed,

  /// Only the `vh:1` format is supported.
  unsupportedFormat,

  /// A bare DID whose source this resolver has not verified.
  unknownSource,

  /// The log is too large or has too many entries.
  tooLarge,

  /// The verified log is not the log of the requested DID.
  mismatch,

  /// The DID is deactivated.
  deactivated,

  /// The log is older than one already verified for this SCID.
  rollback,

  /// The log did not verify.
  invalidLog,
}

/// Thrown when a did:scid does not resolve. Egress refusals throw
/// [BlockedEndpointException] instead; both are [SsiException]s.
class DidScidResolutionException extends SsiException {
  /// Creates the exception.
  DidScidResolutionException(String message, this.failure, {Object? cause})
    : super(
        message: message,
        code: SsiExceptionType.unableToResolveDid.code,
        originalMessage: cause?.toString(),
      );

  /// What went wrong.
  final DidScidFailure failure;

  @override
  String toString() => 'DidScidResolutionException(${failure.name}): $message';
}

/// Whether the DID is deactivated as of version [versionNumber] of [log].
bool isWebvhDeactivatedAt(DidWebVhLog log, int versionNumber) {
  var deactivated = false;
  for (final entry in log.entries) {
    final n = int.tryParse(entry.versionId.split('-').first);
    if (n == null || n > versionNumber) break;
    deactivated = entry.parameters.deactivated ?? deactivated;
  }
  return deactivated;
}

bool _isPortable(DidWebVhLog log, int versionNumber) {
  var portable = false;
  for (final entry in log.entries) {
    final n = int.tryParse(entry.versionId.split('-').first);
    if (n == null || n > versionNumber) break;
    portable = entry.parameters.portable ?? portable;
  }
  return portable;
}

String _scidOfWebvh(String webvhDid) {
  final rest = webvhDid.substring(_webvhPrefix.length);
  final colon = rest.indexOf(':');
  return colon < 0 ? '' : rest.substring(0, colon);
}

/// Resolves `did:scid:vh:1` DIDs and DID URLs, and delegates everything
/// else to [fallback].
///
/// A DID URL with `?src=` resolves from that source; a bare DID resolves
/// from the source [book] last verified for its SCID.
///
/// `src` comes from whoever sent the reference, so every request the
/// resolver makes (the log, and anything `ssi` fetches while verifying it,
/// such as `did-witness.json`) goes through a [GuardedHttpClient]: HTTPS
/// only, public addresses only (checked after DNS, and the connection pinned
/// to the checked address), no redirects, a [maxBytes] cap and a [timeout].
/// [netPolicy] relaxes this for local development; the default is strict.
///
/// The verified log must be the log of the requested DID: its SCID must
/// equal the requested SCID, and its DID must equal the requested did:webvh
/// unless the log declares itself `portable` (a portable DID may have moved
/// host, which the reference resolvers allow).
///
/// [book] is in memory, as in the reference resolvers (vti-didcomm-js
/// `createScidSourceBook`, the Rust `ScidSourceBook`): it refuses a source
/// serving an older log than this process has already verified for the
/// SCID, it is bounded, and it forgets the oldest SCID first. A caller that
/// needs rollback protection across restarts persists the sources and
/// versions it learns and seeds a book with them.
final class DidScidResolver implements DidResolver {
  /// Creates a resolver delegating other methods to [fallback], by default
  /// `ssi`'s universal resolver.
  ///
  /// [transport] replaces the network transport *after* the egress checks
  /// (for tests); [lookup] replaces DNS resolution (for tests).
  DidScidResolver({
    DidResolver? fallback,
    ScidSourceBook? book,
    this.netPolicy = const NetPolicy(),
    this.maxBytes = defaultMaxArtifactBytes,
    this.maxLogEntries = defaultMaxLogEntries,
    this.timeout = defaultRequestTimeout,
    http.Client? transport,
    HostLookup? lookup,
  }) : fallback = fallback ?? UniversalDIDResolver.defaultResolver,
       book = book ?? ScidSourceBook(),
       _transport = transport,
       _lookup = lookup;

  /// Resolves DIDs that are not did:scid.
  final DidResolver fallback;

  /// Sources and latest versions verified so far.
  final ScidSourceBook book;

  /// Egress policy for the `src` host. Strict by default.
  final NetPolicy netPolicy;

  /// Largest log or witness file accepted, in bytes.
  final int maxBytes;

  /// Most log entries accepted.
  final int maxLogEntries;

  /// Per-request timeout.
  final Duration timeout;

  final http.Client? _transport;
  final HostLookup? _lookup;

  GuardedHttpClient _guarded() => GuardedHttpClient(
    policy: netPolicy,
    maxBytes: maxBytes,
    timeout: timeout,
    label: 'did:scid source',
    lookup: _lookup,
    inner: _transport,
  );

  @override
  Future<DidDocument> resolveDid(String did) async {
    if (!did.startsWith(_prefix)) return fallback.resolveDid(did);
    try {
      return await _resolve(did);
    } on SsiException {
      rethrow;
    } on Object catch (e) {
      // Any other failure on untrusted input is a resolution failure, not a
      // crash.
      throw DidScidResolutionException(
        'did:scid resolve: ${_shown(did)} did not resolve',
        DidScidFailure.malformed,
        cause: e,
      );
    }
  }

  Future<DidDocument> _resolve(String did) async {
    if (!did.startsWith(_vhPrefix)) {
      throw DidScidResolutionException(
        'did:scid resolve: only the vh:1 format is supported',
        DidScidFailure.unsupportedFormat,
      );
    }
    final bare = scidIdentity(did);
    final src = scidSrc(did) ?? book.source(bare);
    if (src == null) {
      throw DidScidResolutionException(
        'did:scid resolve: no source is known for ${_shown(bare)}; resolve '
        'it once with its ?src= DID URL',
        DidScidFailure.unknownSource,
      );
    }
    final webvhDid = scidToWebvhDid('$bare?src=$src');
    if (webvhDid == null) {
      throw DidScidResolutionException(
        'did:scid resolve: ${_shown(did)} is not a usable did:scid:vh:1 DID '
        'URL',
        DidScidFailure.malformed,
      );
    }
    final requestedScid = bare.substring(_vhPrefix.length);

    // Check the source host against the egress policy before anything else
    // parses it. The log itself is always fetched over HTTPS from the
    // did:webvh location; a scheme written in `src` only locates it.
    final location = webvhDid.substring(
      _webvhPrefix.length + requestedScid.length + 1,
    );
    final hostPort = location.split(':').first.replaceAll('%3A', ':');
    final Uri sourceUrl;
    try {
      sourceUrl = Uri.parse('https://$hostPort/');
    } on FormatException catch (e) {
      throw DidScidResolutionException(
        'did:scid resolve: ${_shown(src)} is not a usable source',
        DidScidFailure.malformed,
        cause: e,
      );
    }
    assertSafeEndpoint(sourceUrl, netPolicy, label: 'did:scid source');

    final client = _guarded();
    final DidWebVhLog log;
    final DidDocument webvhDoc;
    final DidWebVhDocumentMetadata meta;
    try {
      // Everything ssi fetches while verifying (the witness file, a witness
      // DID) uses `http.Client()`; inside this zone that is the guard too.
      (log, webvhDoc, meta) = await http.runWithClient(
        () => _fetchAndVerify(webvhDid, client),
        _guarded,
      );
    } finally {
      client.close();
    }

    final logDid = webvhDoc.id;
    final versionId = meta.versionId ?? '';
    final versionNumber =
        meta.versionNumber ?? int.tryParse(versionId.split('-').first);
    if (versionNumber == null) {
      throw DidScidResolutionException(
        'did:scid resolve: the log has no usable version',
        DidScidFailure.invalidLog,
      );
    }
    if ((meta.scid != null && meta.scid != requestedScid) ||
        !logDid.startsWith(_webvhPrefix) ||
        _scidOfWebvh(logDid) != requestedScid) {
      throw DidScidResolutionException(
        'did:scid resolve: the log at ${_shown(src)} is not the log of '
        '${_shown(bare)}',
        DidScidFailure.mismatch,
      );
    }
    if (logDid != webvhDid && !_isPortable(log, versionNumber)) {
      throw DidScidResolutionException(
        'did:scid resolve: the log at ${_shown(src)} names ${_shown(logDid)}, '
        'not ${_shown(webvhDid)}, and is not portable',
        DidScidFailure.mismatch,
      );
    }
    if (isWebvhDeactivatedAt(log, versionNumber)) {
      throw DidScidResolutionException(
        'did:scid resolve failed: ${_shown(webvhDid)} has been deactivated',
        DidScidFailure.deactivated,
      );
    }

    final source = webvhToScidDidUrl(logDid)?.split('?src=').last;
    if (source == null) {
      throw DidScidResolutionException(
        'did:scid resolve: ${_shown(logDid)} has no SCID and host',
        DidScidFailure.invalidLog,
      );
    }
    book.accept(bare, source, versionNumber, versionId);
    return DidDocument.fromJson(toScidDidDocument(webvhDoc.toJson()));
  }

  Future<(DidWebVhLog, DidDocument, DidWebVhDocumentMetadata)> _fetchAndVerify(
    String webvhDid,
    http.Client client,
  ) async {
    final url = DidWebVhUrl.fromUrlString(webvhDid);
    final res = await client.get(
      Uri.parse(url.jsonLogFileHttpsUrlString),
      headers: {'Accept': 'application/jsonl, application/json'},
    );
    if (res.statusCode < 200 || res.statusCode >= 300) {
      throw DidScidResolutionException(
        'did:scid resolve: the log for ${_shown(webvhDid)} is not available '
        '(HTTP ${res.statusCode})',
        DidScidFailure.invalidLog,
      );
    }
    final lines = res.body.split('\n').where((l) => l.trim().isNotEmpty).length;
    if (lines > maxLogEntries) {
      throw DidScidResolutionException(
        'did:scid resolve: the log for ${_shown(webvhDid)} has $lines '
        'entries, more than $maxLogEntries',
        DidScidFailure.tooLarge,
      );
    }
    final log = DidWebVhLog.fromJsonLines(res.body);
    final options = DidWebVhResolutionOptions(httpClient: client)
      ..resolvingDidUrl = url;
    final (doc, meta, _) = await log.verify(options: options);
    return (log, doc, meta);
  }
}

// Untrusted values in messages: bounded, with control characters removed.
String _shown(String value) {
  final clean = value.replaceAll(RegExp(r'[\x00-\x1f\x7f]'), '?');
  return clean.length > 160 ? '${clean.substring(0, 160)}…' : clean;
}
