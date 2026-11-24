// Egress guard for URLs this library did not choose.
//
// A did:scid `?src=` (and the did:webvh log location it names) comes from a
// peer, not from the caller, so before dialing it the resolver checks it here:
//
//   - the scheme is `https` (`http` only with `allowInsecure`);
//   - there is no userinfo;
//   - the host is not a special-use or single-label name (`localhost`,
//     `*.local`, `*.internal`, `*.home.arpa`, `intranet`) and not an IP
//     literal in a non-public range (loopback, RFC 1918, link-local / cloud
//     metadata, CGNAT, multicast, unspecified, IPv4-mapped / -compatible
//     IPv6, NAT64, 6to4, ULA, …), unless `allowPrivate` is set;
//   - if `allowHosts` is given, the host matches one of its entries;
//   - every address the host resolves to is public (unless `allowPrivate`),
//     and the connection is made to that vetted address, so a second DNS
//     answer cannot rebind it;
//   - redirects are never followed, responses are capped in size, and each
//     request has a timeout.
//
// Ported from OpenVTC vti-didcomm-js `src/net-guard.js` and
// `src/net-guard-node.js` (which mirror the affinidi-did-web classifier);
// the size cap and timeout match didwebvh-rs (`DEFAULT_MAX_RESPONSE_BYTES`,
// 10 s). Change them together.
import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:ssi/ssi.dart';

/// Default cap on a fetched artifact (a did:webvh log or witness file):
/// 200 KiB, as didwebvh-rs `DEFAULT_MAX_RESPONSE_BYTES`.
const int defaultMaxArtifactBytes = 200 * 1024;

/// Default per-request timeout, as didwebvh-rs and vti-didcomm-js.
const Duration defaultRequestTimeout = Duration(seconds: 10);

/// Why an endpoint was refused.
enum BlockedReason {
  /// Not an absolute URL, or no host.
  invalidUrl,

  /// The scheme is not allowed.
  scheme,

  /// The URL carries credentials.
  userinfo,

  /// The host is, or resolves to, a non-public address.
  privateAddress,

  /// The host is a local-only name.
  privateName,

  /// The host is not in `allowHosts`.
  notAllowlisted,

  /// The endpoint answered with a redirect.
  redirect,

  /// The response is larger than the cap.
  tooLarge,

  /// The request timed out.
  timeout,
}

/// Thrown when an endpoint fails the egress policy.
class BlockedEndpointException extends SsiException {
  /// Creates the exception.
  BlockedEndpointException(String message, this.reason, {this.host})
    : super(message: message, code: SsiExceptionType.unableToResolveDid.code);

  /// Why the endpoint was refused.
  final BlockedReason reason;

  /// The canonical host that was checked, if known.
  final String? host;

  @override
  String toString() => 'BlockedEndpointException(${reason.name}): $message';
}

/// Network policy for endpoints the caller did not choose. Every field
/// defaults to the strict setting.
final class NetPolicy {
  /// Creates a policy.
  const NetPolicy({
    this.allowInsecure = false,
    this.allowPrivate = false,
    this.allowHosts,
  });

  /// Also permit plaintext `http`. Scheme only: it does not admit private
  /// hosts.
  final bool allowInsecure;

  /// Permit special-use names and non-public addresses. Local development
  /// only.
  final bool allowPrivate;

  /// If set, the host must match an entry: an exact host or a `*.` suffix
  /// (which matches subdomains, not the apex). An empty list admits nothing.
  /// It only narrows: it never re-admits a blocked address.
  final List<String>? allowHosts;
}

// ─── IP classification ─────────────────────────────────────────────────

const List<(String, int)> _v4BlockedText = [
  ('0.0.0.0', 8), //        "this network"
  ('10.0.0.0', 8), //       private (RFC 1918)
  ('100.64.0.0', 10), //    shared address space / CGNAT
  ('127.0.0.0', 8), //      loopback
  ('169.254.0.0', 16), //   link-local (cloud metadata)
  ('172.16.0.0', 12), //    private (RFC 1918)
  ('192.0.0.0', 24), //     IETF protocol assignments
  ('192.0.2.0', 24), //     documentation (TEST-NET-1)
  ('192.168.0.0', 16), //   private (RFC 1918)
  ('198.18.0.0', 15), //    benchmarking
  ('198.51.100.0', 24), //  documentation (TEST-NET-2)
  ('203.0.113.0', 24), //   documentation (TEST-NET-3)
  ('224.0.0.0', 4), //      multicast
  ('240.0.0.0', 4), //      reserved, incl. broadcast
];

final List<(int, int)> _v4Blocked = [
  for (final (net, prefix) in _v4BlockedText)
    (_v4ToInt(_parseIpv4(net)!), prefix),
];

/// True if [ip] is an address the resolver must not dial by default.
///
/// Accepts a dotted-quad IPv4 address or an IPv6 address (brackets
/// optional). IPv6 forms that embed an IPv4 address are judged by the
/// embedded address. Fails closed: anything that is not a well-formed IP
/// literal returns true.
bool isBlockedIp(String ip) {
  final v4 = _parseIpv4(ip);
  if (v4 != null) return _v4BlockedInt(_v4ToInt(v4));
  final v6 = _parseIpv6(ip);
  if (v6 != null) return _v6Blocked(v6);
  return true;
}

bool _v4BlockedInt(int n) {
  for (final (net, prefix) in _v4Blocked) {
    final shift = 32 - prefix;
    if ((n >> shift) == (net >> shift)) return true;
  }
  return false;
}

bool _v6Blocked(List<int> g) {
  bool zeros(int from, int to) => g.sublist(from, to).every((x) => x == 0);
  bool embedded(int hi, int lo) => _v4BlockedInt((hi << 16) + lo);
  if (zeros(0, 6)) return embedded(g[6], g[7]); // ::/96 incl. :: and ::1
  if (zeros(0, 5) && g[5] == 0xffff) return embedded(g[6], g[7]); // mapped
  if (zeros(0, 4) && g[4] == 0xffff && g[5] == 0) {
    return embedded(g[6], g[7]); // IPv4-translated
  }
  if (g[0] == 0x64 && g[1] == 0xff9b && zeros(2, 6)) {
    return embedded(g[6], g[7]); // NAT64 well-known
  }
  if (g[0] == 0x64 && g[1] == 0xff9b && g[2] == 1) return true; // local NAT64
  if (g[0] == 0x2002) return embedded(g[1], g[2]); // 6to4
  if (g[0] == 0x2001 && g[1] < 0x200) return true; // IETF assignments
  if (g[0] == 0x2001 && g[1] == 0xdb8) return true; // documentation
  if (g[0] == 0x3fff && (g[1] & 0xf000) == 0) return true; // documentation
  // Everything outside 2000::/3 global unicast is reserved or local
  // (ULA, link-local, site-local, multicast, discard).
  if ((g[0] & 0xe000) != 0x2000) return true;
  return false;
}

final RegExp _ipv4 = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$');

// Strict dotted-quad: four decimal octets, no leading zeros.
List<int>? _parseIpv4(String s) {
  final m = _ipv4.firstMatch(s);
  if (m == null) return null;
  final out = <int>[];
  for (var i = 1; i <= 4; i++) {
    final part = m.group(i)!;
    if (part.length > 1 && part.startsWith('0')) return null;
    final n = int.parse(part);
    if (n > 255) return null;
    out.add(n);
  }
  return out;
}

int _v4ToInt(List<int> o) => (o[0] << 24) + (o[1] << 16) + (o[2] << 8) + o[3];

final RegExp _v6Chars = RegExp(r'^[0-9A-Fa-f:.]+$');
final RegExp _v6Group = RegExp(r'^[0-9A-Fa-f]{1,4}$');

// RFC 4291 text form to eight 16-bit groups, or null. Zone IDs are refused.
List<int>? _parseIpv6(String input) {
  var s = input;
  if (s.startsWith('[') && s.endsWith(']')) s = s.substring(1, s.length - 1);
  if (!_v6Chars.hasMatch(s)) return null;
  final lastColon = s.lastIndexOf(':');
  if (lastColon == -1) return null;
  var tail = <int>[];
  if (s.contains('.')) {
    final v4 = _parseIpv4(s.substring(lastColon + 1));
    if (v4 == null) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.substring(0, lastColon + 1);
    if (!s.endsWith('::')) s = s.substring(0, s.length - 1);
  }
  final want = 8 - tail.length;
  List<int>? groups(String part) {
    if (part.isEmpty) return [];
    final out = <int>[];
    for (final piece in part.split(':')) {
      if (!_v6Group.hasMatch(piece)) return null;
      out.add(int.parse(piece, radix: 16));
    }
    return out;
  }

  final gap = s.indexOf('::');
  if (gap == -1) {
    final all = groups(s);
    if (all == null || all.length != want) return null;
    return [...all, ...tail];
  }
  if (gap != s.lastIndexOf('::')) return null;
  final head = groups(s.substring(0, gap));
  final rest = groups(s.substring(gap + 2));
  if (head == null || rest == null) return null;
  final fill = want - head.length - rest.length;
  if (fill < 1) return null;
  return [...head, ...List.filled(fill, 0), ...rest, ...tail];
}

// ─── URL policy ────────────────────────────────────────────────────────

const List<String> _blockedNameSuffixes = [
  '.localhost',
  '.local',
  '.internal',
  '.home.arpa',
];

String _canonicalHost(String hostname) {
  var h = hostname.toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) return h.substring(1, h.length - 1);
  while (h.endsWith('.')) {
    h = h.substring(0, h.length - 1);
  }
  return h;
}

bool _isIpLiteral(String host) =>
    _parseIpv4(host) != null || _parseIpv6(host) != null;

// A bare single-label host is never a public FQDN.
bool _isBlockedName(String host) =>
    !host.contains('.') || _blockedNameSuffixes.any(host.endsWith);

bool _hostAllowed(String host, List<String> allowHosts) {
  for (final raw in allowHosts) {
    final entry = raw.trim().toLowerCase();
    if (entry.startsWith('*.')) {
      final suffix = entry.substring(1);
      if (host.length > suffix.length && host.endsWith(suffix)) return true;
    } else if (host == _canonicalHost(entry)) {
      return true;
    }
  }
  return false;
}

/// Checks [url] against [policy] before dialing it, and returns its
/// canonical host. Throws [BlockedEndpointException] if it is not allowed.
String assertSafeEndpoint(
  Uri url,
  NetPolicy policy, {
  String label = 'endpoint',
}) {
  final shown =
      '${url.scheme}://${url.host}${url.hasPort ? ':${url.port}' : ''}${url.path}';
  BlockedEndpointException refuse(
    BlockedReason reason,
    String why, [
    String? host,
  ]) => BlockedEndpointException(
    'net-guard: $label $shown refused: $why',
    reason,
    host: host,
  );

  if (!url.isAbsolute || url.host.isEmpty) {
    throw BlockedEndpointException(
      'net-guard: $label endpoint is not a valid absolute URL',
      BlockedReason.invalidUrl,
    );
  }
  final scheme = url.scheme.toLowerCase();
  if (scheme != 'https' && !(scheme == 'http' && policy.allowInsecure)) {
    throw refuse(
      BlockedReason.scheme,
      'scheme $scheme is not allowed${scheme == 'http' ? ' (plaintext needs allowInsecure)' : ''}',
    );
  }
  if (url.userInfo.isNotEmpty) {
    throw refuse(
      BlockedReason.userinfo,
      'credentials in the URL are not allowed',
    );
  }
  final host = _canonicalHost(url.host);
  if (!policy.allowPrivate) {
    if (_isIpLiteral(host)) {
      if (isBlockedIp(host)) {
        throw refuse(
          BlockedReason.privateAddress,
          '$host is not a public address',
          host,
        );
      }
    } else if (_isBlockedName(host)) {
      throw refuse(
        BlockedReason.privateName,
        '$host is a local-only name',
        host,
      );
    }
  }
  final allow = policy.allowHosts;
  if (allow != null && !_hostAllowed(host, allow)) {
    throw refuse(
      BlockedReason.notAllowlisted,
      '$host is not in allowHosts',
      host,
    );
  }
  return host;
}

/// Resolves a host name to its addresses. Injectable for tests.
typedef HostLookup = Future<List<InternetAddress>> Function(String host);

Future<List<InternetAddress>> _systemLookup(String host) =>
    InternetAddress.lookup(host);

/// An [http.Client] that applies [NetPolicy] to every request: the URL check,
/// a DNS check of every resolved address, a connection pinned to the vetted
/// address, no redirects, a response size cap and a timeout.
///
/// With [inner] set, the request is sent through it after the URL and DNS
/// checks (for tests, or a caller's own transport); redirects, the size cap
/// and the timeout still apply.
final class GuardedHttpClient extends http.BaseClient {
  /// Creates a guarded client.
  GuardedHttpClient({
    this.policy = const NetPolicy(),
    this.maxBytes = defaultMaxArtifactBytes,
    this.timeout = defaultRequestTimeout,
    this.label = 'endpoint',
    HostLookup? lookup,
    this.inner,
  }) : lookup = lookup ?? _systemLookup;

  /// The egress policy.
  final NetPolicy policy;

  /// Largest response body accepted, in bytes.
  final int maxBytes;

  /// Per-request timeout, covering connect, headers and body.
  final Duration timeout;

  /// Names the endpoint in error messages.
  final String label;

  /// Resolves host names.
  final HostLookup lookup;

  /// Optional transport used after the URL and DNS checks.
  final http.Client? inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final url = request.url;
    final host = assertSafeEndpoint(url, policy, label: label);
    try {
      return await _send(request, url, host).timeout(timeout);
    } on TimeoutException {
      throw BlockedEndpointException(
        'net-guard: $label ${url.host} timed out after ${timeout.inSeconds}s',
        BlockedReason.timeout,
        host: host,
      );
    }
  }

  Future<http.StreamedResponse> _send(
    http.BaseRequest request,
    Uri url,
    String host,
  ) async {
    final address = await _vettedAddress(host);
    final out = http.Request(request.method, url)
      ..followRedirects = false
      ..maxRedirects = 0
      ..headers.addAll(request.headers);
    if (request is http.Request) out.bodyBytes = request.bodyBytes;

    final http.StreamedResponse resp;
    final transport = inner;
    if (transport != null) {
      resp = await transport.send(out);
    } else {
      resp = await _pinnedSend(out, address);
    }

    if (resp.statusCode >= 300 && resp.statusCode < 400) {
      unawaited(resp.stream.drain<void>().catchError((_) {}));
      throw BlockedEndpointException(
        'net-guard: $label ${url.host} answered with a redirect '
        '(${resp.statusCode}); redirects are not followed',
        BlockedReason.redirect,
        host: host,
      );
    }
    final length = resp.contentLength;
    if (length != null && length > maxBytes) {
      unawaited(resp.stream.drain<void>().catchError((_) {}));
      throw _tooLarge(url, host);
    }
    // Read the body now, under the cap, so the timeout covers it too.
    final body = <int>[];
    await for (final chunk in resp.stream) {
      body.addAll(chunk);
      if (body.length > maxBytes) throw _tooLarge(url, host);
    }
    return http.StreamedResponse(
      Stream.value(body),
      resp.statusCode,
      contentLength: body.length,
      request: resp.request,
      headers: resp.headers,
      reasonPhrase: resp.reasonPhrase,
    );
  }

  BlockedEndpointException _tooLarge(Uri url, String host) =>
      BlockedEndpointException(
        'net-guard: $label ${url.host} response exceeds $maxBytes bytes',
        BlockedReason.tooLarge,
        host: host,
      );

  /// The address to connect to: the literal itself, or the first answer for
  /// a name once every answer has been checked.
  Future<InternetAddress> _vettedAddress(String host) async {
    if (_isIpLiteral(host)) return InternetAddress(host);
    final List<InternetAddress> answers;
    try {
      answers = await lookup(host);
    } on Object catch (e) {
      throw BlockedEndpointException(
        'net-guard: $label host $host did not resolve: $e',
        BlockedReason.invalidUrl,
        host: host,
      );
    }
    if (answers.isEmpty) {
      throw BlockedEndpointException(
        'net-guard: $label host $host resolved to no addresses',
        BlockedReason.invalidUrl,
        host: host,
      );
    }
    if (!policy.allowPrivate) {
      for (final a in answers) {
        if (isBlockedIp(a.address)) {
          throw BlockedEndpointException(
            'net-guard: $label host $host refused: it resolves to non-public '
            'address ${a.address}',
            BlockedReason.privateAddress,
            host: host,
          );
        }
      }
    }
    return answers.first;
  }

  /// Sends through dart:io, connecting to [address] and verifying TLS
  /// against the URL's host, with no proxy and no redirects.
  Future<http.StreamedResponse> _pinnedSend(
    http.Request request,
    InternetAddress address,
  ) async {
    final url = request.url;
    final port = url.hasPort ? url.port : (url.scheme == 'https' ? 443 : 80);
    final io = HttpClient()
      ..findProxy = ((_) => 'DIRECT')
      ..connectionTimeout = timeout
      ..connectionFactory = (uri, proxyHost, proxyPort) async {
        final task = await Socket.startConnect(address, port);
        if (uri.scheme != 'https') return task;
        return ConnectionTask.fromSocket(
          task.socket.then((s) => SecureSocket.secure(s, host: uri.host)),
          task.cancel,
        );
      };
    try {
      final req = await io.openUrl(request.method, url)
        ..followRedirects = false;
      request.headers.forEach(req.headers.set);
      req.add(request.bodyBytes);
      final res = await req.close();
      final headers = <String, String>{};
      res.headers.forEach((k, v) => headers[k] = v.join(','));
      final bytes = <int>[];
      await for (final chunk in res) {
        bytes.addAll(chunk);
        if (bytes.length > maxBytes) break;
      }
      return http.StreamedResponse(
        Stream.value(bytes),
        res.statusCode,
        contentLength: res.contentLength >= 0 ? res.contentLength : null,
        request: request,
        headers: headers,
        isRedirect: res.isRedirect,
        reasonPhrase: res.reasonPhrase,
      );
    } finally {
      io.close(force: true);
    }
  }
}
