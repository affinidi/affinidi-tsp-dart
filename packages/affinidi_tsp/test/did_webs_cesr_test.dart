// Parity of the did:webs CESR layer with the JavaScript port it follows
// (vti-didcomm-js `src/did-webs-cesr.js`): every fixture stream and every
// (stream, mutation) pair the Rust conformance vectors name must parse to the
// same messages, or be refused with the same error. See
// test/fixtures/did_webs/SOURCE.md.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/src/did_webs/cesr.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';

const _fixtures = 'test/fixtures/did_webs';

Map<String, Object?> _golden() {
  final bytes = File('$_fixtures/golden/cesr-golden.json.gz').readAsBytesSync();
  return jsonDecode(utf8.decode(gzip.decode(bytes))) as Map<String, Object?>;
}

Uint8List _blob(String name) =>
    File('$_fixtures/vectors/rust-vectors/blobs/$name').readAsBytesSync();

/// A recorded mutation, applied as the Rust vector generator applied it.
Uint8List _mutate(Uint8List base, Map<String, Object?>? m) {
  if (m == null) return base;
  switch (m['type']) {
    case 'replace':
      final out = Uint8List.fromList(base);
      out[m['at']! as int] = m['byte']! as int;
      return out;
    case 'splice':
      final start = m['start']! as int;
      final end = m['end']! as int;
      final ins = m['insert'] as List<Object?>?;
      final insert = ins == null
          ? Uint8List(0)
          : base.sublist(ins[0]! as int, ins[1]! as int);
      return Uint8List.fromList([
        ...base.sublist(0, start),
        ...insert,
        ...base.sublist(end),
      ]);
    case 'swap':
      final a = (m['a']! as List).cast<int>();
      final b = (m['b']! as List).cast<int>();
      return Uint8List.fromList([
        ...base.sublist(0, a[0]),
        ...base.sublist(b[0], b[1]),
        ...base.sublist(a[0], a[1]),
        ...base.sublist(b[1]),
      ]);
  }
  throw StateError('unknown mutation ${m['type']}');
}

String _sig(Siger s) =>
    '${s.code}:${s.index}:${s.ondex ?? '-'}:${b64Encode(s.raw)}';

String _att(Attachment a) => switch (a) {
  ControllerSigs(:final sigs) => 'ControllerSigs[${sigs.map(_sig).join(',')}]',
  WitnessSigs(:final sigs) => 'WitnessSigs[${sigs.map(_sig).join(',')}]',
  ReceiptCouples(:final couples) =>
    'ReceiptCouples[${couples.map((c) => '${c.$1}/${b64Encode(c.$2)}').join(',')}]',
  FirstSeenReplayCouples(:final couples) =>
    'FirstSeenReplayCouples[${couples.map((c) => '${c.$1}/${c.$2}').join(',')}]',
  SealSourceCouples(:final couples) =>
    'SealSourceCouples[${couples.map((c) => '${c.$1}/${c.$2}').join(',')}]',
  TransIdxSigGroups(:final groups) =>
    'TransIdxSigGroups[${groups.map((g) => '${g.prefix}/${g.sn}/${g.said}/{${g.sigs.map(_sig).join(',')}}').join(',')}]',
  BlindedStates(:final states) =>
    'BlindedStates[${states.map((s) => '${s.blid}/${s.uuid}/${s.acdc}/${s.state}').join(',')}]',
};

String _said(Map<String, Object?> sad, String kind) {
  final d = sad['d'];
  if (d is! String || d.isEmpty) return '-';
  final code = d.startsWith('0') ? d.substring(0, 2) : d.substring(0, 1);
  if (!isDigestCode(code)) return '-';
  try {
    return computeSaid(sad, 'd', code, kind);
  } on KeriError catch (e) {
    return '!${e.type}:${e.message}';
  }
}

String _ver(Version? v) => v == null
    ? 'null'
    : '${v.protocol},${v.major},${v.minor},${v.kind},${v.size},'
          '${v.genus == null ? '-' : '${v.genus!.$1}.${v.genus!.$2}'}';

/// The same canonical summary the golden generator writes.
String _summary(List<ParsedMessage> msgs) => msgs
    .map((m) {
      final s = m.serder;
      final dump = s.kind == 'CESR' ? nativeDump(s.sad, const []) : '';
      return [
        s.kind,
        _ver(s.version),
        s.raw.length,
        serializeJson(s.sad),
        dump,
        _said(s.sad, s.kind),
        m.attachments.map(_att).join(';'),
      ].join('|');
    })
    .join('\n');

void main() {
  final golden = _golden();

  group('did:webs CESR parity with the JavaScript port', () {
    final cases = (golden['cases']! as List).cast<Map<String, Object?>>();

    test('covers every fixture stream and recorded mutation', () {
      expect(cases.length, greaterThan(1000));
      expect(cases.where((c) => c['ok'] == false), isNotEmpty);
    });

    for (final c in cases) {
      final name = c['file'] != null
          ? 'fixture ${c['file']}'
          : 'vector ${c['blob']} ${jsonEncode(c['mutation'])}';
      test(name, () {
        final bytes = c['file'] != null
            ? File('$_fixtures/vectors/${c['file']}').readAsBytesSync()
            : _mutate(
                _blob(c['blob']! as String),
                c['mutation'] as Map<String, Object?>?,
              );
        if (c['ok'] == true) {
          final msgs = parseAll(bytes);
          expect(msgs.length, c['n']);
          final hash = crypto.sha256
              .convert(utf8.encode(_summary(msgs)))
              .toString();
          expect(hash, c['sha256'], reason: _summary(msgs));
        } else {
          final error = c['error']! as Map<String, Object?>;
          expect(
            () => parseAll(bytes),
            throwsA(
              isA<KeriError>()
                  .having((e) => e.type, 'type', error['type'])
                  .having((e) => e.message, 'message', error['message']),
            ),
          );
        }
      });
    }
  });

  test('every KERI digest code matches the JavaScript port', () {
    final digests = (golden['digests']! as Map).cast<String, String>();
    expect(digests, hasLength(27));
    for (final e in digests.entries) {
      final code = e.key.substring(0, e.key.indexOf(':'));
      final len = int.parse(e.key.substring(e.key.indexOf(':') + 1));
      final input = len == 0 ? '' : (len == 3 ? 'abc' : 'x' * len);
      expect(digest(code, utf8.encode(input)), e.value, reason: e.key);
      expect(digestMatches(e.value, utf8.encode(input)), isTrue, reason: e.key);
    }
  });

  group('Base64 and version strings', () {
    test('Base64 round-trips and refuses non-canonical text', () {
      for (var n = 0; n < 40; n++) {
        final bytes = List<int>.generate(n, (i) => (i * 37 + 11) & 255);
        expect(b64Decode(b64Encode(bytes)), bytes);
      }
      expect(() => b64Decode('AB'), throwsA(isA<KeriError>())); // stray bits
      expect(() => b64Decode('A'), throwsA(isA<KeriError>())); // dangling char
      expect(() => b64Decode('AA=='), throwsA(isA<KeriError>())); // padding
      expect(() => b64Decode('A+/A'), throwsA(isA<KeriError>())); // alphabet
    });

    test('version strings parse and print in both forms', () {
      final v1 = parseVersionString('KERI10JSON0000fd_');
      expect(
        [v1.protocol, v1.major, v1.minor, v1.kind, v1.size],
        ['KERI', 1, 0, 'JSON', 253],
      );
      expect(versionString(v1), 'KERI10JSON0000fd_');
      final v2 = parseVersionString('KERICAACAAJSONAAEY.');
      expect([v2.major, v2.minor, v2.kind, v2.genus], [2, 0, 'JSON', (2, 0)]);
      expect(versionString(v2), 'KERICAACAAJSONAAEY.');
      expect(
        () => parseVersionString('KERI10CESR0000fd_'),
        throwsA(isA<KeriError>()),
      );
      expect(
        () => parseVersionString('KERI20JSON0000fd_'),
        throwsA(isA<KeriError>()),
      );
    });

    test('order-preserving JSON keeps member order and refuses duplicates', () {
      final sad =
          parseJson(utf8.encode('{"b":1,"10":2,"a":[true,null,"x"]}'))!
              as Map<String, Object?>;
      expect(sad.keys, ['b', '10', 'a']);
      expect(serializeJson(sad), '{"b":1,"10":2,"a":[true,null,"x"]}');
      expect(
        () => parseJson(utf8.encode('{"a":1,"a":2}')),
        throwsA(isA<KeriError>().having((e) => e.type, 'type', 'json')),
      );
      expect(
        () => parseJson(utf8.encode('{"a":1.5}')),
        throwsA(isA<KeriError>().having((e) => e.type, 'type', 'unsupported')),
      );
      expect(
        serializeJson(parseJson(utf8.encode('"\\u0001\\n\\""'))),
        '"\\u0001\\n\\""',
      );
    });
  });
}
