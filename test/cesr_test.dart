import 'dart:convert';
import 'dart:typed_data';

import 'package:tsp/affinidi_tsp.dart';
import 'package:tsp/src/cesr/cesr.dart';
import 'package:test/test.dart';

import 'support/fixtures.dart';

String qb64(List<int> b) => base64Url.encode(b);

void main() {
  setUpAll(() => primeIdentities([1, 2]));

  group('CESR primitives', () {
    test('short and long count codes transcode to the spec text forms', () {
      final short = (CesrWriter()..count(Cesr.codeInt('Z'), 9)).takeBytes();
      expect(qb64(short), '-ZAJ');
      final long = (CesrWriter()..count(Cesr.codeInt('E'), 4096)).takeBytes();
      expect(qb64(long), '--EAABAA');
      final r = CesrReader(long);
      expect(r.readCount(Cesr.codeInt('E'), 'x'), 4096);
      expect(CesrReader(short).readCount(Cesr.codeInt('Z'), 'x'), 9);
    });

    test('variable-size codes pick lead pad 0, 1 and 2', () {
      String code(int n) => qb64(
        (CesrWriter()..variable(Cesr.codeInt('B'), Uint8List(n))).takeBytes(),
      ).substring(0, 4);
      expect(code(0), '4BAA');
      expect(code(3), '4BAB');
      expect(code(2), '5BAB');
      expect(code(1), '6BAB');
      expect(code(11), '5BAE');
    });

    test('long variable-size codes (7AAB/8AAB/9AAB) round-trip', () {
      for (final n in [12285 + 3, 12285 + 2, 12285 + 1]) {
        final data = Uint8List.fromList(List.generate(n, (i) => i & 0xff | 1));
        final w = (CesrWriter()..variable(Cesr.codeInt('B'), data)).takeBytes();
        final lead = (3 - n % 3) % 3;
        expect(qb64(w).substring(0, 4), '${7 + lead}AAB');
        final r = CesrReader(w);
        expect(r.readVariable(Cesr.codeInt('B'), 'x', maxLength: n), data);
        expect(r.isAtEnd, isTrue);
      }
    });

    test('non-zero lead bytes are rejected', () {
      final w = (CesrWriter()..variable(Cesr.codeInt('B'), [1, 2])).takeBytes();
      w[3] = 1; // the lead byte
      expect(
        () => CesrReader(w).readVariable(Cesr.codeInt('B'), 'x', maxLength: 10),
        throwsA(isA<TspMalformedException>()),
      );
    });

    test('non-zero pad bits in fixed-size codes are rejected', () {
      final digest = (CesrWriter()..fixed(Cesr.codeInt('I'), Uint8List(32)))
          .takeBytes();
      expect(qb64(digest)[0], 'I');
      digest[0] |= 1;
      expect(
        () => CesrReader(digest).readFixed(Cesr.codeInt('I'), 32, 'x'),
        throwsA(isA<TspMalformedException>()),
      );
      final nonce = (CesrWriter()..fixed(Cesr.codeInt('A'), Uint8List(16)))
          .takeBytes();
      expect(qb64(nonce).substring(0, 2), '0A');
      nonce[1] |= 1;
      expect(
        () => CesrReader(nonce).readFixed(Cesr.codeInt('A'), 16, 'x'),
        throwsA(isA<TspMalformedException>()),
      );
    });

    test(
      'a declared length beyond the buffer is rejected without allocating',
      () {
        final w = Uint8List.fromList([
          ...(CesrWriter()..count(Cesr.codeInt('Z'), 4000)).takeBytes(),
        ]);
        expect(
          () => CesrReader(w).readGroup(Cesr.codeInt('Z'), 'x'),
          throwsA(isA<TspMalformedException>()),
        );
      },
    );
  });

  group('long framing in whole messages', () {
    for (final scheme in TspScheme.values) {
      test(
        'a payload over 4095 quadlets uses --E/--Z and 7AAF-style codes (${scheme.wireName})',
        () async {
          final a = identity('did:example:a', 1);
          final b = identity('did:example:b', 2);
          final data = Uint8List.fromList(List.generate(20000, (i) => i % 251));
          final packed = await Tsp.pack(
            sender: a.private,
            receiver: b.public,
            payload: ScsPayload(data),
            scheme: scheme,
          );
          expect(qb64(packed.bytes).substring(0, 3), '--E');
          final m = await Tsp.open(
            packed.bytes,
            receiver: b.private,
            sender: a.public,
          );
          expect((m.payload as ScsPayload).data, data);
        },
      );
    }

    test('long VIDs (over 12285 bytes) round-trip', () async {
      final longId = 'did:example:${'x' * 13000}';
      final a = identity(longId, 1);
      final b = identity('did:example:b', 2);
      final packed = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: ScsPayload(utf8.encode('long vid')),
        options: const TspPackOptions(payloadSender: PayloadSenderMode.present),
      );
      final m = await Tsp.open(
        packed.bytes,
        receiver: b.private,
        sender: a.public,
      );
      expect(m.sender, longId);
      expect(m.payloadSender, longId);
    });

    test('every payload length mod 3 round-trips under every scheme', () async {
      final a = identity('did:example:a', 1);
      final b = identity('did:example:b', 2);
      for (final scheme in TspScheme.values) {
        for (var n = 0; n < 7; n++) {
          final packed = await Tsp.pack(
            sender: a.private,
            receiver: b.public,
            payload: ScsPayload(Uint8List(n), padding: Uint8List(n ~/ 2)),
            scheme: scheme,
          );
          final m = await Tsp.open(
            packed.bytes,
            receiver: b.private,
            sender: a.public,
          );
          expect((m.payload as ScsPayload).data.length, n);
          expect(m.payload.padding.length, n ~/ 2);
        }
      }
    });
  });
}
