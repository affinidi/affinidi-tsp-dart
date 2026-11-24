// KEL verification for did:webs (lib/src/did_webs/kel.dart), checked three
// ways:
//
// - against the Rust reference: every `key_state` and `parse` record of the
//   conformance vectors recorded from `affinidi-did-webs` must give the same
//   key state, or be refused with the same error kind;
// - against the JS port it follows (vti-didcomm-js `src/did-webs-kel.js`):
//   for every fixture stream and every (stream, mutation) pair the vectors
//   name, every identifier's key state, deactivation, issuer log, anchored
//   digests and key state as of each of its events, and the verdict on every
//   signature group, must be identical — refusals to the message;
// - and the JS port's own KEL unit tests, with signature and threshold cases.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:affinidi_tsp/src/did_webs/cesr.dart';
import 'package:affinidi_tsp/src/did_webs/kel.dart';
import 'package:affinidi_tsp/src/did_webs/signatures.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:test/test.dart';

import 'support/did_webs_kel_outcome.dart';
import 'support/did_webs_vectors.dart';

/// The `DidWebsError` kind the resolver reports a KEL-layer failure as
/// (vti-didcomm-js `did-webs.js` `kel()`).
String _kind(Object e) => switch (e) {
  StreamError() => 'Stream',
  KelError() || KeriError() => 'Kel',
  _ => throw StateError('not a KEL-layer error: $e'),
};

Map<String, Object?> _rustState(Kels kels, String prefix) {
  final s = kels.keyState(prefix);
  return {
    'prefix': s.prefix,
    'sn': s.sn,
    'said': s.said,
    'lastEventDigest': s.lastEventDigest,
    'keys': s.keys,
    'nextKeys': s.nextKeys,
    'threshold': thresholdJson(s.threshold),
    'nextThreshold': thresholdJson(s.nextThreshold),
    'backers': s.backers,
    'backerThreshold': s.backerThreshold,
    'config': s.config,
    'delegator': s.delegator,
    'deactivated': kels.isDeactivated(prefix),
  };
}

/// Run a `key_state` or `parse` record as vti-didcomm-js `runOp` does.
Object? _runOp(Map<String, Object?> rec) {
  final stream = mutate(
    vectorBlob(rec['keri_cesr']! as String),
    rec['mutation'] as Map<String, Object?>?,
  );
  var kels = Kels.parse(stream);
  final asOf = rec['as_of'] as List<Object?>?;
  if (asOf != null) kels = kels.asOf(asOf[0]! as String, asOf[1]! as int);
  if (rec['op'] == 'parse') return true;
  return _rustState(kels, rec['prefix']! as String);
}

Map<String, Object?> _golden() {
  final bytes = File(
    '$didWebsFixtures/golden/kel-golden.json.gz',
  ).readAsBytesSync();
  return jsonDecode(utf8.decode(gzip.decode(bytes))) as Map<String, Object?>;
}

// ─── Signing helpers for the signature tests ────────────────────────────

final Uint8List _msg = Uint8List.fromList(utf8.encode('a key event'));

BigInt _be(List<int> bytes) =>
    bytes.fold(BigInt.zero, (n, b) => (n << 8) | BigInt.from(b));

Uint8List _bytes(BigInt n, int len) {
  final out = Uint8List(len);
  for (var i = len - 1; i >= 0; i--) {
    out[i] = (n & BigInt.from(0xff)).toInt();
    n >>= 8;
  }
  return out;
}

Uint8List _compressed(ECPoint p) => Uint8List.fromList([
  p.y!.toBigInteger()!.isOdd ? 3 : 2,
  ..._bytes(p.x!.toBigInteger()!, 32),
]);

/// An ECDSA key and a signature over [_msg] with a fixed nonce, as (qb64 of
/// the key, r, s, n).
(String, BigInt, BigInt, BigInt) _ecdsa(String code, ECDomainParameters c) {
  final d = BigInt.parse('1234567890abcdef1234567890abcdef', radix: 16);
  final k = BigInt.parse('fedcba0987654321fedcba0987654321', radix: 16);
  final n = c.n;
  final q = (c.G * d)!;
  final r = (c.G * k)!.x!.toBigInteger()! % n;
  final e = _be(crypto.sha256.convert(_msg).bytes) % n;
  final s = k.modInverse(n) * (e + r * d) % n;
  return (matterQb64(code, _compressed(q)), r, s, n);
}

Uint8List _rs(BigInt r, BigInt s) =>
    Uint8List.fromList([..._bytes(r, 32), ..._bytes(s, 32)]);

// A KERI 1.0 JSON message with its `v` sized; its SAID is not computed,
// which the stream bounds do not reach.
String _keriJson(Map<String, Object?> fields) {
  final msg = <String, Object?>{'v': 'KERI10JSON000000_', ...fields};
  final size = utf8.encode(jsonEncode(msg)).length;
  msg['v'] = 'KERI10JSON${size.toRadixString(16).padLeft(6, '0')}_';
  return jsonEncode(msg);
}

void main() {
  group('did:webs KEL parity with the Rust reference', () {
    final records = [
      for (final e in loadVectors().entries)
        for (final r in e.value)
          if (r['op'] == 'key_state' || r['op'] == 'parse') r,
    ];

    test('covers every key_state and parse record', () {
      expect(records, hasLength(103));
    });

    for (final rec in records) {
      final label =
          '${rec['source']}'
          '${rec['mutation'] == null ? '' : ' ${jsonEncode(rec['mutation'])}'}'
          ' [${rec['op']}]';
      test(label, () {
        Object? got;
        Object? error;
        try {
          got = _runOp(rec);
        } on Exception catch (e) {
          error = e;
        }
        if (rec['ok'] != true) {
          final want = (rec['error']! as Map)['kind'];
          expect(error, isNotNull, reason: 'Rust refused it ($want)');
          expect(_kind(error!), want, reason: '$error');
        } else {
          expect(error, isNull, reason: 'Rust accepted it');
          expect(got, rec['op'] == 'parse' ? true : rec['state']);
        }
      });
    }
  });

  group('did:webs KEL parity with the JavaScript port', () {
    final golden = _golden();
    final cases = (golden['cases']! as List).cast<Map<String, Object?>>();

    test('covers every fixture stream and recorded mutation', () {
      expect(cases.length, greaterThan(1300));
    });

    for (final c in cases) {
      final name = c['file'] != null
          ? 'fixture ${c['file']}'
          : 'vector ${c['blob']} ${jsonEncode(c['mutation'])}';
      test(name, () {
        final bytes = c['file'] != null
            ? didWebsFixture(c['file']! as String)
            : mutate(
                vectorBlob(c['blob']! as String),
                c['mutation'] as Map<String, Object?>?,
              );
        final want = Map.of(c)
          ..remove('file')
          ..remove('blob')
          ..remove('mutation');
        // Through JSON, so ints and lists compare as the golden's do.
        final got = jsonDecode(jsonEncode(kelOutcome(bytes)));
        expect(got, want);
      });
    }
  });

  group('stream bounds (0.13.3 kel::MAX_STREAM_*)', () {
    final said = 'E'.padRight(44, 'A');
    final sig = 'AA'.padRight(88, 'A');
    Uint8List stream(String text) => Uint8List.fromList(utf8.encode(text));
    final refusedStream = throwsA(
      isA<StreamError>().having(
        (e) => e.message,
        'message',
        contains('more than'),
      ),
    );

    test('a stream past the bounds is refused before anything is verified', () {
      final rct = _keriJson({'t': 'rct', 'd': said, 'i': said, 's': '0'});
      expect(
        () => Kels.parse(stream(rct * (maxStreamMessages + 1))),
        refusedStream,
      );
      Kels.parse(stream(rct * 10));
      expect(
        () => Kels.parse(stream(rct + '-AAB$sig' * (maxStreamSignatures + 1))),
        refusedStream,
      );
      Kels.parse(stream(rct + '-AAB$sig' * 4));
      String ixn(int seals) => _keriJson({
        't': 'ixn',
        'd': said,
        'i': said,
        's': '1',
        'p': said,
        'a': List.generate(seals, (_) => {'d': said}),
      });
      expect(() => Kels.parse(stream(ixn(maxStreamSeals + 1))), refusedStream);
      Kels.parse(stream(ixn(4)));
      String icp(int backers) => _keriJson({
        't': 'icp',
        'd': said,
        'i': said,
        's': '0',
        'kt': '1',
        'k': <String>[],
        'nt': '0',
        'n': <String>[],
        'bt': '0',
        'b': List.generate(backers, (_) => 'B${'A' * 43}'),
        'c': <String>[],
        'a': <Object>[],
      });
      expect(
        () => Kels.parse(stream(icp(maxStreamBackers + 1))),
        refusedStream,
      );
      Kels.parse(stream(icp(4)));
    });

    test('the limits are the reference values', () {
      expect(
        [
          maxStreamMessages,
          maxStreamSignatures,
          maxStreamBackers,
          maxStreamSeals,
        ],
        [10000, 16384, 1024, 16384],
      );
    });

    test('a message cap is applied, and no cap may be asked for', () {
      final cesr = didWebsFixture('ENro7uf0.keri.cesr');
      expect(
        () => Kels.parse(cesr, maxMessages: 2),
        throwsA(
          isA<StreamError>().having(
            (e) => e.message,
            'message',
            contains('more than 2 messages'),
          ),
        ),
      );
      expect(Kels.parse(cesr, maxMessages: null).messages, hasLength(6));
    });
  });

  group('fixtures', () {
    const aid = 'ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe';

    test('the did-webs-resolver reference identifier verifies', () {
      final state = Kels.parse(
        didWebsFixture('ENro7uf0.keri.cesr'),
      ).keyState(aid);
      expect(state.prefix, aid);
      expect(state.keys, isNotEmpty);
    });

    test('a tampered key event stream is refused', () {
      final text = utf8.decode(didWebsFixture('ENro7uf0.keri.cesr'));
      // A changed key in the inception: its SAID no longer holds.
      final tampered = text.replaceFirst(
        'DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr',
        'DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjs',
      );
      expect(tampered, isNot(text));
      expect(
        () => Kels.parse(utf8Bytes(tampered)).keyState(aid),
        throwsA(isA<KelError>()),
      );
      // A truncated stream cannot be framed.
      final cesr = didWebsFixture('ENro7uf0.keri.cesr');
      expect(
        () => Kels.parse(cesr.sublist(0, cesr.length - 7)),
        throwsA(isA<StreamError>()),
      );
      // A body this implementation does not read is refused, not skipped.
      expect(
        () => Kels.parse(Uint8List.fromList([0xa1, 0x61, 0x76])),
        throwsA(isA<StreamError>()),
      );
    });

    test(
      'a KEL with native CESR bodies reaches the key state keripy reaches',
      () {
        final spec =
            (jsonDecode(
                      utf8.decode(
                        didWebsFixture('keripy-native/v2-basic-native.json'),
                      ),
                    )
                    as Map)['keripy']
                as Map;
        final state = Kels.parse(
          didWebsFixture('keripy-native/v2-basic-native.cesr'),
        ).keyState(spec['prefix'] as String);
        expect(state.sn, spec['sn']);
        expect(state.lastEventDigest, spec['said']);
        expect(state.said, (spec['establishment'] as Map)['said']);
        expect(state.keys, spec['keys']);
      },
    );

    test('the KERI 2.0 lifecycle keripy accepts verifies', () {
      final spec =
          jsonDecode(utf8.decode(didWebsFixture('ours-v2/lifecycle.json')))
              as Map;
      final did = spec['did'] as String;
      final aid = did.substring(did.lastIndexOf(':') + 1);
      final state = Kels.parse(
        didWebsFixture('ours-v2/lifecycle.keri.cesr'),
      ).keyState(aid);
      expect(state.sn, (spec['kel'] as Map)['sn']);
      expect(state.lastEventDigest, (spec['kel'] as Map)['said']);
    });

    test('a deactivated identifier is one whose last rotation commits to no '
        'next keys', () {
      final cesr = didWebsFixture('deactivated/keri.cesr');
      final did = utf8.decode(didWebsFixture('deactivated/did.txt')).trim();
      final aid = did.substring(did.lastIndexOf(':') + 1);
      final kels = Kels.parse(cesr);
      final state = kels.keyState(aid);
      expect(kels.isDeactivated(aid), isTrue);
      expect(state.nextKeys, isEmpty);
      // As of an earlier event it was not yet.
      final earlier = kels.asOf(aid, 3);
      expect(earlier.isDeactivated(aid), isFalse);
      expect(earlier.keyState(aid).sn, 3);
    });
  });

  group('thresholds (threshold.rs)', () {
    test('simple thresholds are hex text or numbers', () {
      expect(thresholdJson(parseThreshold('a')), 'a');
      expect(thresholdJson(parseThreshold(const SadNumber('16'))), '10');
      expect(() => parseThreshold('x'), throwsA(isA<KeriError>()));
      expect(
        () => parseThreshold(const SadNumber('-1')),
        throwsA(isA<KeriError>()),
      );
      expect(() => parseThreshold(true), throwsA(isA<KeriError>()));
    });

    test('weighted thresholds: a clause, or a list of clauses', () {
      expect(thresholdJson(parseThreshold(['1/2', '1/2', '1'])), [
        ['1/2', '1/2', '1'],
      ]);
      expect(
        thresholdJson(
          parseThreshold([
            ['1/2', '1/2'],
            ['1'],
          ]),
        ),
        [
          ['1/2', '1/2'],
          ['1'],
        ],
      );
      for (final bad in <Object>[
        <Object>[],
        ['1', <Object>[]],
        [<Object>[]],
        [
          ['1', true],
        ],
        ['1/0'],
        ['x/2'],
        ['1/x'],
        ['4294967296'],
        ['1/2/3'],
      ]) {
        expect(
          () => parseThreshold(bad),
          throwsA(isA<KeriError>()),
          reason: '$bad',
        );
      }
    });

    test('every clause must reach one', () {
      final t = parseThreshold([
        ['1/2', '1/2', '1/2'],
        ['1/2', '1/2'],
      ]);
      expect(thresholdSatisfied(t, [0, 1, 3, 4], 5), isTrue);
      expect(thresholdSatisfied(t, [0, 3, 4], 5), isFalse);
      expect(thresholdSatisfied(t, [0, 1, 3], 5), isFalse);
      // A signer past the key count counts for nothing.
      expect(thresholdSatisfied(t, [0, 1, 3, 4], 4), isFalse);
      expect(thresholdSatisfied(parseThreshold('2'), [0, 1], 2), isTrue);
      expect(thresholdSatisfied(parseThreshold('2'), [0], 2), isFalse);
      expect(thresholdSatisfied(parseThreshold('0'), [], 0), isFalse);
    });

    test('u64 overflow in the weight sums is not met, as the Rust', () {
      final big = parseThreshold([
        ['1/4294967295', '1/4294967291', '1/4294967279', '4294967295'],
      ]);
      expect(thresholdSatisfied(big, [0, 1, 2, 3], 4), isFalse);
      expect(thresholdSatisfied(big, [3], 4), isTrue);
    });
  });

  group('signatures (Verfer::verify)', () {
    test('Ed25519 is verified strictly', () {
      final sk = nacl.SigningKey(seed: Uint8List(32)..fillRange(0, 32, 7));
      final pk = Uint8List.fromList(sk.verifyKey.asTypedList);
      final sig = Uint8List.fromList(sk.sign(_msg).signature.asTypedList);
      final v = verfer(matterQb64('D', pk));
      expect(verifySignature(v, _msg, sig), isTrue);
      final flipped = Uint8List.fromList(sig)..[10] ^= 1;
      expect(verifySignature(v, _msg, flipped), isFalse);
      // S + L: the same point, but not a canonical scalar.
      final l =
          (BigInt.one << 252) +
          BigInt.parse('27742317777372353535851937790883648493');
      var s = BigInt.zero;
      for (var i = 63; i >= 32; i--) {
        s = (s << 8) | BigInt.from(sig[i]);
      }
      final sl = s + l;
      final unreduced = Uint8List.fromList(sig);
      for (var i = 0; i < 32; i++) {
        unreduced[32 + i] = ((sl >> (8 * i)) & BigInt.from(0xff)).toInt();
      }
      expect(ed25519Verify(pk, _msg, unreduced), isFalse);
      // A small-order key verifies nothing (the identity point, y = 1).
      final identity = Uint8List(32)..[0] = 1;
      expect(ed25519KeyDecodes(identity), isTrue);
      expect(ed25519Verify(identity, _msg, Uint8List(64)..[0] = 1), isFalse);
    });

    test('an Ed25519 key that does not decompress is unusable', () {
      var y = 2;
      Uint8List key() => Uint8List(32)..[0] = y;
      while (ed25519KeyDecodes(key())) {
        y++;
      }
      final v = verfer(matterQb64('D', key()));
      expect(
        () => verifySignature(v, _msg, Uint8List(64)),
        throwsA(isA<KeriError>().having((e) => e.type, 'type', 'crypto')),
      );
    });

    test('secp256k1 must be low-S; P-256 need not be', () {
      for (final (code, params, lowS) in [
        ('1AAB', ECCurve_secp256k1(), true),
        ('1AAJ', ECCurve_secp256r1(), false),
      ]) {
        final (qb64, r, s, n) = _ecdsa(code, params);
        final v = verfer(qb64);
        final low = s > (n >> 1) ? n - s : s;
        final high = n - low;
        expect(verifySignature(v, _msg, _rs(r, low)), isTrue, reason: code);
        expect(verifySignature(v, _msg, _rs(r, high)), !lowS, reason: code);
        expect(
          verifySignature(v, _msg, _rs(r + BigInt.one, low)),
          isFalse,
          reason: code,
        );
        expect(
          () => verifySignature(v, _msg, _rs(r, n)),
          throwsA(isA<KeriError>()),
          reason: code,
        );
        expect(
          () => verifySignature(v, _msg, _rs(BigInt.zero, low)),
          throwsA(isA<KeriError>()),
          reason: code,
        );
      }
    });

    test('only signing key codes are verfers', () {
      expect(
        () => verfer('E'.padRight(44, 'A')),
        throwsA(isA<KeriError>().having((e) => e.type, 'type', 'crypto')),
      );
    });
  });
}
