import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:test/test.dart';

import 'support/fixtures.dart';
import 'support/spec_vectors.dart';

void main() {
  setUpAll(() => primeIdentities([1, 2, 3]));
  final sv = SpecVectors.load();
  Uint8List vector(String n) => b64(sv.vectors[n]!['message']! as String);

  Future<TspMessage> openAsBob(Uint8List m) => Tsp.open(
    m,
    receiver: sv.privateVid('bob'),
    sender: sv.publicVid('alice'),
  );

  test('trailing bytes after the signature are rejected', () async {
    final m = vector('direct-hpke-base');
    await expectLater(
      openAsBob(Uint8List.fromList([...m, 0, 0, 0])),
      throwsA(isA<TspMalformedException>()),
    );
  });

  test('truncation at every length is rejected with a TspException', () async {
    final m = vector('control-rfi-direct');
    for (var n = 0; n < m.length; n++) {
      await expectLater(
        openAsBob(Uint8List.sublistView(m, 0, n)),
        throwsA(isA<TspException>()),
      );
    }
  });

  test(
    'every single-bit flip is rejected, and only with TspException',
    () async {
      final m = vector('direct-sealed-box');
      for (var i = 0; i < m.length; i++) {
        final t = Uint8List.fromList(m)..[i] ^= 1 << (i % 8);
        await expectLater(
          openAsBob(t),
          throwsA(isA<TspException>()),
          reason: 'byte $i',
        );
      }
    },
  );

  test('random garbage never escapes as a non-TSP exception', () async {
    final rnd = Random(42);
    for (var i = 0; i < 300; i++) {
      final len = rnd.nextInt(400);
      final g = Uint8List.fromList(List.generate(len, (_) => rnd.nextInt(256)));
      if (i.isEven && len > 3) {
        g.setAll(0, [0xf8, 0x40 | rnd.nextInt(16), rnd.nextInt(256)]);
      }
      await expectLater(openAsBob(g), throwsA(isA<TspException>()));
      expect(() => Tsp.peek(g), throwsA(isA<TspException>()));
    }
  });

  group('version', () {
    // `YTSP-AAC`: the version count code follows the 3-byte YTSP marker.
    int versionOffset(Uint8List m) =>
        indexOfBytes(m, base64Url.decode('YTSP')) + 3;

    test('an unknown major version is rejected as a version error', () async {
      final m = await resign(
        vector('direct-signed-only'),
        sv.privateVid('alice').signingKey,
        (s) {
          final at = versionOffset(s);
          s[at + 1] = (s[at + 1] & 0x0f) | (1 << 4); // -B.. : major 1
        },
      );
      await expectLater(openAsBob(m), throwsA(isA<TspVersionException>()));
    });

    test('a Rev 2 minor version is rejected as a version error', () async {
      final m = await resign(
        vector('direct-signed-only'),
        sv.privateVid('alice').signingKey,
        (s) {
          s[versionOffset(s) + 2] = 1; // -AAB
        },
      );
      await expectLater(openAsBob(m), throwsA(isA<TspVersionException>()));
    });
  });

  test('a wrong expected sender is a sender error', () async {
    await expectLater(
      Tsp.open(
        vector('direct-hpke-base'),
        receiver: sv.privateVid('bob'),
        sender: sv.publicVid('p'),
      ),
      throwsA(isA<TspSenderException>()),
    );
  });

  test('a message for someone else is a receiver error', () async {
    await expectLater(
      Tsp.open(
        vector('direct-hpke-base'),
        receiver: sv.privateVid('p'),
        sender: sv.publicVid('alice'),
      ),
      throwsA(isA<TspReceiverException>()),
    );
  });

  test('a signature by the wrong key is a signature error', () async {
    final alice = sv.publicVid('alice');
    await expectLater(
      Tsp.open(
        vector('direct-hpke-base'),
        receiver: sv.privateVid('bob'),
        sender: PublicVid(
          id: alice.id,
          verificationKey: sv.publicVid('p').verificationKey,
        ),
      ),
      throwsA(isA<TspSignatureException>()),
    );
  });

  test('a ciphertext re-signed after tampering is a decrypt error', () async {
    final m = await resign(
      vector('direct-hpke-base'),
      sv.privateVid('alice').signingKey,
      (s) {
        s[s.length - 1] ^= 1;
      },
    );
    await expectLater(openAsBob(m), throwsA(isA<TspDecryptionException>()));
  });

  test(
    'a ciphertext moved under another envelope sender does not open (aad)',
    () async {
      // p re-signs alice's ciphertext as its own.
      final m = vector('direct-hpke-base');
      final alice = utf8.encode(sv.id('alice'));
      final p = utf8.encode(sv.id('p'));
      expect(alice.length, p.length);
      final moved = await resign(m, sv.privateVid('p').signingKey, (s) {
        s.setAll(indexOfBytes(s, alice), p);
      });
      await expectLater(
        Tsp.open(
          moved,
          receiver: sv.privateVid('bob'),
          sender: sv.publicVid('p'),
        ),
        throwsA(isA<TspDecryptionException>()),
      );
    },
  );

  test(
    'a signed-only invite with an altered digest is a digest error',
    () async {
      final a = identity('did:example:a', 1);
      final b = identity('did:example:b', 2);
      final packed = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: RfiPayload(),
        scheme: TspScheme.signedOnly,
      );
      final digestAt = indexOfBytes(packed.bytes, packed.digest!.bytes);
      final m = await resign(
        packed.bytes,
        a.private.signingKey,
        (s) => s[digestAt] ^= 1,
      );
      await expectLater(
        Tsp.open(m, receiver: b.private, sender: a.public),
        throwsA(isA<TspDigestException>()),
      );
    },
  );

  test(
    'an ESSR sender that differs from the envelope is a sender error',
    () async {
      // Carry a payload sender of equal length to the envelope sender, then
      // swap the envelope sender and re-sign: signature and aad are fine
      // (signed-only has no aad), but the ESSR field now disagrees.
      final a = identity('did:example:a', 1);
      final c = identity('did:example:c', 1);
      final b = identity('did:example:b', 2);
      final packed = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: ScsPayload([1, 2, 3]),
        scheme: TspScheme.signedOnly,
        options: const TspPackOptions(payloadSender: PayloadSenderMode.present),
      );
      final m = await resign(packed.bytes, a.private.signingKey, (s) {
        s.setAll(
          indexOfBytes(s, utf8.encode('did:example:a')),
          utf8.encode('did:example:c'),
        );
      });
      await expectLater(
        Tsp.open(m, receiver: b.private, sender: c.public),
        throwsA(isA<TspSenderException>()),
      );
    },
  );

  test(
    'a non-canonical lead byte in the application body is malformed',
    () async {
      final a = identity('did:example:a', 1);
      final b = identity('did:example:b', 2);
      final packed = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: ScsPayload([7, 7]), // 5BAB 00 07 07
        scheme: TspScheme.signedOnly,
      );
      final body = indexOfBytes(packed.bytes, [0, 7, 7]);
      final m = await resign(
        packed.bytes,
        a.private.signingKey,
        (s) => s[body] = 1,
      );
      await expectLater(
        Tsp.open(m, receiver: b.private, sender: a.public),
        throwsA(isA<TspMalformedException>()),
      );
    },
  );

  test('a sealed-box payload without the ESSR sender is refused', () async {
    final a = identity('did:example:a', 1);
    final b = identity('did:example:b', 2);
    expect(
      () => Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: ScsPayload([1]),
        scheme: TspScheme.sealedBox,
        options: const TspPackOptions(payloadSender: PayloadSenderMode.nullVid),
      ),
      throwsA(isA<TspInvalidInputException>()),
    );
  });

  test('a nested message may not be signed-only', () async {
    final a = identity('did:example:a', 1);
    final b = identity('did:example:b', 2);
    expect(
      () => Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: HopPayload(inner: vector('direct-hpke-base')),
        scheme: TspScheme.signedOnly,
      ),
      throwsA(isA<TspInvalidInputException>()),
    );
  });

  test('a non-zero signature index is refused', () async {
    final m = Uint8List.fromList(vector('direct-hpke-base'));
    m[m.length - 65] |= 0x10; // index bits of `B#`
    await expectLater(openAsBob(m), throwsA(isA<TspSignatureException>()));
  });

  test('size limits are enforced before parsing', () async {
    await expectLater(
      Tsp.open(
        vector('direct-hpke-base'),
        receiver: sv.privateVid('bob'),
        sender: sv.publicVid('alice'),
        limits: const TspLimits(maxMessageLength: 100),
      ),
      throwsA(isA<TspMalformedException>()),
    );
    await expectLater(
      Tsp.open(
        vector('direct-hpke-base'),
        receiver: sv.privateVid('bob'),
        sender: sv.publicVid('alice'),
        limits: const TspLimits(maxVidLength: 10),
      ),
      throwsA(isA<TspMalformedException>()),
    );
  });
}
