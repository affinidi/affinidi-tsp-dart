import 'dart:convert';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:test/test.dart';

import 'support/fixtures.dart';

void main() {
  setUpAll(() => primeIdentities([1, 2, 3, 4]));

  late ({PrivateVid private, PublicVid public}) a;
  late ({PrivateVid private, PublicVid public}) b;
  setUp(() {
    a = identity('did:example:alice', 1);
    b = identity('did:example:bob', 2);
  });

  Future<TspMessage> roundTrip(
    TspPayload payload, {
    TspScheme scheme = TspScheme.hpkeBase,
    TspPackOptions options = const TspPackOptions(),
  }) async {
    final packed = await Tsp.pack(
      sender: a.private,
      receiver: b.public,
      payload: payload,
      scheme: scheme,
      options: options,
    );
    return Tsp.open(packed.bytes, receiver: b.private, sender: a.public);
  }

  test('XCTL carries upper-layer control data', () async {
    final m = await roundTrip(CtlPayload(utf8.encode('{"op":"x"}')));
    expect(m.payload, isA<CtlPayload>());
    expect(utf8.decode((m.payload as CtlPayload).data!), '{"op":"x"}');
  });

  test('XSCS carries an arbitrary pre-encoded CESR stream', () async {
    final stream = Uint8List.fromList([
      ...base64Url.decode('-HAB'),
      ...base64Url.decode('4BAB'),
      1,
      2,
      3,
    ]);
    final m = await roundTrip(ScsPayload.stream(stream));
    final p = m.payload as ScsPayload;
    expect(p.stream, stream);
    expect(p.data, isNull);
  });

  test('XPAD carries its nonce and padding', () async {
    final nonce = Uint8List(16)..fillRange(0, 16, 9);
    final m = await roundTrip(
      PadPayload(nonce: nonce, padding: Uint8List(100)),
    );
    final p = m.payload as PadPayload;
    expect(p.nonce, nonce);
    expect(p.padding.length, 100);
  });

  test('two padding messages without a nonce differ', () async {
    Future<Uint8List> pad() async => (await Tsp.pack(
      sender: a.private,
      receiver: b.public,
      payload: PadPayload(),
      scheme: TspScheme.signedOnly,
    )).bytes;
    expect(await pad(), isNot(await pad()));
  });

  test('padding is excluded from the invite and accept digests', () async {
    final nonce = Uint8List(16);
    Future<TspDigest> invite(int pad) async => (await Tsp.pack(
      sender: a.private,
      receiver: b.public,
      payload: RfiPayload(nonce: nonce, padding: Uint8List(pad)),
    )).digest!;
    expect(await invite(0), await invite(31));
    final d = await invite(0);
    Future<TspDigest> accept(int pad) async => (await Tsp.pack(
      sender: b.private,
      receiver: a.public,
      payload: RfaPayload(digest: d, padding: Uint8List(pad)),
    )).digest!;
    expect(await accept(0), await accept(5));
  });

  test('payload sender modes', () async {
    for (final scheme in [TspScheme.hpkeBase, TspScheme.signedOnly]) {
      expect(
        (await roundTrip(ScsPayload([1]), scheme: scheme)).payloadSender,
        isNull,
      );
      expect(
        (await roundTrip(
          ScsPayload([1]),
          scheme: scheme,
          options: const TspPackOptions(
            payloadSender: PayloadSenderMode.present,
          ),
        )).payloadSender,
        a.private.id,
      );
    }
    expect(
      (await roundTrip(
        ScsPayload([1]),
        scheme: TspScheme.sealedBox,
      )).payloadSender,
      a.private.id,
    );
  });

  test('the invite digest binds the payload sender field', () async {
    final nonce = Uint8List(16);
    Future<TspDigest> invite(PayloadSenderMode mode) async => (await Tsp.pack(
      sender: a.private,
      receiver: b.public,
      payload: RfiPayload(nonce: nonce),
      options: TspPackOptions(payloadSender: mode),
    )).digest!;
    expect(
      await invite(PayloadSenderMode.nullVid),
      isNot(await invite(PayloadSenderMode.present)),
    );
  });

  test('a routed invite carries its reply path', () async {
    final m = await roundTrip(
      RfiPayload(replyPath: ['did:example:hop1', 'did:example:exit']),
    );
    expect((m.payload as RfiPayload).replyPath, [
      'did:example:hop1',
      'did:example:exit',
    ]);
  });

  test(
    'a referral signed at pack time verifies against the new VID only',
    () async {
      final newVid = identity('did:example:alice-2', 3);
      final other = identity('did:example:other', 4);
      final packed = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: RfiPayload(
          referral: Referral.signWith(
            vid: newVid.private.id,
            signingKey: newVid.private.signingKey,
          ),
        ),
      );
      final m = await Tsp.open(
        packed.bytes,
        receiver: b.private,
        sender: a.public,
      );
      final p = m.payload as RfiPayload;
      expect(p.referral!.vid, newVid.private.id);
      expect(p.digest, packed.digest);
      expect(
        await Tsp.verifyReferral(m, newVid.public.verificationKey),
        isTrue,
      );
      expect(
        await Tsp.verifyReferral(m, other.public.verificationKey),
        isFalse,
      );
      expect(await Tsp.verifyReferral(m, a.public.verificationKey), isFalse);

      // The same referral signature re-carried verbatim reproduces the message.
      final again = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: RfiPayload(
          nonce: p.nonce,
          referral: Referral(
            vid: p.referral!.vid,
            signature: p.referral!.signature!,
          ),
        ),
        scheme: TspScheme.signedOnly,
      );
      final m2 = await Tsp.open(
        again.bytes,
        receiver: b.private,
        sender: a.public,
      );
      expect((m2.payload as RfiPayload).digest, p.digest);
    },
  );

  test(
    'a referral does not verify once moved to another relationship',
    () async {
      final newVid = identity('did:example:alice-2', 3);
      final m = await roundTrip(
        RfiPayload(
          referral: Referral.signWith(
            vid: newVid.private.id,
            signingKey: newVid.private.signingKey,
          ),
        ),
      );
      final p = m.payload as RfiPayload;
      final moved = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: RfiPayload(
          referral: Referral(
            vid: newVid.private.id,
            signature: p.referral!.signature!,
          ),
        ),
      );
      final m2 = await Tsp.open(
        moved.bytes,
        receiver: b.private,
        sender: a.public,
      );
      expect(
        await Tsp.verifyReferral(m2, newVid.public.verificationKey),
        isFalse,
      );
    },
  );

  test('nested and routed messages carry the inner message unopened', () async {
    final inner = await Tsp.pack(
      sender: a.private,
      receiver: b.public,
      payload: ScsPayload(utf8.encode('inner')),
      scheme: TspScheme.signedOnly,
    );
    final nested = await roundTrip(HopPayload(inner: inner.bytes));
    expect((nested.payload as HopPayload).isRouted, isFalse);
    expect((nested.payload as HopPayload).inner, inner.bytes);
    final routed = await roundTrip(
      HopPayload(
        hops: ['did:example:q', 'did:example:dest'],
        inner: inner.bytes,
      ),
    );
    expect((routed.payload as HopPayload).hops, [
      'did:example:q',
      'did:example:dest',
    ]);
  });

  test('a NULL envelope receiver round-trips', () async {
    final m = await roundTrip(
      RfiPayload(),
      options: const TspPackOptions(nullReceiver: true),
    );
    expect(m.receiver, isNull);
    expect(
      Tsp.peek(
        (await Tsp.pack(
          sender: a.private,
          receiver: b.public,
          payload: RfiPayload(),
          options: const TspPackOptions(nullReceiver: true),
        )).bytes,
      ).receiver,
      isNull,
    );
  });

  test('peek reports what an intermediary sees', () async {
    for (final scheme in TspScheme.values) {
      final packed = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: ScsPayload([1]),
        scheme: scheme,
      );
      final info = Tsp.peek(packed.bytes);
      expect(info.scheme, scheme);
      expect(info.confidential, scheme != TspScheme.signedOnly);
      expect(info.sender, a.private.id);
      expect(info.receiver, b.private.id);
    }
  });

  test(
    'HPKE and sealed-box packing is randomised without ephemeral material',
    () async {
      for (final scheme in [TspScheme.hpkeBase, TspScheme.sealedBox]) {
        Future<Uint8List> p() async => (await Tsp.pack(
          sender: a.private,
          receiver: b.public,
          payload: ScsPayload([1]),
          scheme: scheme,
        )).bytes;
        expect(await p(), isNot(await p()));
      }
    },
  );
}
