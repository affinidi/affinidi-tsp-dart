import 'dart:convert';
import 'dart:typed_data';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:affinidi_tsp/src/message/frame.dart';
import 'package:test/test.dart';

import 'support/spec_vectors.dart';

void main() {
  final sv = SpecVectors.load();

  Map<String, Object?> vec(String name) => sv.vectors[name]!;
  Uint8List message(String name) => b64(vec(name)['message']! as String);

  Future<TspMessage> openVector(String name) {
    final v = vec(name);
    return Tsp.open(
      message(name),
      receiver: sv.privateVid(v['receiver']! as String),
      sender: sv.publicVid(v['sender']! as String),
    );
  }

  Future<Uint8List> reencodeFrame(TspMessage m, TspScheme scheme) async {
    final fields = encodeEnvelopeFields(
      m.sender,
      m.receiver,
      TspLimits.defaults,
    );
    final f = await encodePayloadFrame(
      payload: m.payload,
      envelopeFields: fields,
      payloadSender: m.payloadSender,
      digestAlgorithm: scheme == TspScheme.sealedBox
          ? TspDigestAlgorithm.blake2b256
          : TspDigestAlgorithm.sha256,
      limits: TspLimits.defaults,
    );
    return f.frame;
  }

  Future<Uint8List> repack(
    String name,
    TspPayload payload,
    TspScheme scheme, {
    PayloadSenderMode sender = PayloadSenderMode.schemeDefault,
    TspDigest? expectDigest,
  }) async {
    final v = vec(name);
    final eph = v['ikmE'] ?? v['skEm'];
    final packed = eph == null
        ? await Tsp.pack(
            sender: sv.privateVid(v['sender']! as String),
            receiver: sv.publicVid(v['receiver']! as String),
            payload: payload,
            scheme: scheme,
            options: TspPackOptions(payloadSender: sender),
          )
        : await Tsp.packForTestVector(
            sender: sv.privateVid(v['sender']! as String),
            receiver: sv.publicVid(v['receiver']! as String),
            payload: payload,
            scheme: scheme,
            options: TspPackOptions(payloadSender: sender),
            ephemeral: b64(eph as String),
          );
    if (expectDigest != null) expect(packed.digest, expectDigest);
    return packed.bytes;
  }

  group('Appendix A vectors open and re-pack byte-exact', () {
    test('direct-sealed-box', () async {
      final m = await openVector('direct-sealed-box');
      expect(m.scheme, TspScheme.sealedBox);
      expect(m.sender, sv.id('alice'));
      expect(m.receiver, sv.id('bob'));
      expect(m.payloadSender, sv.id('alice'));
      final p = m.payload as ScsPayload;
      expect(utf8.decode(p.data), 'hello world');
      expect(p.padding, isEmpty);
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('direct-sealed-box')['payload']! as String),
      );
      // The ephemeral public key is the first 32 bytes of the ciphertext.
      expect(
        await repack(
          'direct-sealed-box',
          ScsPayload(utf8.encode('hello world')),
          TspScheme.sealedBox,
        ),
        message('direct-sealed-box'),
      );
    });

    test('direct-hpke-base', () async {
      final m = await openVector('direct-hpke-base');
      expect(m.scheme, TspScheme.hpkeBase);
      expect(m.kem, TspKem.x25519);
      expect(m.payloadSender, isNull);
      expect(utf8.decode((m.payload as ScsPayload).data), 'hello world');
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('direct-hpke-base')['payload']! as String),
      );
      expect(
        await repack(
          'direct-hpke-base',
          ScsPayload(utf8.encode('hello world')),
          TspScheme.hpkeBase,
        ),
        message('direct-hpke-base'),
      );
    });

    test('direct-signed-only', () async {
      final m = await openVector('direct-signed-only');
      expect(m.scheme, TspScheme.signedOnly);
      expect(m.confidential, isFalse);
      expect(
        utf8.decode((m.payload as ScsPayload).data),
        'public announcement!',
      );
      expect(
        await repack(
          'direct-signed-only',
          ScsPayload(utf8.encode('public announcement!')),
          TspScheme.signedOnly,
        ),
        message('direct-signed-only'),
      );
    });

    test('control-rfi-direct', () async {
      final m = await openVector('control-rfi-direct');
      final p = m.payload as RfiPayload;
      expect(p.replyPath, isEmpty);
      expect(p.referral, isNull);
      expect(p.digest!.algorithm, TspDigestAlgorithm.sha256);
      expect(p.nonce, Uint8List(16)..fillRange(0, 16, 0x11));
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('control-rfi-direct')['payload']! as String),
      );
      expect(
        await repack(
          'control-rfi-direct',
          RfiPayload(nonce: p.nonce),
          TspScheme.hpkeBase,
          expectDigest: p.digest,
        ),
        message('control-rfi-direct'),
      );
    });

    test('control-rfa-direct', () async {
      final invite =
          (await openVector('control-rfi-direct')).payload as RfiPayload;
      final m = await openVector('control-rfa-direct');
      final p = m.payload as RfaPayload;
      expect(
        p.digest,
        invite.digest,
        reason: 'the accept echoes the invite digest',
      );
      expect(p.replyDigest, isNotNull);
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('control-rfa-direct')['payload']! as String),
      );
      expect(
        await repack(
          'control-rfa-direct',
          RfaPayload(digest: p.digest),
          TspScheme.hpkeBase,
          expectDigest: p.replyDigest,
        ),
        message('control-rfa-direct'),
      );
    });

    test('control-rfd', () async {
      final invite =
          (await openVector('control-rfi-direct')).payload as RfiPayload;
      final m = await openVector('control-rfd');
      final p = m.payload as RfdPayload;
      expect(p.digest, invite.digest);
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('control-rfd')['payload']! as String),
      );
      expect(
        await repack(
          'control-rfd',
          RfdPayload(digest: p.digest),
          TspScheme.hpkeBase,
        ),
        message('control-rfd'),
      );
    });

    test('control-rfi-sealed-box', () async {
      final m = await openVector('control-rfi-sealed-box');
      expect(m.scheme, TspScheme.sealedBox);
      expect(m.payloadSender, sv.id('alice'));
      final p = m.payload as RfiPayload;
      expect(p.digest!.algorithm, TspDigestAlgorithm.blake2b256);
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('control-rfi-sealed-box')['payload']! as String),
      );
      expect(
        await repack(
          'control-rfi-sealed-box',
          RfiPayload(nonce: p.nonce),
          TspScheme.sealedBox,
          expectDigest: p.digest,
        ),
        message('control-rfi-sealed-box'),
      );
    });

    test('nested-direct', () async {
      final m = await openVector('nested-direct');
      final p = m.payload as HopPayload;
      expect(p.hops, isEmpty);
      expect(p.isRouted, isFalse);
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('nested-direct')['payload']! as String),
      );
      final inner = await Tsp.open(
        p.inner,
        receiver: sv.privateVid('nested_bob'),
        sender: sv.publicVid('nested_alice'),
      );
      expect(utf8.decode((inner.payload as ScsPayload).data), 'hello world');
      expect(
        await reencodeFrame(inner, inner.scheme),
        b64(vec('nested-direct')['innerPayload']! as String),
      );
      expect(
        await repack(
          'nested-direct',
          HopPayload(inner: p.inner),
          TspScheme.hpkeBase,
        ),
        message('nested-direct'),
      );
    });

    test('routed', () async {
      final m = await openVector('routed');
      final p = m.payload as HopPayload;
      expect(p.hops, [sv.id('q'), sv.id('nested_bob')]);
      expect(
        await reencodeFrame(m, m.scheme),
        b64(vec('routed')['payload']! as String),
      );
      final inner = await Tsp.open(
        p.inner,
        receiver: sv.privateVid('nested_bob'),
        sender: sv.publicVid('nested_alice'),
      );
      expect(
        await reencodeFrame(inner, inner.scheme),
        b64(vec('routed')['innerPayload']! as String),
      );
      expect(
        await repack(
          'routed',
          HopPayload(hops: p.hops, inner: p.inner),
          TspScheme.hpkeBase,
        ),
        message('routed'),
      );
    });

    test('peek reads every classical vector without keys', () {
      for (final name in sv.vectors.keys) {
        final info = Tsp.peek(message(name));
        final v = vec(name);
        expect(info.sender, sv.id(v['sender']! as String), reason: name);
        expect(info.receiver, sv.id(v['receiver']! as String), reason: name);
        expect(info.version, TspVersion.current);
      }
    });
  });
}
