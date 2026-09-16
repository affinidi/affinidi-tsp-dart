import 'dart:convert';

import 'package:affinidi_tsp/affinidi_tsp.dart';
import 'package:test/test.dart';

import 'support/fixtures.dart';

void main() {
  setUpAll(() => primeIdentities([1, 2]));

  group('state machine', () {
    test('outbound and inbound flows', () {
      var s = transitionRelationship(
        RelationshipState.none,
        RelationshipEvent.sendInvite,
      );
      expect(s, RelationshipState.inviteSent);
      s = transitionRelationship(s, RelationshipEvent.receiveAccept);
      expect(s, RelationshipState.bidirectional);
      s = transitionRelationship(
        RelationshipState.none,
        RelationshipEvent.receiveInvite,
      );
      expect(
        transitionRelationship(s, RelationshipEvent.sendAccept),
        RelationshipState.bidirectional,
      );
    });

    test('cancels return to none from every live state', () {
      for (final s in [
        RelationshipState.inviteSent,
        RelationshipState.inviteReceived,
        RelationshipState.bidirectional,
      ]) {
        for (final e in [
          RelationshipEvent.sendCancel,
          RelationshipEvent.receiveCancel,
        ]) {
          expect(transitionRelationship(s, e), RelationshipState.none);
        }
      }
    });

    test('invalid transitions throw a relationship error', () {
      expect(
        () => transitionRelationship(
          RelationshipState.inviteSent,
          RelationshipEvent.sendInvite,
        ),
        throwsA(isA<TspRelationshipException>()),
      );
      expect(
        () => transitionRelationship(
          RelationshipState.none,
          RelationshipEvent.sendCancel,
        ),
        throwsA(isA<TspRelationshipException>()),
      );
      expect(
        () => transitionRelationship(
          RelationshipState.none,
          RelationshipEvent.receiveAccept,
        ),
        throwsA(isA<TspRelationshipException>()),
      );
    });
  });

  group('endpoint', () {
    late ({PrivateVid private, PublicVid public}) a;
    late ({PrivateVid private, PublicVid public}) b;
    late TspEndpoint ea;
    late TspEndpoint eb;
    setUp(() {
      a = identity('did:example:a', 1);
      b = identity('did:example:b', 2);
      ea = TspEndpoint(
        identities: [a.private],
        resolver: StaticVidResolver([b.public]),
      );
      eb = TspEndpoint(
        identities: [b.private],
        resolver: StaticVidResolver([a.public]),
      );
    });

    Future<(TspDigest, TspDigest)> form() async {
      final inv = await ea.invite(from: a.private.id, to: b.private.id);
      await eb.receive(inv.bytes);
      final acc = await eb.accept(from: b.private.id, to: a.private.id);
      await ea.receive(acc.bytes);
      return (inv.digest!, acc.digest!);
    }

    test('invite, accept and exchange data in both directions', () async {
      final (d1, d2) = await form();
      for (final (ep, l, r) in [(ea, a, b), (eb, b, a)]) {
        final rel = await ep.relationship(l.private.id, r.private.id);
        expect(rel.state, RelationshipState.bidirectional);
        expect(rel.digest, d1);
        expect(rel.replyDigest, d2);
      }
      final ab = await ea.send(
        from: a.private.id,
        to: b.private.id,
        data: utf8.encode('ab'),
      );
      expect(utf8.decode((await eb.receive(ab.bytes)).data!), 'ab');
      final ba = await eb.send(
        from: b.private.id,
        to: a.private.id,
        data: utf8.encode('ba'),
      );
      expect(utf8.decode((await ea.receive(ba.bytes)).data!), 'ba');
    });

    test('an application message before a relationship is refused', () async {
      final packed = await Tsp.pack(
        sender: a.private,
        receiver: b.public,
        payload: ScsPayload([1]),
      );
      await expectLater(
        eb.receive(packed.bytes),
        throwsA(isA<TspRelationshipException>()),
      );
      expect(
        (await eb.relationship(b.private.id, a.private.id)).state,
        RelationshipState.none,
      );
      await expectLater(
        ea.send(from: a.private.id, to: b.private.id, data: [1]),
        throwsA(isA<TspRelationshipException>()),
      );
    });

    test('an accept naming an unknown invite is refused', () async {
      await ea.invite(from: a.private.id, to: b.private.id);
      final bogus = await Tsp.pack(
        sender: b.private,
        receiver: a.public,
        payload: RfaPayload(digest: TspDigest(List.filled(32, 7))),
      );
      await expectLater(
        ea.receive(bogus.bytes),
        throwsA(isA<TspRelationshipException>()),
      );
      expect(
        (await ea.relationship(a.private.id, b.private.id)).state,
        RelationshipState.inviteSent,
      );
    });

    test(
      'cancel returns both sides to none and offers a reciprocal cancel',
      () async {
        final (d1, d2) = await form();
        final c = await ea.cancel(from: a.private.id, to: b.private.id);
        final ev = await eb.receive(c.bytes);
        expect(ev.kind, TspEndpointEventKind.cancel);
        final named = (ev.message.payload as RfdPayload).digest;
        expect([d1, d2], contains(named));
        expect(ev.reply, isNotNull);
        expect(
          (await ea.relationship(a.private.id, b.private.id)).state,
          RelationshipState.none,
        );
        expect(
          (await eb.relationship(b.private.id, a.private.id)).state,
          RelationshipState.none,
        );
        // The reciprocal cancel finds nothing left to cancel.
        await expectLater(
          ea.receive(ev.reply!.bytes),
          throwsA(isA<TspRelationshipException>()),
        );
      },
    );

    test('declining an invite', () async {
      final inv = await ea.invite(from: a.private.id, to: b.private.id);
      await eb.receive(inv.bytes);
      final d = await eb.cancel(from: b.private.id, to: a.private.id);
      final ev = await ea.receive(d.bytes);
      expect(ev.kind, TspEndpointEventKind.cancel);
      expect((ev.message.payload as RfdPayload).digest, inv.digest);
      expect(
        (await ea.relationship(a.private.id, b.private.id)).state,
        RelationshipState.none,
      );
    });

    test('crossing invites converge on the lower digest (§7.2.3)', () async {
      final ia = await ea.invite(from: a.private.id, to: b.private.id);
      final ib = await eb.invite(from: b.private.id, to: a.private.id);
      final aWins = ourInviteWinsRace(ia.digest!, ib.digest!);
      final (winner, winnerId, loser, loserId, winDigest) = aWins
          ? (ea, a, eb, b, ia.digest!)
          : (eb, b, ea, a, ib.digest!);
      final toWinner = aWins ? ib : ia;
      final toLoser = aWins ? ia : ib;
      await expectLater(
        winner.receive(toWinner.bytes),
        throwsA(isA<TspRelationshipException>()),
      );
      final ev = await loser.receive(toLoser.bytes);
      expect(ev.kind, TspEndpointEventKind.invite);
      expect(
        (await winner.relationship(
          winnerId.private.id,
          loserId.private.id,
        )).digest,
        winDigest,
      );
      final lrel = await loser.relationship(
        loserId.private.id,
        winnerId.private.id,
      );
      expect(lrel.state, RelationshipState.inviteReceived);
      expect(lrel.digest, winDigest);
      final acc = await loser.accept(
        from: loserId.private.id,
        to: winnerId.private.id,
      );
      final got = await winner.receive(acc.bytes);
      expect(got.kind, TspEndpointEventKind.accept);
      expect(
        (await winner.relationship(
          winnerId.private.id,
          loserId.private.id,
        )).state,
        RelationshipState.bidirectional,
      );
    });

    test(
      'a message for an unknown local identity is a receiver error',
      () async {
        final packed = await Tsp.pack(
          sender: a.private,
          receiver: b.public,
          payload: RfiPayload(),
        );
        await expectLater(
          ea.receive(packed.bytes),
          throwsA(isA<TspReceiverException>()),
        );
      },
    );
  });
}
