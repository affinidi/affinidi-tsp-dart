import 'dart:typed_data';

import '../errors.dart';
import '../message/model.dart';
import '../message/tsp.dart';
import 'relationship.dart';

/// Resolves a VID to its public keys.
abstract interface class VidResolver {
  /// Returns the public VID for [vid]. Throws when it cannot be resolved.
  Future<PublicVid> resolve(String vid);
}

/// A [VidResolver] over a fixed set of VIDs, e.g. peers learned out of band.
final class StaticVidResolver implements VidResolver {
  /// Creates a resolver over [vids].
  StaticVidResolver(Iterable<PublicVid> vids)
    : _vids = {for (final v in vids) v.id: v};

  final Map<String, PublicVid> _vids;

  /// Adds or replaces [vid].
  void add(PublicVid vid) => _vids[vid.id] = vid;

  @override
  Future<PublicVid> resolve(String vid) async {
    final v = _vids[vid];
    if (v == null) {
      throw TspSenderException('unknown VID $vid');
    }
    return v;
  }
}

/// What [TspEndpoint.receive] made of a message.
enum TspEndpointEventKind {
  /// An invite was received.
  invite('invite'),

  /// An accept completed a relationship we initiated.
  accept('accept'),

  /// A decline or cancel removed a relationship.
  cancel('cancel'),

  /// An application message arrived within a relationship.
  message('message');

  const TspEndpointEventKind(this.wireName);

  /// The event name used by the conformance driver protocol.
  final String wireName;
}

/// The outcome of receiving a message at a [TspEndpoint].
final class TspEndpointEvent {
  /// Creates an event.
  const TspEndpointEvent({
    required this.kind,
    required this.from,
    required this.to,
    required this.message,
    this.data,
    this.relationship,
    this.reply,
  });

  /// What happened.
  final TspEndpointEventKind kind;

  /// The remote VID.
  final String from;

  /// The local VID.
  final String to;

  /// The verified, decrypted message.
  final TspMessage message;

  /// The application data of a [TspEndpointEventKind.message].
  final Uint8List? data;

  /// The relationship record after the event (its state before removal, for a
  /// cancel).
  final Relationship? relationship;

  /// For a cancel of a bidirectional relationship, the reciprocal cancel §7.3
  /// says to send back.
  final PackedTspMessage? reply;
}

/// A stateful TSP endpoint: a set of local identities, a way to resolve peers,
/// and a relationship store, driving the relationship forming protocol.
final class TspEndpoint {
  /// Creates an endpoint.
  TspEndpoint({
    required Iterable<PrivateVid> identities,
    required this.resolver,
    RelationshipStore? store,
    this.scheme = TspScheme.hpkeBase,
    this.limits = TspLimits.defaults,
  }) : _identities = {for (final i in identities) i.id: i},
       store = store ?? InMemoryRelationshipStore();

  final Map<String, PrivateVid> _identities;

  /// Resolves remote VIDs.
  final VidResolver resolver;

  /// Keeps relationship state.
  final RelationshipStore store;

  /// The scheme used for messages this endpoint sends.
  final TspScheme scheme;

  /// Bounds applied to received messages.
  final TspLimits limits;

  /// The local identities this endpoint holds.
  Iterable<PrivateVid> get identities => _identities.values;

  /// Adds a local identity.
  void addIdentity(PrivateVid identity) => _identities[identity.id] = identity;

  PrivateVid _local(String vid) {
    final i = _identities[vid];
    if (i == null) {
      throw TspInvalidInputException('$vid is not a local identity of this endpoint');
    }
    return i;
  }

  /// The relationship between [local] and [remote].
  Future<Relationship> relationship(String local, String remote) =>
      store.get(local, remote);

  Future<PackedTspMessage> _pack(PrivateVid from, String to, TspPayload payload) async =>
      Tsp.pack(
        sender: from,
        receiver: await resolver.resolve(to),
        payload: payload,
        scheme: scheme,
        options: TspPackOptions(limits: limits),
      );

  /// Sends an invite from [from] to [to]. [replyPath] asks for a routed
  /// accept.
  Future<PackedTspMessage> invite({
    required String from,
    required String to,
    List<String> replyPath = const [],
  }) async {
    final local = _local(from);
    final rel = await store.get(from, to);
    final next = transitionRelationship(rel.state, RelationshipEvent.sendInvite);
    final packed = await _pack(local, to, RfiPayload(replyPath: replyPath));
    await store.put(
      rel.copyWith(state: next, digest: packed.digest, initiatedLocally: true),
    );
    return packed;
  }

  /// Accepts, as [from], the invite received from [to].
  Future<PackedTspMessage> accept({required String from, required String to}) async {
    final local = _local(from);
    final rel = await store.get(from, to);
    final next = transitionRelationship(rel.state, RelationshipEvent.sendAccept);
    final packed = await _pack(local, to, RfaPayload(digest: rel.digest!));
    await store.put(rel.copyWith(state: next, replyDigest: packed.digest));
    return packed;
  }

  /// Declines (or cancels) the relationship between [from] and [to].
  Future<PackedTspMessage> cancel({required String from, required String to}) async {
    final local = _local(from);
    final rel = await store.get(from, to);
    final next = transitionRelationship(rel.state, RelationshipEvent.sendCancel);
    final packed = await _pack(local, to, RfdPayload(digest: rel.cancelDigest!));
    await store.put(Relationship.none(from, to).copyWith(state: next));
    return packed;
  }

  /// Sends application [data] from [from] to [to]; requires a bidirectional
  /// relationship.
  Future<PackedTspMessage> send({
    required String from,
    required String to,
    required List<int> data,
  }) async {
    final local = _local(from);
    final rel = await store.get(from, to);
    if (!rel.canSend) {
      throw TspRelationshipException(
        'no bidirectional relationship from $from to $to (state ${rel.state.wireName})',
      );
    }
    return _pack(local, to, ScsPayload(data));
  }

  /// Verifies and opens [bytes], applies it to the relationship state, and
  /// reports what happened. A message the state forbids is refused with
  /// [TspRelationshipException] and leaves the state unchanged.
  Future<TspEndpointEvent> receive(Uint8List bytes) async {
    final info = Tsp.peek(bytes, limits: limits);
    final to = info.receiver;
    final local = to == null ? null : _identities[to];
    if (local == null) {
      throw const TspReceiverException('the message is not addressed to a local identity');
    }
    final PublicVid remote;
    try {
      remote = await resolver.resolve(info.sender);
    } on TspException {
      rethrow;
    } on Object catch (e) {
      throw TspSenderException('cannot resolve the sender VID', cause: e);
    }
    final message = await Tsp.open(bytes, receiver: local, sender: remote, limits: limits);
    final from = message.sender;
    final rel = await store.get(local.id, from);

    TspEndpointEvent event(
      TspEndpointEventKind kind, {
      Relationship? r,
      Uint8List? data,
      PackedTspMessage? reply,
    }) => TspEndpointEvent(
      kind: kind,
      from: from,
      to: local.id,
      message: message,
      data: data,
      relationship: r,
      reply: reply,
    );

    switch (message.payload) {
      case RfiPayload(:final digest):
        switch (rel.state) {
          case RelationshipState.none:
            break;
          case RelationshipState.inviteSent:
            if (ourInviteWinsRace(rel.digest!, digest!)) {
              throw const TspRelationshipException(
                'crossing invite discarded: ours has the lower digest (§7.2.3)',
              );
            }
          case RelationshipState.inviteReceived:
          case RelationshipState.bidirectional:
            throw TspRelationshipException(
              'unexpected invite in state ${rel.state.wireName}',
            );
        }
        final updated = Relationship(
          local: local.id,
          remote: from,
          state: RelationshipState.inviteReceived,
          digest: digest,
        );
        await store.put(updated);
        return event(TspEndpointEventKind.invite, r: updated);

      case RfaPayload(:final digest, :final replyDigest):
        if (rel.state != RelationshipState.inviteSent ||
            rel.digest == null ||
            rel.digest != digest) {
          throw const TspRelationshipException('the accept matches no outstanding invite');
        }
        final updated = rel.copyWith(
          state: transitionRelationship(rel.state, RelationshipEvent.receiveAccept),
          replyDigest: replyDigest,
        );
        await store.put(updated);
        return event(TspEndpointEventKind.accept, r: updated);

      case RfdPayload(:final digest):
        if (rel.state == RelationshipState.none || !rel.isNamedBy(digest)) {
          throw const TspRelationshipException('the cancel names no known relationship');
        }
        PackedTspMessage? reply;
        if (rel.state == RelationshipState.bidirectional) {
          reply = await _pack(local, from, RfdPayload(digest: rel.cancelDigest!));
        }
        transitionRelationship(rel.state, RelationshipEvent.receiveCancel);
        await store.put(Relationship.none(local.id, from));
        return event(TspEndpointEventKind.cancel, r: rel, reply: reply);

      case ScsPayload():
        if (!rel.admitsInbound) {
          throw TspRelationshipException(
            'application message without a relationship from $from (state ${rel.state.wireName})',
          );
        }
        final data = (message.payload as ScsPayload).data;
        if (data == null) {
          throw const TspUnsupportedException(
            'the application stream is not a single Bytes primitive',
          );
        }
        return event(TspEndpointEventKind.message, r: rel, data: data);

      case CtlPayload() || PadPayload() || HopPayload():
        throw TspUnsupportedException(
          'the endpoint does not process ${message.payload.typeCode} payloads',
        );
    }
  }
}
