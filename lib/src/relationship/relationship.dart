import '../crypto/digest.dart';
import '../errors.dart';
import '../util/bytes.dart';

/// The state of the relationship between a local and a remote VID (§7.2).
enum RelationshipState {
  /// No relationship.
  none('none'),

  /// We sent an invite and await the accept: `<local, remote>`.
  inviteSent('invite-sent'),

  /// We received an invite and have not answered: `<remote, local>` from the
  /// peer's side, which admits the peer's messages to us.
  inviteReceived('invite-received'),

  /// Both directions are established: `(local, remote)`.
  bidirectional('bidirectional');

  const RelationshipState(this.wireName);

  /// The state name used by the conformance driver protocol.
  final String wireName;
}

/// Something that happened to a relationship.
enum RelationshipEvent {
  /// We sent an invite.
  sendInvite,

  /// We received an invite.
  receiveInvite,

  /// We sent an accept.
  sendAccept,

  /// We received an accept.
  receiveAccept,

  /// We sent a decline or cancel.
  sendCancel,

  /// We received a decline or cancel.
  receiveCancel,
}

/// A relationship record, as kept by a [RelationshipStore].
final class Relationship {
  /// Creates a relationship record.
  const Relationship({
    required this.local,
    required this.remote,
    required this.state,
    this.digest,
    this.replyDigest,
    this.initiatedLocally = false,
  });

  /// A record for a pair with no relationship.
  const Relationship.none(this.local, this.remote)
    : state = RelationshipState.none,
      digest = null,
      replyDigest = null,
      initiatedLocally = false;

  /// The local VID.
  final String local;

  /// The remote VID.
  final String remote;

  /// The current state.
  final RelationshipState state;

  /// The invite's digest (`Digest`), identifying the inviter's direction.
  final TspDigest? digest;

  /// The accept's digest (`Reply_Digest`), identifying the invitee's
  /// direction.
  final TspDigest? replyDigest;

  /// Whether the local side sent the invite.
  final bool initiatedLocally;

  /// Returns a copy with the given fields replaced.
  Relationship copyWith({
    RelationshipState? state,
    TspDigest? digest,
    TspDigest? replyDigest,
    bool? initiatedLocally,
  }) => Relationship(
    local: local,
    remote: remote,
    state: state ?? this.state,
    digest: digest ?? this.digest,
    replyDigest: replyDigest ?? this.replyDigest,
    initiatedLocally: initiatedLocally ?? this.initiatedLocally,
  );

  /// Whether the local side may send application messages (§7.2.2).
  bool get canSend => state == RelationshipState.bidirectional;

  /// Whether an application message from the remote side is admitted: the
  /// remote-to-local direction must exist, i.e. we received its invite or the
  /// relationship is bidirectional (§7.2.2).
  bool get admitsInbound =>
      state == RelationshipState.inviteReceived ||
      state == RelationshipState.bidirectional;

  /// The digest a cancel from the local side names: the digest it previously
  /// received (§7.3) — the peer's invite digest if we were invited, the
  /// peer's reply digest if we invited — or our own outstanding invite's.
  TspDigest? get cancelDigest => switch (state) {
    RelationshipState.none => null,
    RelationshipState.inviteSent || RelationshipState.inviteReceived => digest,
    RelationshipState.bidirectional => initiatedLocally ? replyDigest : digest,
  };

  /// Whether [named] identifies this relationship.
  bool isNamedBy(TspDigest named) =>
      (digest != null && constantTimeEquals(digest!.bytes, named.bytes)) ||
      (replyDigest != null && constantTimeEquals(replyDigest!.bytes, named.bytes));
}

/// The pure transition function of the relationship state machine.
///
/// ```text
///  none ──sendInvite──► inviteSent ──receiveAccept──► bidirectional
///   │                     │ send/receiveCancel             │
///   └─receiveInvite─► inviteReceived ──sendAccept──────────┘
///                          │ send/receiveCancel            send/receiveCancel
///                          ▼                               ▼
///                         none                            none
/// ```
RelationshipState transitionRelationship(
  RelationshipState state,
  RelationshipEvent event,
) {
  final next = switch ((state, event)) {
    (RelationshipState.none, RelationshipEvent.sendInvite) =>
      RelationshipState.inviteSent,
    (RelationshipState.none, RelationshipEvent.receiveInvite) =>
      RelationshipState.inviteReceived,
    (RelationshipState.inviteSent, RelationshipEvent.receiveAccept) =>
      RelationshipState.bidirectional,
    (RelationshipState.inviteReceived, RelationshipEvent.sendAccept) =>
      RelationshipState.bidirectional,
    (
      RelationshipState.inviteSent ||
          RelationshipState.inviteReceived ||
          RelationshipState.bidirectional,
      RelationshipEvent.sendCancel || RelationshipEvent.receiveCancel,
    ) =>
      RelationshipState.none,
    _ => null,
  };
  if (next == null) {
    throw TspRelationshipException('cannot ${event.name} in state ${state.wireName}');
  }
  return next;
}

/// Resolves the invite race of §7.2.3: both sides keep the invite whose
/// digest is lexicographically lower. Returns `true` if [ours] wins.
bool ourInviteWinsRace(TspDigest ours, TspDigest theirs) =>
    compareBytes(ours.bytes, theirs.bytes) < 0;

/// Persistence for relationship records.
abstract interface class RelationshipStore {
  /// Returns the record for the pair, or a [Relationship.none] record.
  Future<Relationship> get(String local, String remote);

  /// Stores [relationship]; a `none` state removes the record.
  Future<void> put(Relationship relationship);
}

/// A [RelationshipStore] held in memory.
final class InMemoryRelationshipStore implements RelationshipStore {
  final Map<(String, String), Relationship> _records = {};

  @override
  Future<Relationship> get(String local, String remote) async =>
      _records[(local, remote)] ?? Relationship.none(local, remote);

  @override
  Future<void> put(Relationship relationship) async {
    final key = (relationship.local, relationship.remote);
    if (relationship.state == RelationshipState.none) {
      _records.remove(key);
    } else {
      _records[key] = relationship;
    }
  }
}
