// Two parties with ssi-managed did:key identities form a TSP relationship and
// exchange a confidential message.
//
//   dart run example/affinidi_tsp_example.dart

import 'dart:convert';
import 'dart:io';

import 'package:tsp/affinidi_tsp.dart';
import 'package:ssi/ssi.dart';

Future<PrivateVid> createIdentity(String keyId) async {
  final wallet = PersistentWallet(InMemoryKeyStore());
  final didManager = DidKeyManager(wallet: wallet, store: InMemoryDidStore());
  await wallet.generateKey(keyId: keyId, keyType: KeyType.ed25519);
  await didManager.addVerificationMethod(keyId);
  // Keys stay in the wallet: signing goes through the DidManager's signer and
  // decryption through the key pair's ECDH.
  return didManager.toTspPrivateVid();
}

Future<void> main() async {
  final alice = await createIdentity('alice-key');
  final bob = await createIdentity('bob-key');

  // Peers are resolved through ssi's DID resolution (did:key, did:peer,
  // did:web, did:webvh) plus did:peer:4.
  final resolver = SsiVidResolver();
  final aliceEndpoint = TspEndpoint(identities: [alice], resolver: resolver);
  final bobEndpoint = TspEndpoint(identities: [bob], resolver: resolver);

  // 1. Alice invites Bob (TSP_RFI). Deliver `invite.bytes` over any transport.
  final invite = await aliceEndpoint.invite(from: alice.id, to: bob.id);
  final received = await bobEndpoint.receive(invite.bytes);
  stdout.writeln(
    'Bob received an ${received.kind.wireName} from ${received.from}',
  );

  // 2. Bob accepts (TSP_RFA), echoing the invite digest.
  final accept = await bobEndpoint.accept(from: bob.id, to: alice.id);
  await aliceEndpoint.receive(accept.bytes);
  final relationship = await aliceEndpoint.relationship(alice.id, bob.id);
  stdout.writeln('Relationship is ${relationship.state.wireName}');

  // 3. Application data flows within the relationship (HPKE-Base).
  final message = await aliceEndpoint.send(
    from: alice.id,
    to: bob.id,
    data: utf8.encode('hello over TSP'),
  );
  final event = await bobEndpoint.receive(message.bytes);
  stdout.writeln('Bob read: ${utf8.decode(event.data!)}');

  // The low-level API needs no endpoint or state at all.
  final packed = await Tsp.pack(
    sender: alice,
    receiver: await resolver.resolve(bob.id),
    payload: ScsPayload(utf8.encode('stateless')),
    scheme: TspScheme.signedOnly,
  );
  final info = Tsp.peek(packed.bytes);
  stdout.writeln(
    'An intermediary sees ${info.sender} -> ${info.receiver}, '
    'confidential: ${info.confidential}',
  );
}
